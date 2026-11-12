"""SQLite inbox and delivery queue.

The boundary this file protects: an event is acknowledged to the sender only after it is
committed, a repeated webhook id is stored once, and a delivery is claimed with a lease
and a fencing token so that a worker that died (or stalled past its lease) can neither
lose the event nor overwrite the result of the worker that took over.
"""
from __future__ import annotations

import hashlib
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY,
  source      TEXT NOT NULL,
  msg_id      TEXT NOT NULL,
  digest      TEXT NOT NULL,
  body        BLOB NOT NULL,
  received_at REAL NOT NULL,
  UNIQUE (source, msg_id)
);
CREATE TABLE IF NOT EXISTS deliveries (
  event_id     INTEGER PRIMARY KEY REFERENCES events(id),
  target       TEXT NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'delivered', 'dead')),
  attempts     INTEGER NOT NULL DEFAULT 0,
  next_at      REAL NOT NULL,
  lease_token  TEXT,
  lease_until  REAL,
  last_status  INTEGER,
  last_error   TEXT,
  delivered_at REAL
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries (state, next_at);
CREATE TABLE IF NOT EXISTS attempts (
  id          INTEGER PRIMARY KEY,
  event_id    INTEGER NOT NULL REFERENCES events(id),
  n           INTEGER NOT NULL,
  worker      TEXT NOT NULL,
  started_at  REAL NOT NULL,
  finished_at REAL,
  status      INTEGER,
  outcome     TEXT,
  error       TEXT
);
"""


class Conflict(ValueError):
    """The same webhook id arrived again with a different body."""


@dataclass(frozen=True)
class Accepted:
    event_id: int
    duplicate: bool


@dataclass(frozen=True)
class Claim:
    event_id: int
    source: str
    msg_id: str
    body: bytes
    target: str
    attempt: int
    lease_token: str
    attempt_row: int


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class Store:
    def __init__(self, path: str):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=FULL")
            c.execute("PRAGMA foreign_keys=ON")
            yield c
        finally:
            c.close()

    @contextmanager
    def _tx(self):
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
            except BaseException:
                c.execute("ROLLBACK")
                raise
            c.execute("COMMIT")

    # -- ingress -------------------------------------------------------------------------
    def accept(self, source: str, msg_id: str, body: bytes, target: str, now: float) -> Accepted:
        """Store the event and queue one delivery, or report the copy already stored.
        Returns only after COMMIT, so a 2xx sent after it never loses the event."""
        d = digest(body)
        with self._tx() as c:
            row = c.execute("SELECT id, digest FROM events WHERE source = ? AND msg_id = ?",
                            (source, msg_id)).fetchone()
            if row:
                if row[1] != d:
                    raise Conflict(f"webhook id {msg_id!r} was already received with another body")
                return Accepted(row[0], True)
            cur = c.execute("INSERT INTO events (source, msg_id, digest, body, received_at) "
                            "VALUES (?, ?, ?, ?, ?)", (source, msg_id, d, body, now))
            c.execute("INSERT INTO deliveries (event_id, target, state, next_at) VALUES (?, ?, 'pending', ?)",
                      (cur.lastrowid, target, now))
            return Accepted(cur.lastrowid, False)

    # -- delivery ------------------------------------------------------------------------
    def claim(self, worker: str, now: float, lease_secs: float) -> Claim | None:
        """Lease the oldest due delivery: a pending one whose time has come, or a leased one
        whose lease ran out (its worker died or stalled)."""
        with self._tx() as c:
            row = c.execute(
                "SELECT d.event_id, e.source, e.msg_id, e.body, d.target, d.attempts FROM deliveries d "
                "JOIN events e ON e.id = d.event_id "
                "WHERE (d.state = 'pending' AND d.next_at <= ?) OR (d.state = 'leased' AND d.lease_until <= ?) "
                "ORDER BY d.next_at, d.event_id LIMIT 1", (now, now)).fetchone()
            if not row:
                return None
            event_id, source, msg_id, body, target, attempts = row
            token = uuid.uuid4().hex
            c.execute("UPDATE deliveries SET state = 'leased', lease_token = ?, lease_until = ?, attempts = ? "
                      "WHERE event_id = ?", (token, now + lease_secs, attempts + 1, event_id))
            cur = c.execute("INSERT INTO attempts (event_id, n, worker, started_at) VALUES (?, ?, ?, ?)",
                            (event_id, attempts + 1, worker, now))
            return Claim(event_id, source, msg_id, bytes(body), target, attempts + 1, token, cur.lastrowid)

    def finish(self, claim: Claim, now: float, *, outcome: str, status: int | None, error: str | None,
               next_at: float | None = None) -> bool:
        """Record the result of one attempt. ``outcome`` is delivered, retry or dead.
        Returns False, and changes nothing, when the lease was taken over in the meantime."""
        state = {"delivered": "delivered", "retry": "pending", "dead": "dead"}[outcome]
        with self._tx() as c:
            c.execute("UPDATE attempts SET finished_at = ?, status = ?, outcome = ?, error = ? WHERE id = ?",
                      (now, status, outcome, error, claim.attempt_row))
            cur = c.execute(
                "UPDATE deliveries SET state = ?, next_at = COALESCE(?, next_at), lease_token = NULL, "
                "lease_until = NULL, last_status = ?, last_error = ?, "
                "delivered_at = CASE WHEN ? = 'delivered' THEN ? ELSE delivered_at END "
                "WHERE event_id = ? AND lease_token = ?",
                (state, next_at, status, error, state, now, claim.event_id, claim.lease_token))
            if cur.rowcount == 0:
                c.execute("UPDATE attempts SET outcome = 'fenced' WHERE id = ?", (claim.attempt_row,))
                return False
            return True

    # -- operator ------------------------------------------------------------------------
    def replay(self, event_id: int, now: float) -> bool:
        """Put a dead delivery back in the queue with a fresh attempt budget."""
        with self._tx() as c:
            cur = c.execute("UPDATE deliveries SET state = 'pending', attempts = 0, next_at = ?, "
                            "last_error = NULL WHERE event_id = ? AND state = 'dead'", (now, event_id))
            return cur.rowcount == 1

    def deliveries(self, state: str | None = None) -> list:
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            sql = ("SELECT d.event_id, e.source, e.msg_id, d.state, d.attempts, d.last_status, d.last_error, "
                   "d.next_at, d.delivered_at FROM deliveries d JOIN events e ON e.id = d.event_id")
            rows = c.execute(sql + (" WHERE d.state = ?" if state else "") + " ORDER BY d.event_id",
                             (state,) if state else ()).fetchall()
            return [dict(r) for r in rows]

    def attempts(self, event_id: int | None = None) -> list:
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            sql = "SELECT event_id, n, worker, status, outcome, error FROM attempts"
            rows = c.execute(sql + (" WHERE event_id = ?" if event_id else "") + " ORDER BY id",
                             (event_id,) if event_id else ()).fetchall()
            return [dict(r) for r in rows]

    def counts(self) -> dict:
        with self._conn() as c:
            out = {"events": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                   "attempts": c.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]}
            for state, n in c.execute("SELECT state, COUNT(*) FROM deliveries GROUP BY state"):
                out[state] = n
            return out
