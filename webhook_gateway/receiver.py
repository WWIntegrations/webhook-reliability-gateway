"""Example receiver: applies each event once, keyed by its Idempotency-Key.

It stands for the downstream system (an order service, a CRM). The effect row and the
idempotency key are written in one SQLite transaction, so a second delivery of the same
event (after a timeout, a lost answer or a crashed gateway worker) is answered 200 and
changes nothing. ``fail_next`` makes it answer 503 with Retry-After for a while, and
``refuse`` makes it reject given keys with 422, to drive the demo and the tests.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Receiver:
    def __init__(self, db_path: str, host: str = "127.0.0.1", port: int = 0):
        self.db_path = str(db_path)
        self.fail_next = 0
        self.retry_after = "1"
        self.refuse: set = set()
        self.requests = 0
        self.lock = threading.Lock()
        with closing(sqlite3.connect(self.db_path)) as c, c:
            c.execute("CREATE TABLE IF NOT EXISTS effects (idem_key TEXT PRIMARY KEY, body TEXT NOT NULL)")
        rcv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                key = self.headers.get("Idempotency-Key") or ""
                code, extra, msg = rcv.handle(key, body)
                data = json.dumps(msg).encode()
                self.send_response(code)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://{host}:{self.httpd.server_address[1]}/events"

    def handle(self, key: str, body: bytes):
        with self.lock:
            self.requests += 1
            if not key:
                return 400, {}, {"error": "Idempotency-Key required"}
            if key in self.refuse:
                return 422, {}, {"error": "order does not exist"}
            if self.fail_next > 0:
                self.fail_next -= 1
                return 503, {"Retry-After": self.retry_after}, {"error": "maintenance"}
        with closing(sqlite3.connect(self.db_path, timeout=30)) as c, c:
            cur = c.execute("INSERT OR IGNORE INTO effects (idem_key, body) VALUES (?, ?)",
                            (key, body.decode("utf-8", "replace")))
            applied = cur.rowcount == 1
        return 200, {}, {"applied": applied}

    def effects(self) -> list:
        with closing(sqlite3.connect(self.db_path)) as c:
            return [r[0] for r in c.execute("SELECT idem_key FROM effects ORDER BY rowid")]

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
