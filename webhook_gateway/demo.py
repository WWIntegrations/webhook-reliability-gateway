"""End-to-end demo: real HTTP sender, gateway, receiver and a worker process that dies.

Every step below is measured, not narrated; the run fails (exit 1) when any check fails.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from .delivery import Policy, Worker
from .ingress import Ingress, Source
from .receiver import Receiver
from .signing import sign
from .store import Store

SECRET = "whsec_ZGVtby1zZWNyZXQtbm90LWZvci1wcm9kdWN0aW9u"   # base64("demo-secret-not-for-production")
POLICY = Policy(max_attempts=5, base_delay=0.05, max_delay=2.0, lease_secs=0.5, timeout=5)


def send(url: str, msg_id: str, payload: dict | bytes, *, secret: str = SECRET, ts: int | None = None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
    ts = int(time.time()) if ts is None else ts
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "webhook-id": msg_id, "webhook-timestamp": str(ts),
        "webhook-signature": sign(secret, msg_id, ts, body)})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            return e.code, json.loads(e.read() or b"{}")


def run(workdir: str | None = None) -> dict:
    tmp = tempfile.TemporaryDirectory() if workdir is None else None
    root = Path(workdir or tmp.name)
    steps, checks = [], []

    def step(name, observed, ok):
        steps.append({"step": len(steps) + 1, "name": name, "observed": observed, "pass": bool(ok)})
        checks.append(bool(ok))

    store = Store(root / "gateway.db")
    receiver = Receiver(root / "receiver.db").start()
    ingress = Ingress(store, {"shop": Source("shop", (SECRET,), receiver.url)}).start()
    hook = ingress.url + "/hooks/shop"
    order = {"type": "order.paid", "order_id": "order-17", "amount_cents": 4250, "currency": "EUR"}
    try:
        code, body = send(hook, "evt_1", order)
        step("event accepted and committed before the answer", f"HTTP {code}, duplicate={body.get('duplicate')}",
             code == 202 and body["duplicate"] is False)
        code, body = send(hook, "evt_1", order)
        step("sender retries the same event after a timeout", f"HTTP {code}, duplicate={body.get('duplicate')}",
             code == 200 and body["duplicate"] is True)
        code, body = send(hook, "evt_1", dict(order, amount_cents=1))
        step("same id with a different body is refused", f"HTTP {code}", code == 409)
        code, _ = send(hook, "evt_forged", order, secret="whsec_" + "d3Jvbmc=")
        code2, _ = send(hook, "evt_old", order, ts=int(time.time()) - 900)
        step("forged signature and 15-minute-old replay are refused", f"HTTP {code} and HTTP {code2}",
             code == 401 and code2 == 401)

        receiver.fail_next, receiver.retry_after = 2, "1"
        t0 = time.monotonic()
        Worker(store, POLICY, name="worker-a").run_until_idle(time.time() + 30)
        waited = time.monotonic() - t0
        tries = [a["status"] for a in store.attempts(1)]
        step("receiver down twice (503, Retry-After: 1): retried, then delivered",
             f"attempts {tries}, waited {waited:.1f} s", tries == [503, 503, 200] and waited >= 2.0)

        code, _ = send(hook, "evt_2", dict(order, order_id="order-18", amount_cents=990))
        crash = subprocess.run([sys.executable, "-m", "webhook_gateway", "_crash-once", "--db",
                                str(store.path), "--lease", str(POLICY.lease_secs)],
                               capture_output=True, text=True, timeout=30)
        leased = [d["state"] for d in store.deliveries() if d["msg_id"] == "evt_2"]
        step("worker process dies after the receiver applied the event, before saving",
             f"exit code {crash.returncode}, delivery state {leased[0]}, receiver effects for evt_2: "
             f"{receiver.effects().count('shop:evt_2')}",
             crash.returncode == 73 and leased == ["leased"] and receiver.effects().count("shop:evt_2") == 1)
        time.sleep(POLICY.lease_secs + 0.1)
        Worker(store, POLICY, name="worker-b").run_until_idle(time.time() + 30)
        a2 = store.attempts(2)
        step("lease expires, a new worker delivers again, receiver applies nothing twice",
             f"attempts by {[a['worker'] for a in a2]}, effects for evt_2: {receiver.effects().count('shop:evt_2')}",
             [a["worker"] for a in a2] == ["crash-worker", "worker-b"] and receiver.effects().count("shop:evt_2") == 1)

        receiver.refuse.add("shop:evt_3")
        send(hook, "evt_3", dict(order, order_id="order-404"))
        Worker(store, POLICY, name="worker-b").run_until_idle(time.time() + 30)
        dead = store.deliveries("dead")
        step("receiver rejects an event for good (422): dead-lettered after 1 attempt",
             f"dead letters {[d['msg_id'] for d in dead]}, attempts {[d['attempts'] for d in dead]}",
             [d["msg_id"] for d in dead] == ["evt_3"] and dead[0]["attempts"] == 1)
        receiver.refuse.clear()
        replayed = store.replay(dead[0]["event_id"], time.time())
        Worker(store, POLICY, name="worker-b").run_until_idle(time.time() + 30)
        step("operator fixes the receiver and replays the dead letter",
             f"replayed={replayed}, state {store.deliveries()[2]['state']}",
             replayed and store.deliveries()[2]["state"] == "delivered")

        effects = receiver.effects()
        counts = store.counts()
        summary = {"http_requests_sent": 7, "events_stored": counts["events"], "delivered": counts.get("delivered", 0),
                   "delivery_attempts": counts["attempts"], "receiver_requests": receiver.requests,
                   "receiver_effects": len(effects), "effects_per_event": max(effects.count(k) for k in set(effects))}
        step("each stored event changed the receiver exactly once",
             f"{summary['events_stored']} events, {summary['delivery_attempts']} attempts, "
             f"{summary['receiver_effects']} effects", summary["receiver_effects"] == summary["events_stored"] == 3
             and summary["effects_per_event"] == 1)
    finally:
        ingress.shutdown()
        receiver.shutdown()
        if tmp:
            tmp.cleanup()
    return {"pass": all(checks), "steps": steps, "summary": summary}


def crash_once(db: str, lease: float) -> None:
    """Claim one delivery, let the receiver apply it, then die before recording the result."""
    store = Store(db)
    claim = store.claim("crash-worker", time.time(), lease)
    if claim is None:
        os._exit(2)
    from .delivery import post
    post(claim, 5)
    os._exit(73)
