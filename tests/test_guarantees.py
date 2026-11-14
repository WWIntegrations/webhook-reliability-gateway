"""Regression tests for defects found in review, and tests for the guarantees the README lists."""
import base64
import gc
import hashlib
import hmac
import http.client
import importlib.util
import os
import random
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from webhook_gateway.__main__ import main
from webhook_gateway.delivery import Policy, Worker, parse_retry_after, post
from webhook_gateway.demo import SECRET, run
from webhook_gateway.ingress import MAX_BODY, Ingress, Source
from webhook_gateway.receiver import Receiver
from webhook_gateway.signing import SignatureError, decode_secret, sign, verify
from webhook_gateway.store import Claim, Store

NOW = 1_800_000_000


class FakeClock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


def post_raw(url: str, path: str, body: bytes, headers: dict, timeout: float = 5):
    """POST with http.client so that header values are sent exactly as given (latin-1).
    Returns (status, response headers)."""
    host, port = url.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status, resp.headers
    finally:
        conn.close()


class NonAsciiDigitTests(unittest.TestCase):
    """str.isdigit() is True for characters such as U+00B2 that int() and float() reject.
    Header values arrive latin-1 decoded, so a sender or a receiver can put them there."""

    def test_retry_after_with_a_superscript_digit_is_ignored_not_raised(self):
        for value in ("\u00b2", "1\u00b2", "\u0663"):
            self.assertIsNone(parse_retry_after(value, NOW), repr(value))

    def test_worker_survives_a_receiver_that_sends_a_non_ascii_retry_after(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store(Path(tmp.name) / "gw.db")
        store.accept("shop", "evt_1", b"{}", "http://t", NOW)
        w = Worker(store, Policy(base_delay=1, max_delay=1), name="w", rng=random.Random(1), clock=FakeClock(),
                   sender=lambda claim, timeout: (503, "\u00b2", "HTTP 503"))
        self.assertEqual(w.run_once(), "retry")
        self.assertEqual(store.deliveries()[0]["state"], "pending")

    def test_timestamp_with_a_superscript_digit_is_a_signature_error(self):
        h = {"webhook-id": "evt_1", "webhook-timestamp": "\u00b2", "webhook-signature": sign(SECRET, "evt_1", 2, b"{}")}
        with self.assertRaises(SignatureError):
            verify([SECRET], h, b"{}", NOW)

    def test_ingress_answers_401_for_a_non_ascii_timestamp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store(Path(tmp.name) / "gw.db")
        gw = Ingress(store, {"shop": Source("shop", (SECRET,), "http://t")}).start()
        self.addCleanup(gw.shutdown)
        code, _ = post_raw(gw.url, "/hooks/shop", b"{}", {
            "Content-Type": "application/json", "webhook-id": "evt_1", "webhook-timestamp": "\u00b2",
            "webhook-signature": "v1,AAAA"})
        self.assertEqual(code, 401)
        self.assertEqual(store.counts()["events"], 0)


class SecretTests(unittest.TestCase):
    """``whsec_`` with nothing after it decoded to an empty HMAC key, so anyone could sign."""

    def test_whsec_prefix_without_key_is_refused(self):
        for bad in ("whsec_", "whsec_====", ""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                decode_secret(bad)

    def test_a_signature_made_with_an_empty_key_is_never_accepted(self):
        mac = hmac.new(b"", f"evt_1.{NOW}.".encode() + b"{}", hashlib.sha256).digest()
        h = {"webhook-id": "evt_1", "webhook-timestamp": str(NOW),
             "webhook-signature": "v1," + base64.b64encode(mac).decode()}
        with self.assertRaises(ValueError):
            verify(["whsec_"], h, b"{}", NOW)

    def test_serve_refuses_unusable_secrets_before_listening(self):
        for value in ("whsec_", "whsec_***"):
            with tempfile.TemporaryDirectory() as d, \
                    mock.patch.dict(os.environ, {"WEBHOOK_SECRET_SHOP": value}), \
                    mock.patch("webhook_gateway.ingress.Ingress", side_effect=AssertionError("started")):
                self.assertEqual(main(["serve", "--db", str(Path(d) / "g.db"), "--source", "shop=http://t"]), 2)


def signed_headers(msg_id: str, body: bytes, ts: int | None = None) -> dict:
    ts = int(time.time()) if ts is None else ts
    return {"Content-Type": "application/json", "webhook-id": msg_id, "webhook-timestamp": str(ts),
            "webhook-signature": sign(SECRET, msg_id, ts, body)}


class IngressRobustnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = Store(self.root / "gw.db")

    def start(self, store=None, **kw):
        gw = Ingress(store or self.store, {"shop": Source("shop", (SECRET,), "http://t")}, **kw).start()
        self.addCleanup(gw.shutdown)
        return gw

    def test_a_client_that_stops_sending_is_disconnected(self):
        """Without a socket timeout one idle connection held a server thread forever (slowloris)."""
        gw = self.start(read_timeout=0.5)
        host, port = gw.url.removeprefix("http://").split(":")
        for partial in (b"POST /hooks/shop HTTP/1.1\r\n",
                        b"POST /hooks/shop HTTP/1.1\r\nContent-Type: application/json\r\n"
                        b"Content-Length: 100\r\n\r\n{"):
            with socket.create_connection((host, int(port)), timeout=5) as s:
                s.sendall(partial)
                t0 = time.monotonic()
                self.assertEqual(s.recv(1024), b"", "server should close the idle connection")
                self.assertLess(time.monotonic() - t0, 3)

    def test_a_storage_failure_answers_503_and_never_2xx(self):
        class Locked(Store):
            def accept(self, *a, **kw):
                raise sqlite3.OperationalError("database is locked")

        gw = self.start(store=Locked(self.root / "locked.db"))
        code, headers = post_raw(gw.url, "/hooks/shop", b"{}", signed_headers("evt_1", b"{}"))
        self.assertEqual(code, 503)
        self.assertEqual(headers.get("Retry-After"), "1")

    def test_deeply_nested_json_is_refused_with_400(self):
        body = b"[" * 260_000
        gw = self.start()
        code, _ = post_raw(gw.url, "/hooks/shop", body, signed_headers("evt_deep", body))
        self.assertEqual(code, 400)
        self.assertEqual(self.store.counts()["events"], 0)


class RetryStormTests(unittest.TestCase):
    def test_events_told_to_wait_the_same_time_do_not_come_back_together(self):
        """With Retry-After above the jitter ceiling every event got exactly now + Retry-After,
        so a receiver that asked for 30 s got the whole queue back in the same instant."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store(Path(tmp.name) / "gw.db")
        for i in range(50):
            store.accept("shop", f"evt_{i}", b"{}", "http://t", NOW)
        w = Worker(store, Policy(base_delay=1, max_delay=300), name="w", rng=random.Random(3), clock=FakeClock(),
                   sender=lambda claim, timeout: (429, "30", "HTTP 429"))
        self.assertEqual([w.run_once() for _ in range(50)], ["retry"] * 50)
        due = [d["next_at"] for d in store.deliveries()]
        self.assertGreaterEqual(min(due), NOW + 30)           # never sooner than Retry-After
        self.assertEqual(len(set(due)), 50)
        self.assertGreater(max(due) - min(due), 0.5)          # spread over the first jitter window


class ConnectionHygieneTests(unittest.TestCase):
    def test_error_answers_do_not_leave_the_response_open(self):
        """post() kept the HTTPError (which holds the socket) open on every 4xx and 5xx;
        under a long outage each retry left a socket for the garbage collector."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rcv = Receiver(Path(tmp.name) / "r.db").start()
        self.addCleanup(rcv.shutdown)
        rcv.fail_next = 1
        rcv.refuse.add("shop:evt_2")
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always", ResourceWarning)
            for msg_id, want in (("evt_1", 503), ("evt_2", 422)):
                claim = Claim(1, "shop", msg_id, b"{}", rcv.url, 1, "tok", 1)
                self.assertEqual(post(claim, 5)[0], want)
            gc.collect()
        self.assertEqual([str(w.message) for w in seen if issubclass(w.category, ResourceWarning)], [])


class DeliveryGuaranteeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = Store(self.root / "gw.db")

    def test_concurrent_workers_claim_each_delivery_once(self):
        for i in range(20):
            self.store.accept("shop", f"evt_{i}", b"{}", "http://t", NOW)
        claims, start = [], threading.Barrier(8)

        def go(n):
            mine, own = [], Store(self.store.path)     # one connection per worker, as in production
            start.wait()
            while (c := own.claim(f"w{n}", NOW, 60)) is not None:
                mine.append(c.event_id)
            claims.extend(mine)

        threads = [threading.Thread(target=go, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(claims), list(range(1, 21)))

    def test_every_attempt_carries_the_same_key_and_body(self):
        rcv = Receiver(self.root / "r.db").start()
        self.addCleanup(rcv.shutdown)
        seen = []
        handle = rcv.handle
        rcv.handle = lambda key, body: seen.append((key, body)) or handle(key, body)
        rcv.fail_next, rcv.retry_after = 2, "0"
        self.store.accept("shop", "evt_1", b'{"n":1}', rcv.url, time.time())
        outcomes = Worker(self.store, Policy(base_delay=0.01), name="w").run_until_idle(time.time() + 10)
        self.assertEqual(outcomes, ["retry", "retry", "delivered"])
        self.assertEqual(seen, [("shop:evt_1", b'{"n":1}')] * 3)
        self.assertEqual(rcv.effects(), ["shop:evt_1"])

    def test_a_redirect_is_not_followed(self):
        """Targets are fixed by the operator; a 3xx must not send the event somewhere else."""
        rcv = Receiver(self.root / "r.db").start()
        self.addCleanup(rcv.shutdown)

        class Moved(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(307)
                self.send_header("Location", rcv.url)
                self.send_header("Content-Length", "0")
                self.end_headers()

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Moved)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        self.store.accept("shop", "evt_1", b"{}", f"http://127.0.0.1:{httpd.server_address[1]}/hook", time.time())
        self.assertEqual(Worker(self.store, Policy(), name="w").run_once(), "dead")
        self.assertEqual(self.store.deliveries()[0]["last_status"], 307)
        self.assertEqual(rcv.requests, 0)

    def test_body_of_exactly_max_body_is_accepted(self):
        gw = Ingress(self.store, {"shop": Source("shop", (SECRET,), "http://t")}).start()
        self.addCleanup(gw.shutdown)
        body = b'"' + b"x" * (MAX_BODY - 2) + b'"'
        self.assertEqual(post_raw(gw.url, "/hooks/shop", body, signed_headers("evt_big", body))[0], 202)
        self.assertEqual(self.store.counts()["events"], 1)


ROOT = Path(__file__).resolve().parents[1]


class DocumentedClaimsTests(unittest.TestCase):
    """The README numbers and the committed diagram come from one demo run, not from prose."""

    @classmethod
    def setUpClass(cls):
        cls.result = run()
        spec = importlib.util.spec_from_file_location("build_diagram", ROOT / "tools" / "build_diagram.py")
        cls.diagram = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.diagram)

    def test_readme_numbers(self):
        s = self.result["summary"]
        self.assertTrue(self.result["pass"])
        self.assertEqual((s["http_requests_sent"], s["events_stored"], s["delivery_attempts"],
                          s["receiver_effects"], s["effects_per_event"]), (7, 3, 7, 3, 1))
        self.assertEqual(len(self.result["requests"]), 7)
        self.assertEqual(len(self.result["attempts"]), 7)

    def test_committed_diagrams_match_a_fresh_run(self):
        for theme in self.diagram.THEMES:
            committed = (ROOT / "docs" / f"how-it-works-{theme}.svg").read_text(encoding="utf-8")
            self.assertEqual(committed, self.diagram.svg(theme, self.result),
                             f"docs/how-it-works-{theme}.svg is stale: run python3 tools/build_diagram.py")

    def test_diagram_counts_follow_the_record(self):
        changed = dict(self.result, attempts=self.result["attempts"][:-1])
        titles = [title for title, _ in self.diagram.groups_from(changed)]
        self.assertIn("Worker: 6 attempts", titles)


if __name__ == "__main__":
    unittest.main()
