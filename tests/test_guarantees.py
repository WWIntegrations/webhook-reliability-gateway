"""Regression tests for defects found in review, and tests for the guarantees the README lists."""
import base64
import hashlib
import hmac
import http.client
import os
import random
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from webhook_gateway.__main__ import main
from webhook_gateway.delivery import Policy, Worker, parse_retry_after
from webhook_gateway.demo import SECRET, send
from webhook_gateway.ingress import Ingress, Source
from webhook_gateway.signing import SignatureError, decode_secret, sign, verify
from webhook_gateway.store import Store

NOW = 1_800_000_000


class FakeClock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


def post_raw(url: str, path: str, body: bytes, headers: dict, timeout: float = 5) -> int:
    """POST with http.client so that header values are sent exactly as given (latin-1)."""
    host, port = url.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status
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
        code = post_raw(gw.url, "/hooks/shop", b"{}", {
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


if __name__ == "__main__":
    unittest.main()
