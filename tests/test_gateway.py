import json
import random
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from email.utils import formatdate
from pathlib import Path

from webhook_gateway.__main__ import main, safe
from webhook_gateway.delivery import Policy, Worker, backoff, classify, parse_retry_after
from webhook_gateway.demo import SECRET, run, send
from webhook_gateway.ingress import MAX_BODY, Ingress, Source
from webhook_gateway.receiver import Receiver
from webhook_gateway.signing import SignatureError, decode_secret, sign, verify
from webhook_gateway.store import Conflict, Store

NOW = 1_800_000_000


def headers(msg_id="evt_1", ts=NOW, body=b"{}", secret=SECRET, sig=None):
    return {"webhook-id": msg_id, "webhook-timestamp": str(ts),
            "webhook-signature": sig or sign(secret, msg_id, ts, body)}


class SigningTests(unittest.TestCase):
    def test_valid_signature_returns_the_id(self):
        self.assertEqual(verify([SECRET], headers(), b"{}", NOW), "evt_1")

    def test_wrong_secret_and_tampered_body_are_refused(self):
        with self.assertRaisesRegex(SignatureError, "does not match"):
            verify(["whsec_b3RoZXI="], headers(), b"{}", NOW)
        with self.assertRaisesRegex(SignatureError, "does not match"):
            verify([SECRET], headers(), b'{"amount":1}', NOW)

    def test_rotation_accepts_old_and_new_secret_and_multiple_signatures(self):
        old, new = "whsec_b2xk", SECRET
        h = headers(secret=old)
        self.assertEqual(verify([new, old], h, b"{}", NOW), "evt_1")
        both = sign(new, "evt_1", NOW, b"{}") + " " + sign(old, "evt_1", NOW, b"{}")
        self.assertEqual(verify([new], headers(sig=both), b"{}", NOW), "evt_1")

    def test_timestamp_window_both_directions(self):
        for ts in (NOW - 301, NOW + 301):
            with self.assertRaisesRegex(SignatureError, "away from now"):
                verify([SECRET], headers(ts=ts), b"{}", NOW)
        self.assertEqual(verify([SECRET], headers(ts=NOW - 299), b"{}", NOW), "evt_1")

    def test_malformed_headers(self):
        for bad in ({}, {"webhook-id": "a", "webhook-timestamp": "1"},
                    dict(headers(), **{"webhook-timestamp": "12x"}),
                    dict(headers(), **{"webhook-id": "evt\x1b[31m"}),
                    dict(headers(), **{"webhook-signature": "v2,abc"})):
            with self.assertRaises(SignatureError):
                verify([SECRET], bad, b"{}", NOW)

    def test_secret_formats(self):
        self.assertEqual(decode_secret("whsec_ZGVtbw=="), b"demo")
        self.assertEqual(decode_secret("plain"), b"plain")
        with self.assertRaises(ValueError):
            decode_secret("whsec_***")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "gw.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_same_id_is_stored_once_and_other_body_conflicts(self):
        a = self.store.accept("shop", "evt_1", b"{}", "http://t", NOW)
        b = self.store.accept("shop", "evt_1", b"{}", "http://t", NOW + 5)
        self.assertEqual((a.duplicate, b.duplicate, a.event_id), (False, True, b.event_id))
        with self.assertRaises(Conflict):
            self.store.accept("shop", "evt_1", b'{"x":1}', "http://t", NOW)
        self.assertEqual(self.store.accept("crm", "evt_1", b"{}", "http://t", NOW).duplicate, False)
        self.assertEqual(self.store.counts()["events"], 2)

    def test_concurrent_copies_of_one_event_store_one_row(self):
        results, start = [], threading.Barrier(12)

        def go():
            start.wait()
            results.append(self.store.accept("shop", "evt_race", b"{}", "http://t", NOW).duplicate)

        threads = [threading.Thread(target=go) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), [False] + [True] * 11)
        self.assertEqual(self.store.counts()["pending"], 1)

    def test_a_stalled_worker_cannot_overwrite_the_worker_that_took_over(self):
        self.store.accept("shop", "evt_1", b"{}", "http://t", NOW)
        a = self.store.claim("a", NOW, lease_secs=10)
        self.assertIsNone(self.store.claim("b", NOW + 5, lease_secs=10))     # lease still held
        b = self.store.claim("b", NOW + 11, lease_secs=10)                   # lease ran out
        self.assertEqual((a.attempt, b.attempt), (1, 2))
        self.assertTrue(self.store.finish(b, NOW + 12, outcome="delivered", status=200, error=None))
        self.assertFalse(self.store.finish(a, NOW + 13, outcome="retry", status=503, error="late",
                                           next_at=NOW + 20))
        self.assertEqual(self.store.deliveries()[0]["state"], "delivered")
        self.assertEqual([x["outcome"] for x in self.store.attempts()], ["fenced", "delivered"])

    def test_retry_waits_for_next_at_and_replay_only_revives_dead_letters(self):
        ev = self.store.accept("shop", "evt_1", b"{}", "http://t", NOW).event_id
        c = self.store.claim("a", NOW, 10)
        self.store.finish(c, NOW, outcome="retry", status=503, error="x", next_at=NOW + 30)
        self.assertIsNone(self.store.claim("a", NOW + 29, 10))
        self.assertIsNotNone(c2 := self.store.claim("a", NOW + 30, 10))
        self.assertFalse(self.store.replay(ev, NOW))
        self.store.finish(c2, NOW + 31, outcome="dead", status=422, error="HTTP 422")
        self.assertTrue(self.store.replay(ev, NOW + 40))
        self.assertEqual(self.store.deliveries()[0]["attempts"], 0)


class DeliveryRuleTests(unittest.TestCase):
    def test_classification(self):
        for status, want in ((200, "delivered"), (204, "delivered"), (None, "retry"), (408, "retry"),
                             (425, "retry"), (429, "retry"), (500, "retry"), (503, "retry"),
                             (302, "dead"), (400, "dead"), (401, "dead"), (404, "dead"), (422, "dead")):
            self.assertEqual(classify(status), want, status)

    def test_backoff_is_full_jitter_capped_and_never_below_retry_after(self):
        p = Policy(base_delay=1, max_delay=60)
        rng = random.Random(7)
        for attempt in range(1, 12):
            for _ in range(200):
                d = backoff(attempt, p, rng)
                self.assertTrue(0 <= d <= min(60, 2 ** (attempt - 1)))
        self.assertGreaterEqual(backoff(1, p, rng, retry_after=30), 30)
        self.assertTrue(60 <= backoff(1, p, rng, retry_after=10_000) <= 61)    # floor capped, jitter on top

    def test_retry_after_parsing(self):
        self.assertEqual(parse_retry_after("120", NOW), 120)
        self.assertAlmostEqual(parse_retry_after(formatdate(NOW + 90, usegmt=True), NOW), 90, delta=1)
        self.assertEqual(parse_retry_after(formatdate(NOW - 90, usegmt=True), NOW), 0)
        for bad in (None, "", "soon", "-5", "1.5"):
            self.assertIsNone(parse_retry_after(bad, NOW))


class FakeClock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "gw.db")
        self.clock = FakeClock()
        self.store.accept("shop", "evt_1", b"{}", "http://t", NOW)

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, answers, **policy):
        seq = iter(answers)
        return Worker(self.store, Policy(**policy), name="w", rng=random.Random(1), clock=self.clock,
                      sender=lambda claim, timeout: next(seq))

    def test_gives_up_after_max_attempts(self):
        w = self.worker([(503, None, "HTTP 503")] * 3, max_attempts=3, base_delay=1, max_delay=1)
        outcomes = []
        for _ in range(3):
            outcomes.append(w.run_once())
            self.clock.t += 2
        self.assertEqual(outcomes, ["retry", "retry", "dead"])
        self.assertIn("gave up after 3 attempts", self.store.deliveries()[0]["last_error"])

    def test_permanent_refusal_is_dead_lettered_at_once(self):
        self.assertEqual(self.worker([(422, None, "HTTP 422")]).run_once(), "dead")
        self.assertEqual(self.store.deliveries()[0]["attempts"], 1)

    def test_retry_after_from_the_receiver_is_obeyed(self):
        w = self.worker([(429, "40", "HTTP 429")], base_delay=0.01)
        w.run_once()
        self.assertGreaterEqual(self.store.deliveries()[0]["next_at"], NOW + 40)

    def test_expired_leases_count_against_the_budget(self):
        for _ in range(2):                       # two workers die mid-attempt
            self.store.claim("dying", self.clock(), 1)
            self.clock.t += 2
        sent = []
        w = Worker(self.store, Policy(max_attempts=2), name="w", clock=self.clock,
                   sender=lambda c, t: sent.append(c) or (200, None, None))
        self.assertEqual(w.run_once(), "dead")
        self.assertEqual(sent, [])


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = Store(root / "gw.db")
        self.receiver = Receiver(root / "rcv.db").start()
        self.gw = Ingress(self.store, {"shop": Source("shop", (SECRET,), self.receiver.url)}).start()
        self.hook = self.gw.url + "/hooks/shop"

    def tearDown(self):
        self.gw.shutdown()
        self.receiver.shutdown()
        self.tmp.cleanup()

    def raw(self, path, body=b"{}", ctype="application/json", extra=None):
        h = {"Content-Type": ctype, **(extra or {})}
        req = urllib.request.Request(self.gw.url + path, data=body, method="POST", headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            with e:
                return e.code

    def test_refusals_store_nothing(self):
        self.assertEqual(send(self.hook, "e1", {"a": 1}, secret="whsec_eA==")[0], 401)
        self.assertEqual(send(self.hook, "e2", {"a": 1}, ts=int(time.time()) - 400)[0], 401)
        self.assertEqual(self.raw("/hooks/unknown"), 404)
        self.assertEqual(self.raw("/hooks/shop", ctype="text/plain"), 415)
        self.assertEqual(self.raw("/hooks/shop", body=b"x" * (MAX_BODY + 1)), 413)
        self.assertEqual(send(self.hook, "e3", b"not json")[0], 400)
        self.assertEqual(self.store.counts()["events"], 0)

    def test_delivery_carries_the_idempotency_key_and_receiver_applies_once(self):
        self.assertEqual(send(self.hook, "evt_9", {"a": 1})[0], 202)
        w = Worker(self.store, Policy(base_delay=0.01), name="w")
        self.assertEqual(w.run_until_idle(time.time() + 10), ["delivered"])
        self.store.replay  # noqa: B018 - the dead-letter path is covered in StoreTests
        claim_again = self.store.accept("shop", "evt_9", json.dumps({"a": 1}, separators=(",", ":")).encode(),
                                        self.receiver.url, time.time())
        self.assertTrue(claim_again.duplicate)
        self.assertEqual(self.receiver.effects(), ["shop:evt_9"])

    def test_unreachable_target_is_retried_not_lost(self):
        self.store.accept("shop", "evt_x", b"{}", "http://127.0.0.1:9/none", time.time())
        w = Worker(self.store, Policy(base_delay=0.01, timeout=1), name="w")
        self.assertEqual(w.run_once(), "retry")
        d = self.store.deliveries()[0]
        self.assertEqual((d["state"], d["last_status"]), ("pending", None))
        self.assertTrue(d["last_error"])


class EndToEndTests(unittest.TestCase):
    def test_demo_passes_every_step(self):
        result = run()
        self.assertTrue(result["pass"], [s for s in result["steps"] if not s["pass"]])
        self.assertEqual(len(result["steps"]), 10)
        self.assertEqual(result["summary"]["effects_per_event"], 1)


class CliTests(unittest.TestCase):
    def test_safe_escapes_terminal_control_and_bidi(self):
        self.assertEqual(safe("a\x1b[31mb"), "a\\x1b[31mb")
        self.assertNotIn("‮", safe("x‮y"))

    def test_serve_refuses_a_source_without_secret(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["serve", "--db", str(Path(d) / "g.db"), "--source", "shop=http://t"]), 2)


if __name__ == "__main__":
    unittest.main()
