"""Deliver stored events to the configured target, at least once, with an idempotency key.

The gateway can never know whether a receiver applied an event when the connection broke
or the worker died after the receiver answered. So it delivers at least once and sends the
same ``Idempotency-Key`` (``<source>:<webhook id>``) on every attempt; a receiver that
stores that key in the same transaction as its effect applies each event exactly once.

Retry rules:
- 2xx: delivered.
- 408, 425, 429, 5xx and network errors: retried with exponential backoff and full jitter.
  A ``Retry-After`` from the receiver (capped at ``max_delay``) is a floor, and the jitter
  is added on top of it, so events told to wait the same time do not return together.
- any other 4xx: the receiver refused this event for good; it goes to the dead-letter list
  at once instead of using up the retry budget. An operator can replay it later.
- after ``max_attempts`` the event goes to the dead-letter list as well.
"""
from __future__ import annotations

import email.utils
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .store import Claim, Store

RETRYABLE = {408, 425, 429}
MAX_ERROR = 300


@dataclass(frozen=True)
class Policy:
    max_attempts: int = 8
    base_delay: float = 1.0
    max_delay: float = 300.0
    lease_secs: float = 30.0
    timeout: float = 10.0


def parse_retry_after(value: str | None, now: float) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or an HTTP date)."""
    if not value:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():   # isdigit() alone accepts '\u00b2', which float() rejects
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None or when.tzinfo is None:
        return None
    return max(0.0, when.timestamp() - now)


def backoff(attempt: int, policy: Policy, rng: random.Random, retry_after: float | None = None) -> float:
    """Full jitter: uniform(0, min(max_delay, base * 2**(attempt-1))).

    With Retry-After the jitter goes on top of min(Retry-After, max_delay): never sooner than
    the receiver asked, and not all at the same instant either.
    """
    ceiling = min(policy.max_delay, policy.base_delay * (2 ** max(0, attempt - 1)))
    floor = 0.0 if retry_after is None else min(retry_after, policy.max_delay)
    return floor + rng.uniform(0, ceiling)


def classify(status: int | None) -> str:
    if status is None:
        return "retry"                      # network error, timeout, refused connection
    if 200 <= status < 300:
        return "delivered"
    if status in RETRYABLE or status >= 500:
        return "retry"
    return "dead"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a target that moves must be reconfigured
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post(claim: Claim, timeout: float) -> tuple[int | None, str | None, str | None]:
    """POST the stored body. Returns (status, retry_after_header, error)."""
    req = urllib.request.Request(claim.target, data=claim.body, method="POST", headers={
        "Content-Type": "application/json",
        "Idempotency-Key": f"{claim.source}:{claim.msg_id}",
        "X-Gateway-Attempt": str(claim.attempt),
        "User-Agent": "webhook-reliability-gateway",
    })
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Retry-After"), None
    except urllib.error.HTTPError as e:
        with e:                             # an HTTPError is also the open response: close it
            return e.code, e.headers.get("Retry-After") if e.headers else None, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return None, None, f"{type(e).__name__}: {getattr(e, 'reason', e)}"[:MAX_ERROR]


class Worker:
    def __init__(self, store: Store, policy: Policy = Policy(), name: str | None = None,
                 rng: random.Random | None = None, clock=time.time, sender=post):
        self.store = store
        self.policy = policy
        self.name = name or f"worker-{os.getpid()}"
        self.rng = rng or random.Random()
        self.clock = clock
        self.sender = sender

    def run_once(self) -> str | None:
        """Claim and deliver one due event. Returns its outcome, or None when idle."""
        claim = self.store.claim(self.name, self.clock(), self.policy.lease_secs)
        if claim is None:
            return None
        if claim.attempt > self.policy.max_attempts:
            # leases that expired (workers dying mid-attempt) count against the budget too
            kept = self.store.finish(claim, self.clock(), outcome="dead", status=None,
                                     error=f"gave up: {claim.attempt - 1} attempts without a result")
            return "dead" if kept else "fenced"
        status, retry_after, error = self.sender(claim, self.policy.timeout)
        now = self.clock()
        outcome = classify(status)
        next_at = None
        if outcome == "retry":
            if claim.attempt >= self.policy.max_attempts:
                outcome, error = "dead", f"gave up after {claim.attempt} attempts: {error or status}"
            else:
                next_at = now + backoff(claim.attempt, self.policy, self.rng, parse_retry_after(retry_after, now))
        elif outcome == "dead":
            error = error or f"HTTP {status}"
        kept = self.store.finish(claim, now, outcome=outcome, status=status, error=error, next_at=next_at)
        return outcome if kept else "fenced"

    def run_until_idle(self, deadline: float, poll: float = 0.02) -> list:
        """Deliver until nothing is due or pending, or until ``deadline`` (clock time)."""
        outcomes = []
        while self.clock() < deadline:
            out = self.run_once()
            if out is not None:
                outcomes.append(out)
                continue
            counts = self.store.counts()
            if not counts.get("pending") and not counts.get("leased"):
                break
            time.sleep(poll)
        return outcomes
