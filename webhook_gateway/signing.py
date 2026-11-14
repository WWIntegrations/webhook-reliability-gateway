"""Webhook signatures in the Standard Webhooks format.

A sender signs ``<webhook-id>.<webhook-timestamp>.<body>`` with HMAC-SHA256 and sends
``webhook-signature: v1,<base64>``. Several space-separated signatures are allowed so a
secret can be rotated without dropping events. A timestamp further than ``tolerance``
seconds from now (in either direction) is refused, which bounds how long a captured
request can be replayed; within that window the event id deduplicates it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

TOLERANCE = 300
MAX_ID = 128


class SignatureError(ValueError):
    """The request is not from a sender that holds the secret, or is too old."""


def decode_secret(secret: str) -> bytes:
    """Accept ``whsec_<base64>`` (the usual format) or any other string as raw bytes."""
    if secret.startswith("whsec_"):
        try:
            key = base64.b64decode(secret[6:], validate=True)
        except ValueError as e:
            raise ValueError("secret after whsec_ is not valid base64") from e
    else:
        key = secret.encode("utf-8")
    if not key:      # an empty HMAC key is public: anyone could sign with it
        raise ValueError("empty secret")
    return key


def sign(secret: str, msg_id: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(decode_secret(secret), f"{msg_id}.{timestamp}.".encode() + body, hashlib.sha256)
    return "v1," + base64.b64encode(mac.digest()).decode()


def verify(secrets: list, headers, body: bytes, now: float, tolerance: int = TOLERANCE) -> str:
    """Return the webhook id when one of ``secrets`` signed this request; raise otherwise.

    ``headers`` is any mapping with case-insensitive ``get`` (http.server's is).
    """
    msg_id = (headers.get("webhook-id") or "").strip()
    ts_raw = (headers.get("webhook-timestamp") or "").strip()
    sig_header = headers.get("webhook-signature") or ""
    if not msg_id or not ts_raw or not sig_header:
        raise SignatureError("missing webhook-id, webhook-timestamp or webhook-signature")
    if len(msg_id) > MAX_ID or not msg_id.isprintable():
        raise SignatureError("webhook-id is too long or has control characters")
    # isascii(): str.isdigit() also accepts characters such as '\u00b2' that int() rejects
    if not (ts_raw.isascii() and ts_raw.isdigit()) or len(ts_raw) > 12:
        raise SignatureError("webhook-timestamp is not a number of seconds")
    ts = int(ts_raw)
    if abs(now - ts) > tolerance:
        raise SignatureError(f"timestamp is {int(now - ts)} s away from now (limit {tolerance} s)")
    given = [part.split(",", 1)[1] for part in sig_header.split() if part.startswith("v1,")]
    if not given:
        raise SignatureError("no v1 signature")
    for secret in secrets:
        expected = sign(secret, msg_id, ts, body).split(",", 1)[1]
        # compare every candidate in constant time; never stop at the first byte that differs
        if any(hmac.compare_digest(expected.encode(), g.encode()) for g in given):
            return msg_id
    raise SignatureError("signature does not match")
