"""Command line.

    python -m webhook_gateway demo [--json]
    python -m webhook_gateway serve --db gw.db --source shop=https://orders.internal/hooks [--port 8080]
    python -m webhook_gateway worker --db gw.db [--once]
    python -m webhook_gateway status --db gw.db
    python -m webhook_gateway dead --db gw.db
    python -m webhook_gateway replay --db gw.db EVENT_ID

Secrets never go on the command line: ``serve`` reads WEBHOOK_SECRET_<SOURCE> (upper case;
several space-separated values during a rotation).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .delivery import Policy, Worker
from .store import Store


def safe(value) -> str:
    """Printable text only: stored ids and errors come from other systems."""
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in str(value))


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="webhook_gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the measured end-to-end demo")
    d.add_argument("--json", action="store_true")
    s = sub.add_parser("serve", help="receive webhooks (loopback by default)")
    s.add_argument("--db", required=True)
    s.add_argument("--source", action="append", required=True, metavar="NAME=TARGET_URL")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    w = sub.add_parser("worker", help="deliver queued events")
    w.add_argument("--db", required=True)
    w.add_argument("--once", action="store_true", help="deliver what is due now, then exit")
    for name in ("status", "dead"):
        sub.add_parser(name).add_argument("--db", required=True)
    r = sub.add_parser("replay", help="put a dead letter back in the queue")
    r.add_argument("--db", required=True)
    r.add_argument("event_id", type=int)
    c = sub.add_parser("_crash-once")
    c.add_argument("--db", required=True)
    c.add_argument("--lease", type=float, required=True)
    return ap


def main(argv=None) -> int:
    a = _parser().parse_args(argv)
    if a.cmd == "demo":
        from .demo import run
        result = run()
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            for s in result["steps"]:
                print(f"{s['step']}. {'PASS' if s['pass'] else 'FAIL'}  {s['name']}\n   {safe(s['observed'])}")
            print("PASS" if result["pass"] else "FAIL")
        return 0 if result["pass"] else 1
    if a.cmd == "_crash-once":
        from .demo import crash_once
        crash_once(a.db, a.lease)
    store = Store(a.db)
    if a.cmd == "serve":
        from .ingress import Ingress, Source
        from .signing import decode_secret
        sources = {}
        for spec in a.source:
            name, _, target = spec.partition("=")
            secrets = os.environ.get(f"WEBHOOK_SECRET_{name.upper()}", "").split()
            if not name or not target.startswith(("http://", "https://")) or not secrets:
                print(f"--source {safe(spec)}: need NAME=http(s)://target and WEBHOOK_SECRET_{safe(name.upper())}",
                      file=sys.stderr)
                return 2
            try:
                for secret in secrets:
                    decode_secret(secret)
            except ValueError as e:
                print(f"WEBHOOK_SECRET_{safe(name.upper())}: {e}", file=sys.stderr)
                return 2
            sources[name] = Source(name, tuple(secrets), target)
        gw = Ingress(store, sources, a.host, a.port)
        print(f"receiving on {gw.url}/hooks/<source> for {', '.join(sorted(sources))}", flush=True)
        try:
            gw.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    if a.cmd == "worker":
        w = Worker(store, Policy())
        if a.once:
            outcomes = w.run_until_idle(time.time() + 60)
            print(json.dumps({o: outcomes.count(o) for o in sorted(set(outcomes))}))
            return 0
        while True:
            if w.run_once() is None:
                time.sleep(0.5)
    if a.cmd == "status":
        print(json.dumps(store.counts(), indent=2))
        return 0
    if a.cmd == "dead":
        for d in store.deliveries("dead"):
            print(f"{d['event_id']}  {safe(d['source'])}:{safe(d['msg_id'])}  attempts={d['attempts']}  "
                  f"{safe(d['last_error'])}")
        return 0
    if a.cmd == "replay":
        ok = store.replay(a.event_id, time.time())
        print("queued again" if ok else "no dead letter with this id")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
