"""HTTP ingress: verify, store, then answer.

    POST /hooks/<source>     Standard Webhooks headers, JSON body up to MAX_BODY

202 {"event": id, "duplicate": false}   stored and queued (answered after COMMIT)
200 {"event": id, "duplicate": true}    the same id and body were stored before
401  signature missing, wrong, or timestamp outside the tolerance window: nothing stored
404  unknown source       409  same id, different body      413  body too large
415  not application/json

Binds to loopback by default; put a TLS-terminating proxy in front for real traffic.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .signing import TOLERANCE, SignatureError, verify
from .store import Conflict, Store

MAX_BODY = 256 * 1024


@dataclass(frozen=True)
class Source:
    name: str
    secrets: tuple          # current secret first; an old one may stay during rotation
    target: str             # where its events are delivered (fixed by the operator)


class Ingress:
    def __init__(self, store: Store, sources: dict, host: str = "127.0.0.1", port: int = 0,
                 clock=time.time, tolerance: int = TOLERANCE):
        self.store, self.sources, self.clock, self.tolerance = store, sources, clock, tolerance
        gw = self

        class Handler(_Handler):
            ctx = gw

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://{host}:{self.httpd.server_address[1]}"

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class _Handler(BaseHTTPRequestHandler):
    ctx: Ingress = None
    server_version = "webhook-gateway"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _json(self, code: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        if len(parts) != 2 or parts[0] != "hooks" or parts[1] not in self.ctx.sources:
            return self._json(404, {"error": "unknown source"})
        source = self.ctx.sources[parts[1]]
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return self._json(415, {"error": "body must be application/json"})
        try:
            length = int(self.headers.get("Content-Length") or "-1")
        except ValueError:
            length = -1
        if length < 0:
            return self._json(411, {"error": "Content-Length required"})
        if length > MAX_BODY:
            return self._json(413, {"error": f"body over {MAX_BODY} bytes"})
        body = self.rfile.read(length)
        try:
            msg_id = verify(list(source.secrets), self.headers, body, self.ctx.clock(), self.ctx.tolerance)
        except SignatureError as e:
            return self._json(401, {"error": str(e)})
        try:
            json.loads(body)
        except ValueError:
            return self._json(400, {"error": "body is not valid JSON"})
        try:
            acc = self.ctx.store.accept(source.name, msg_id, body, source.target, self.ctx.clock())
        except Conflict as e:
            return self._json(409, {"error": str(e)})
        return self._json(200 if acc.duplicate else 202, {"event": acc.event_id, "duplicate": acc.duplicate})
