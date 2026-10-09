"""HTTP JSON API over the control plane (stdlib http.server).

Users:  Authorization: Bearer <token>
Robots: X-Robot, X-Ts, X-Nonce, X-Sig  (HMAC-SHA256 over method, path, ts, nonce, sha256(body))

  POST /robots                         {site, serial}             admin → {robot, secret}
  POST /robots/<id>/revoke                                        admin
  POST /robots/<id>/commands           {action, args, idem, ttl}  operator+ (Idempotency by `idem`)
  GET  /metrics                                                   any user (own tenant)
  GET  /robot/commands                                            robot (signed)
  POST /robot/commands/<id>/ack        {ok, result}               robot (signed)
  POST /robot/tasks                    {task}                     robot (signed)
"""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import Conflict, Fleet, Forbidden, NotFound, Unauthorized

CODES = {Unauthorized: 401, Forbidden: 403, NotFound: 404, Conflict: 409}


def make_handler(fleet: Fleet, lock: threading.Lock):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _route(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = json.loads(raw or b"{}")
            path = self.path
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            try:
                with lock:
                    if path.startswith("/robot/"):
                        me = fleet.robot_auth(self.headers.get("X-Robot"), method, path, float(self.headers.get("X-Ts") or 0),
                                              self.headers.get("X-Nonce") or "", self.headers.get("X-Sig") or "", raw)
                        if method == "GET" and path == "/robot/commands":
                            return self._send(200, {"commands": fleet.poll(me)})
                        if m := re.fullmatch(r"/robot/commands/([\w-]+)/ack", path):
                            return self._send(200, {"status": fleet.ack(me, m[1], bool(body.get("ok")), body.get("result", ""))})
                        if path == "/robot/tasks":
                            fleet.report_task(me, body["task"])
                            return self._send(200, {"ok": True})
                    if method == "POST" and path == "/robots":
                        rid, secret = fleet.register_robot(token, body["site"], body["serial"])
                        return self._send(201, {"robot": rid, "secret": secret})
                    if m := re.fullmatch(r"/robots/([\w-]+)/revoke", path):
                        fleet.revoke_robot(token, m[1])
                        return self._send(200, {"revoked": m[1]})
                    if m := re.fullmatch(r"/robots/([\w-]+)/commands", path):
                        c = fleet.send_command(token, m[1], body["action"], body.get("args", {}), body["idem"], body.get("ttl", 900))
                        return self._send(201, {k: c[k] for k in ("id", "seq", "status", "expires")})
                    if path == "/metrics":
                        u = fleet.user(token)
                        return self._send(200, fleet.metrics("robot in (select id from robots where tenant=?)", (u["tenant"],)))
                return self._send(404, {"error": "no such route"})
            except tuple(CODES) as e:
                return self._send(CODES[type(e)], {"error": str(e)})

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")
    return H


def serve(fleet: Fleet, port: int = 0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(fleet, threading.Lock()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
