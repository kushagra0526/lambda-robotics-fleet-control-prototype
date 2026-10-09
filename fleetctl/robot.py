"""Robot-side agent: signs every request, executes each command at most once, never after it expires."""
from __future__ import annotations

import json
import secrets

from .core import sign


class RobotAgent:
    def __init__(self, rid: str, secret: str, clock):
        self.rid, self.secret, self.clock = rid, secret, clock
        self.executed: dict[str, float] = {}       # command id → when it ran
        self.dup_ignored = 0
        self.stale_rejected = 0

    def headers(self, method: str, path: str, body: bytes, ts=None, nonce=None) -> dict:
        ts = self.clock() if ts is None else ts
        nonce = nonce or secrets.token_hex(8)
        return {"robot": self.rid, "ts": ts, "nonce": nonce, "sig": sign(self.secret, method, path, ts, nonce, body)}

    def handle(self, cmds: list[dict]) -> list[tuple[str, bool, str]]:
        """→ acks to send: (command id, ok, result)."""
        acks = []
        for c in sorted(cmds, key=lambda c: c["seq"]):
            if c["id"] in self.executed:
                self.dup_ignored += 1
                continue
            if c["expires"] <= self.clock():
                self.stale_rejected += 1
                acks.append((c["id"], False, "expired on arrival, not executed"))
                continue
            self.executed[c["id"]] = self.clock()
            acks.append((c["id"], True, f"{c['action']} {json.dumps(c['args'])} done"))
        return acks
