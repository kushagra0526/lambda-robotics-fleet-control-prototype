"""Fleet control plane: identity, tenancy, commands, telemetry, OTA, audit. sqlite + stdlib.

Errors map to HTTP: Unauthorized 401, Forbidden 403, NotFound 404 (also used for other tenants' objects,
so a caller can't learn that a robot exists somewhere else), Conflict 409.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import sqlite3
import time

CLOCK_SKEW = 60          # seconds a signed robot request may be off
ROLES = {"viewer": 0, "operator": 1, "admin": 2}


class Unauthorized(Exception): ...
class Forbidden(Exception): ...
class NotFound(Exception): ...
class Conflict(Exception): ...


def sha(s: str | bytes) -> str:
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def sign(secret: str, method: str, path: str, ts: float, nonce: str, body: bytes) -> str:
    msg = f"{method}\n{path}\n{ts:.3f}\n{nonce}\n{sha(body)}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


SCHEMA = """
create table tenants(id integer primary key, name text);
create table sites(id integer primary key, tenant integer, name text);
create table users(id integer primary key, name text, tenant integer, site integer, role text, token_hash text unique);
create table robots(id text primary key, tenant integer, site integer, serial text, secret text, revoked integer default 0,
                    firmware text, next_seq integer default 1, last_seen real);
create table nonces(robot text, nonce text, ts real, primary key(robot, nonce));
create table commands(id text primary key, robot text, tenant integer, seq integer, action text, args text, idem text,
                      created real, expires real, status text, delivered real, finished real, result text, by_user integer,
                      unique(robot, idem));
create table tasks(id integer primary key, robot text, firmware text, ts real, ok integer, decisions integer, failures integer,
                   recovered integer, interventions integer, operator_min real);
create table interventions(id integer primary key, robot text, firmware text, ts real, task_type text, step integer,
                           state_ref text, operator_action text);
create table rollouts(id integer primary key, tenant integer, firmware text, baseline text, stage integer, stages text,
                      status text, started real, stage_started real, detail text);
create table audit(id integer primary key, ts real, actor text, action text, target text, allowed integer, detail text);
"""


class Fleet:
    def __init__(self, now=time.time, db=":memory:"):
        self.now = now
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ------------------------------------------------------------ audit
    def audit(self, actor, action, target, allowed, detail=""):
        self.db.execute("insert into audit(ts, actor, action, target, allowed, detail) values(?,?,?,?,?,?)",
                        (self.now(), actor, action, str(target), int(allowed), detail))

    def _deny(self, exc, actor, action, target, detail):
        self.audit(actor, action, target, False, f"{exc.__name__}: {detail}")
        raise exc(detail)

    # ------------------------------------------------------------ tenancy and users
    def create_tenant(self, name):
        return self.db.execute("insert into tenants(name) values(?)", (name,)).lastrowid

    def create_site(self, tenant, name):
        return self.db.execute("insert into sites(tenant, name) values(?,?)", (tenant, name)).lastrowid

    def create_user(self, name, tenant, role, site=None):
        assert role in ROLES
        token = secrets.token_urlsafe(24)
        self.db.execute("insert into users(name, tenant, site, role, token_hash) values(?,?,?,?,?)", (name, tenant, site, role, sha(token)))
        return token

    def user(self, token):
        u = self.db.execute("select * from users where token_hash=?", (sha(token or ""),)).fetchone()
        if not u:
            self._deny(Unauthorized, "anonymous", "auth", "-", "unknown token")
        return u

    def _robot_for_user(self, u, robot_id, need, action):
        r = self.db.execute("select * from robots where id=?", (robot_id,)).fetchone()
        actor = f"user:{u['name']}"
        if not r or r["tenant"] != u["tenant"] or (u["site"] is not None and r["site"] != u["site"]):
            self._deny(NotFound, actor, action, robot_id, "no such robot in your scope")
        if ROLES[u["role"]] < ROLES[need]:
            self._deny(Forbidden, actor, action, robot_id, f"role {u['role']} cannot {action}")
        return r

    # ------------------------------------------------------------ robot identity
    def register_robot(self, token, site, serial, firmware="v1.4"):
        u = self.user(token)
        s = self.db.execute("select * from sites where id=?", (site,)).fetchone()
        if not s or s["tenant"] != u["tenant"]:
            self._deny(NotFound, f"user:{u['name']}", "register", site, "no such site in your scope")
        if u["role"] != "admin":
            self._deny(Forbidden, f"user:{u['name']}", "register", serial, "only admins register robots")
        rid, secret = f"r-{secrets.token_hex(4)}", secrets.token_hex(32)
        self.db.execute("insert into robots(id, tenant, site, serial, secret, firmware) values(?,?,?,?,?,?)",
                        (rid, u["tenant"], site, serial, secret, firmware))
        self.audit(f"user:{u['name']}", "register", rid, True, serial)
        return rid, secret

    def revoke_robot(self, token, robot_id):
        u = self.user(token)
        self._robot_for_user(u, robot_id, "admin", "revoke")
        self.db.execute("update robots set revoked=1 where id=?", (robot_id,))
        self.audit(f"user:{u['name']}", "revoke", robot_id, True)

    def robot_auth(self, robot_id, method, path, ts, nonce, sig, body=b""):
        actor = f"robot:{robot_id}"
        r = self.db.execute("select * from robots where id=?", (robot_id,)).fetchone()
        if not r:
            self._deny(Unauthorized, actor, f"{method} {path}", robot_id, "unknown robot")
        if r["revoked"]:
            self._deny(Unauthorized, actor, f"{method} {path}", robot_id, "robot credentials revoked")
        if not hmac.compare_digest(sign(r["secret"], method, path, ts, nonce, body), sig):
            self._deny(Unauthorized, actor, f"{method} {path}", robot_id, "bad signature")
        if abs(self.now() - ts) > CLOCK_SKEW:
            self._deny(Unauthorized, actor, f"{method} {path}", robot_id, f"timestamp {self.now() - ts:+.0f}s outside ±{CLOCK_SKEW}s")
        self.db.execute("delete from nonces where ts < ?", (self.now() - 2 * CLOCK_SKEW,))
        try:
            self.db.execute("insert into nonces values(?,?,?)", (robot_id, nonce, ts))
        except sqlite3.IntegrityError:
            self._deny(Unauthorized, actor, f"{method} {path}", robot_id, "replayed nonce")
        self.db.execute("update robots set last_seen=? where id=?", (self.now(), robot_id))
        return r

    # ------------------------------------------------------------ commands
    def send_command(self, token, robot_id, action, args, idem, ttl=120):
        u = self.user(token)
        r = self._robot_for_user(u, robot_id, "operator", f"command:{action}")
        old = self.db.execute("select * from commands where robot=? and idem=?", (robot_id, idem)).fetchone()
        if old:
            if old["action"] != action or json.loads(old["args"]) != args:
                self._deny(Conflict, f"user:{u['name']}", f"command:{action}", robot_id, "idempotency key reused with a different command")
            return dict(old)  # a retried POST gets the same command back, nothing new is queued
        seq = r["next_seq"]
        cid = f"c-{secrets.token_hex(5)}"
        self.db.execute("update robots set next_seq=next_seq+1 where id=?", (robot_id,))
        self.db.execute("insert into commands(id, robot, tenant, seq, action, args, idem, created, expires, status, by_user) "
                        "values(?,?,?,?,?,?,?,?,?,?,?)", (cid, robot_id, r["tenant"], seq, action, json.dumps(args), idem,
                                                          self.now(), self.now() + ttl, "QUEUED", u["id"]))
        self.audit(f"user:{u['name']}", f"command:{action}", robot_id, True, f"{cid} seq {seq} ttl {ttl}s")
        return dict(self.db.execute("select * from commands where id=?", (cid,)).fetchone())

    def sweep(self):
        n = self.db.execute("update commands set status='EXPIRED', finished=? where status in ('QUEUED','DELIVERED') and expires <= ?",
                            (self.now(), self.now())).rowcount
        return n

    def poll(self, robot):
        self.sweep()
        rows = self.db.execute("select * from commands where robot=? and status in ('QUEUED','DELIVERED') order by seq", (robot["id"],)).fetchall()
        for c in rows:
            self.db.execute("update commands set status='DELIVERED', delivered=coalesce(delivered, ?) where id=?", (self.now(), c["id"]))
        return [{"id": c["id"], "seq": c["seq"], "action": c["action"], "args": json.loads(c["args"]), "expires": c["expires"]} for c in rows]

    def ack(self, robot, cid, ok, result=""):
        c = self.db.execute("select * from commands where id=? and robot=?", (cid, robot["id"])).fetchone()
        if not c:
            self._deny(NotFound, f"robot:{robot['id']}", "ack", cid, "not your command")
        if c["status"] in ("DONE", "FAILED", "EXPIRED"):
            return c["status"]  # duplicate ack after a retry
        self.db.execute("update commands set status=?, finished=?, result=? where id=?", ("DONE" if ok else "FAILED", self.now(), result, cid))
        return "DONE" if ok else "FAILED"

    # ------------------------------------------------------------ telemetry
    def report_task(self, robot, t):
        fw = robot["firmware"]
        self.db.execute("insert into tasks(robot, firmware, ts, ok, decisions, failures, recovered, interventions, operator_min) values(?,?,?,?,?,?,?,?,?)",
                        (robot["id"], fw, self.now(), int(t["ok"]), t["decisions"], t["failures"], t["recovered"], len(t["interventions"]), t["operator_min"]))
        for iv in t["interventions"]:
            self.db.execute("insert into interventions(robot, firmware, ts, task_type, step, state_ref, operator_action) values(?,?,?,?,?,?,?)",
                            (robot["id"], fw, self.now(), t["type"], iv["step"], iv["state_ref"], iv["action"]))

    def metrics(self, where="1=1", args=()):
        rows = self.db.execute(f"select firmware, count(*) n, avg(ok) done, sum(interventions) iv, sum(operator_min) om, sum(failures) f, "
                               f"sum(recovered) rec from tasks where {where} group by firmware", args).fetchall()
        return {r["firmware"]: {"tasks": r["n"], "completion": r["done"], "interventions_per_task": r["iv"] / r["n"],
                                "operator_min_per_task": r["om"] / r["n"], "recovery": (r["rec"] / r["f"]) if r["f"] else 1.0,
                                "interventions": r["iv"]} for r in rows}

    def retrain_queue(self, limit=10):
        return [dict(r) for r in self.db.execute("select firmware, task_type, step, count(*) n from interventions group by firmware, task_type, step "
                                                 "order by n desc limit ?", (limit,))]

    # ------------------------------------------------------------ OTA
    def start_rollout(self, token, firmware, stages=(0.1, 0.5, 1.0)):
        u = self.user(token)
        if u["role"] != "admin":
            self._deny(Forbidden, f"user:{u['name']}", "rollout", firmware, "only admins roll out firmware")
        robots = self.db.execute("select id, firmware from robots where tenant=? and revoked=0 order by id", (u["tenant"],)).fetchall()
        base = max({r["firmware"] for r in robots}, key=lambda f: sum(x["firmware"] == f for x in robots))
        rid = self.db.execute("insert into rollouts(tenant, firmware, baseline, stage, stages, status, started, stage_started, detail) "
                              "values(?,?,?,?,?,?,?,?,?)", (u["tenant"], firmware, base, 0, json.dumps(stages), "RUNNING", self.now(), self.now(), "")).lastrowid
        self._apply_stage(rid)
        self.audit(f"user:{u['name']}", "rollout", firmware, True, f"stages {stages}")
        return rid

    def _apply_stage(self, rid):
        ro = self.db.execute("select * from rollouts where id=?", (rid,)).fetchone()
        robots = self.db.execute("select id from robots where tenant=? and revoked=0 order by serial", (ro["tenant"],)).fetchall()
        k = max(1, math.ceil(json.loads(ro["stages"])[ro["stage"]] * len(robots)))
        for r in robots[:k]:
            self.db.execute("update robots set firmware=? where id=?", (ro["firmware"], r["id"]))

    def rollout_gate(self, rid, min_tasks=100, alpha=0.01):
        """Canary tasks since this stage started vs baseline-firmware tasks in the last 24 h (same tenant). → status.

        Two-sample test on interventions: given k interventions in total, the canary's share is Binomial(k, n_c / (n_c + n_b))
        if both builds are equally good. Roll back when the canary's share is improbably high.
        """
        ro = self.db.execute("select * from rollouts where id=?", (rid,)).fetchone()
        if ro["status"] != "RUNNING":
            return ro["status"]
        scope = "robot in (select id from robots where tenant=?)"
        c = self.metrics(f"ts >= ? and {scope}", (ro["stage_started"], ro["tenant"])).get(ro["firmware"])
        b = self.metrics(f"ts >= ? and {scope}", (self.now() - 86400, ro["tenant"])).get(ro["baseline"])
        if not c or c["tasks"] < min_tasks:
            return "RUNNING"
        if b and b["tasks"] >= min_tasks:
            k = c["interventions"] + b["interventions"]
            p = binom_sf(c["interventions"], k, c["tasks"] / (c["tasks"] + b["tasks"]))
            dz = (b["completion"] - c["completion"]) / math.sqrt(max(b["completion"] * (1 - b["completion"]), 1e-6) * (1 / c["tasks"] + 1 / b["tasks"]))
            if p < alpha or dz > 3:
                why = (f"interventions/task {c['interventions_per_task']:.2f} vs {b['interventions_per_task']:.2f} (p={p:.1e}); "
                       f"completion {c['completion']:.1%} vs {b['completion']:.1%}")
                self.db.execute("update robots set firmware=? where tenant=? and firmware=?", (ro["baseline"], ro["tenant"], ro["firmware"]))
                self.db.execute("update rollouts set status='ROLLED_BACK', detail=? where id=?", (why, rid))
                self.audit("system:ota", "rollback", ro["firmware"], True, why)
                return "ROLLED_BACK"
        stages = json.loads(ro["stages"])
        if ro["stage"] + 1 >= len(stages):
            self.db.execute("update rollouts set status='COMPLETE' where id=?", (rid,))
            self.audit("system:ota", "complete", ro["firmware"], True)
            return "COMPLETE"
        self.db.execute("update rollouts set stage=stage+1, stage_started=? where id=?", (self.now(), rid))
        self._apply_stage(rid)
        self.audit("system:ota", "advance", ro["firmware"], True, f"stage {ro['stage'] + 1}: {stages[ro['stage'] + 1]:.0%}")
        return "RUNNING"


def binom_sf(x: int, n: int, p: float) -> float:
    """P(X >= x) for X ~ Binomial(n, p), summed in log space."""
    if x <= 0:
        return 1.0
    if p >= 1:
        return 1.0
    lp, lq = math.log(p), math.log1p(-p)
    terms = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq for i in range(x, n + 1)]
    m = max(terms)
    return min(1.0, math.exp(m) * sum(math.exp(t - m) for t in terms))


def poisson_sf(k: int, lam: float) -> float:
    """P(X >= k) for X ~ Poisson(lam)."""
    if k <= 0:
        return 1.0
    if lam > 400:  # normal approximation, avoids underflow
        return 0.5 * math.erfc((k - 0.5 - lam) / math.sqrt(2 * lam))
    term, cdf = math.exp(-lam), 0.0
    for i in range(k):
        cdf += term
        term *= lam / (i + 1)
    return max(0.0, 1.0 - cdf)
