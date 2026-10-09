"""Five shifts of a 24-robot fleet across two customers' data centers, over a flaky network, with planted attacks and two OTA builds.

Everything is simulated: tenants, robots, tasks and failure rates are invented.
"""
from __future__ import annotations

import json
import random
import secrets

from .core import Conflict, Fleet, Forbidden, NotFound, Unauthorized
from .robot import RobotAgent

FIRMWARE_Q = {"v1.4": 0.030, "v1.5": 0.050, "v1.5.1": 0.025}   # per-decision failure probability
WEAK_STEP = {"v1.4": None, "v1.5": 23, "v1.5.1": None}           # v1.5 regressed on step 23 (latch grasp)
TASKS = ["drive_swap", "cable_reseat", "thermal_inspection"]


class Clock:
    def __init__(self, t0=1_790_000_000.0):
        self.t = t0

    def __call__(self):
        return self.t


def robot_req(fleet, agent, method, path, body=None, ts=None, nonce=None, hdr=None):
    raw = json.dumps(body or {}).encode()
    h = hdr or agent.headers(method, path, raw, ts, nonce)
    return fleet.robot_auth(h["robot"], method, path, h["ts"], h["nonce"], h["sig"], raw), h


def task(rng, fw, rid, ts):
    q, kind = FIRMWARE_Q[fw], rng.choice(TASKS)
    failures = recovered = 0
    ivs, op_min, ok = [], 0.0, True
    for step in range(40):
        p = q * (4 if WEAK_STEP[fw] == step else 1)
        if rng.random() < p:
            failures += 1
            if rng.random() < 0.8:
                recovered += 1
            else:
                ivs.append({"step": step, "state_ref": f"s3://fleet-logs/{rid}/{int(ts)}/step{step}.mcap",
                            "action": rng.choice(["teleop: regrasp", "teleop: reposition", "manual reset"])})
                op_min += rng.uniform(2, 6)
                ok = ok and rng.random() > 0.1
    return {"type": kind, "ok": ok, "decisions": 40, "failures": failures, "recovered": recovered, "interventions": ivs, "operator_min": op_min}


def run(seed=11):
    rng, clock = random.Random(seed), Clock()
    f = Fleet(now=clock)
    nb, cv = f.create_tenant("Northbeam DC"), f.create_tenant("Corvid AI Cloud")
    sjc1, sjc2, pdx1 = f.create_site(nb, "SJC-1"), f.create_site(nb, "SJC-2"), f.create_site(cv, "PDX-1")
    tok = {"nb_admin": f.create_user("nb_admin", nb, "admin"), "nb_ops": f.create_user("nb_ops", nb, "operator"),
           "nb_view": f.create_user("nb_view", nb, "viewer"), "nb_sjc2_ops": f.create_user("nb_sjc2_ops", nb, "operator", sjc2),
           "cv_admin": f.create_user("cv_admin", cv, "admin"), "cv_ops": f.create_user("cv_ops", cv, "operator")}
    agents = {}
    for site, n, admin in ((sjc1, 10, "nb_admin"), (sjc2, 6, "nb_admin"), (pdx1, 8, "cv_admin")):
        for i in range(n):
            rid, secret = f.register_robot(tok[admin], site, f"LR-{site}-{i:02d}")
            agents[rid] = RobotAgent(rid, secret, clock)
    rob = {r["id"]: dict(r) for r in f.db.execute("select * from robots")}
    nb_robots = [r for r in rob if rob[r]["tenant"] == nb]
    sjc1_robots = [r for r in nb_robots if rob[r]["site"] == sjc1]
    cv_robots = [r for r in rob if rob[r]["tenant"] == cv]
    owner = {r: ("nb_ops" if rob[r]["tenant"] == nb else "cv_ops") for r in rob}

    stats = {"commands": 0, "post_retries": 0, "poll_drops": 0, "dup_deliveries": 0, "late_deliveries": 0, "ack_lost": 0,
             "legit_denied": 0}
    attacks = []
    pending_late = []   # (deliver_at, agent, cmds)
    pending_ack = []    # acks lost once, retried on the next poll
    offline = {}        # robot → back online at
    rollouts = []
    planted_stale = None

    def attack(name, expect, fn):
        try:
            fn()
            attacks.append({"attack": name, "expected": expect.__name__, "got": "ALLOWED", "blocked": False})
        except (Unauthorized, Forbidden, NotFound, Conflict) as e:
            attacks.append({"attack": name, "expected": expect.__name__, "got": type(e).__name__, "detail": str(e), "blocked": isinstance(e, expect)})

    for day in range(5):
        for hour in range(10):
            # --- planted attacks and events, at fixed points
            if (day, hour) == (0, 2):
                attack("other customer's operator commands a Northbeam robot", NotFound,
                       lambda: f.send_command(tok["cv_ops"], nb_robots[0], "swap_drive", {"rack": 3}, "atk-1"))
                attack("viewer tries to send a command", Forbidden,
                       lambda: f.send_command(tok["nb_view"], nb_robots[1], "swap_drive", {"rack": 4}, "atk-2"))
                attack("SJC-2 operator commands an SJC-1 robot", NotFound,
                       lambda: f.send_command(tok["nb_sjc2_ops"], sjc1_robots[0], "reseat_cable", {"port": 7}, "atk-3"))
                f.send_command(tok["nb_ops"], nb_robots[2], "swap_drive", {"rack": 9, "slot": 2}, "idem-x")
                attack("same idempotency key, different command", Conflict,
                       lambda: f.send_command(tok["nb_ops"], nb_robots[2], "swap_drive", {"rack": 9, "slot": 5}, "idem-x"))
                stats["commands"] += 1
            if (day, hour) == (0, 4):
                victim = agents[cv_robots[0]]
                _, h = robot_req(f, victim, "POST", "/robot/heartbeat", {"battery": 0.82})
                clock.t += 10
                attack("captured heartbeat replayed 10 s later", Unauthorized,
                       lambda: robot_req(f, victim, "POST", "/robot/heartbeat", {"battery": 0.82}, hdr=h))
                clock.t += 300
                attack("captured heartbeat replayed 5 min later", Unauthorized,
                       lambda: robot_req(f, victim, "POST", "/robot/heartbeat", {"battery": 0.82}, hdr=h))
                fake = RobotAgent(cv_robots[1], secrets.token_hex(32), clock)
                attack("request signed with a guessed key", Unauthorized, lambda: robot_req(f, fake, "GET", "/robot/commands"))
            if (day, hour) == (1, 0):
                gone = nb_robots[-1]
                f.revoke_robot(tok["nb_admin"], gone)
                attack("revoked robot keeps polling", Unauthorized, lambda: robot_req(f, agents[gone], "GET", "/robot/commands"))
            if (day, hour) == (1, 5):
                rollouts.append(("v1.5", f.start_rollout(tok["nb_admin"], "v1.5")))
            if (day, hour) == (3, 0):
                rollouts.append(("v1.5.1", f.start_rollout(tok["nb_admin"], "v1.5.1")))
            if (day, hour) == (2, 3):
                offline[nb_robots[3]] = clock.t + 1800
            if (day, hour) == (2, 6):   # a power-cycle command whose delivery sits in a network buffer for 10 min
                ag = agents[nb_robots[4]]
                c = f.send_command(tok["nb_ops"], nb_robots[4], "power_cycle", {"rack": 12}, "planted-stale", ttl=300)
                me, _ = robot_req(f, ag, "GET", "/robot/commands")
                pending_late.append((clock.t + 600, ag, [x for x in f.poll(me) if x["id"] == c["id"]]))
                planted_stale = c["id"]

            for step in range(12):           # 5-minute ticks
                clock.t += 300
                # operators send commands
                for rid in rob:
                    if rob[rid]["id"] == nb_robots[-1] and day >= 1:
                        continue
                    if rng.random() < 0.06:
                        key = secrets.token_hex(6)
                        args = {"rack": rng.randint(1, 40), "slot": rng.randint(1, 24)}
                        action = rng.choice(["swap_drive", "reseat_cable", "inspect"])
                        try:
                            f.send_command(tok[owner[rid]], rid, action, args, key, ttl=900)
                            stats["commands"] += 1
                            if rng.random() < 0.1:   # client timeout → retry the same POST
                                f.send_command(tok[owner[rid]], rid, action, args, key, ttl=900)
                                stats["post_retries"] += 1
                        except (Unauthorized, Forbidden, NotFound, Conflict):
                            stats["legit_denied"] += 1
                # robots poll, execute, ack, report tasks
                for rid, ag in agents.items():
                    if rid == nb_robots[-1] and day >= 1:
                        continue  # revoked
                    if offline.get(rid, 0) > clock.t:
                        continue
                    if rng.random() < 0.15:
                        stats["poll_drops"] += 1
                        continue
                    me, _ = robot_req(f, ag, "GET", "/robot/commands")
                    cmds = f.poll(me)
                    if cmds and rng.random() < 0.03:
                        pending_late.append((clock.t + rng.uniform(150, 400), ag, cmds))   # stuck in a network buffer
                        stats["late_deliveries"] += 1
                        continue
                    batches = [cmds] + ([cmds] if cmds and rng.random() < 0.05 else [])
                    stats["dup_deliveries"] += len(batches) - 1
                    for b in batches:
                        for cid, ok, res in ag.handle(b):
                            if rng.random() < 0.1:
                                pending_ack.append((ag, cid, ok, res))
                                stats["ack_lost"] += 1
                                continue
                            me, _ = robot_req(f, ag, "POST", f"/robot/commands/{cid}/ack", {"ok": ok})
                            f.ack(me, cid, ok, res)
                    for ag2, cid, ok, res in [p for p in pending_ack if p[0] is ag]:
                        me, _ = robot_req(f, ag2, "POST", f"/robot/commands/{cid}/ack", {"ok": ok})
                        f.ack(me, cid, ok, res)
                    pending_ack = [p for p in pending_ack if p[0] is not ag]
                    if step % 2 == 0:
                        me, _ = robot_req(f, ag, "POST", "/robot/tasks", {})
                        f.report_task(me, task(rng, me["firmware"], rid, clock.t))
                        me, _ = robot_req(f, ag, "POST", "/robot/tasks", {})
                        f.report_task(me, task(rng, me["firmware"], rid, clock.t))
                for item in [p for p in pending_late if p[0] <= clock.t]:
                    _, ag, cmds = item
                    for cid, ok, res in ag.handle(cmds):
                        try:
                            me, _ = robot_req(f, ag, "POST", f"/robot/commands/{cid}/ack", {"ok": ok})
                        except Unauthorized:
                            continue   # robot was revoked while the delivery sat in the buffer
                        f.ack(me, cid, ok, res)
                pending_late = [p for p in pending_late if p[0] > clock.t]
                f.sweep()
            for _, rid_ in rollouts:
                f.rollout_gate(rid_)

    # invariants
    executions = {}
    for ag in agents.values():
        for cid, t in ag.executed.items():
            executions.setdefault(cid, []).append(t)
    cmds = {r["id"]: dict(r) for r in f.db.execute("select * from commands")}
    twice = [c for c, ts in executions.items() if len(ts) > 1]
    after_expiry = [c for c, ts in executions.items() if any(t >= cmds[c]["expires"] for t in ts)]
    status = {}
    for c in cmds.values():
        status[c["status"]] = status.get(c["status"], 0) + 1
    ro = [dict(r) for r in f.db.execute("select * from rollouts")]
    return {"fleet": f, "attacks": attacks, "stats": stats, "executed_twice": twice, "after_expiry": after_expiry, "status": status,
            "rollouts": ro, "dup_ignored": sum(a.dup_ignored for a in agents.values()),
            "stale_rejected": sum(a.stale_rejected for a in agents.values()), "metrics": f.metrics(), "retrain": f.retrain_queue(6),
            "tenants": {"Northbeam DC": len(nb_robots), "Corvid AI Cloud": len(cv_robots)},
            "planted_stale": {"id": planted_stale, "executed": planted_stale in executions, "status": cmds[planted_stale]["status"],
                              "result": cmds[planted_stale]["result"]},
            "offline_expired": sum(1 for c in cmds.values() if c["robot"] == nb_robots[3] and c["status"] == "EXPIRED")}
