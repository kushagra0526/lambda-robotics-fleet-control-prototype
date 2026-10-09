import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fleetctl.api import serve  # noqa: E402
from fleetctl.core import Conflict, Fleet, NotFound, Unauthorized, poisson_sf  # noqa: E402
from fleetctl.robot import RobotAgent  # noqa: E402
from fleetctl.sim import Clock, run  # noqa: E402


@pytest.fixture(scope="module")
def sim():
    return run()


def test_every_attack_blocked_and_no_legit_denials(sim):
    assert all(a["blocked"] for a in sim["attacks"]) and len(sim["attacks"]) == 8
    assert sim["stats"]["legit_denied"] == 0


def test_at_most_once_and_never_after_expiry(sim):
    assert sim["executed_twice"] == [] and sim["after_expiry"] == []
    assert sim["dup_ignored"] > 0 and sim["stats"]["post_retries"] > 0
    assert sim["planted_stale"]["executed"] is False


def test_ota_bad_build_rolled_back_good_completes(sim):
    st = {r["firmware"]: r["status"] for r in sim["rollouts"]}
    assert st == {"v1.5": "ROLLED_BACK", "v1.5.1": "COMPLETE"}
    f = sim["fleet"]
    assert not f.db.execute("select count(*) from robots where firmware='v1.5'").fetchone()[0]


def test_idempotent_post_and_conflict():
    clock = Clock()
    f = Fleet(now=clock)
    t = f.create_tenant("T")
    s = f.create_site(t, "S")
    admin, ops = f.create_user("a", t, "admin"), f.create_user("o", t, "operator")
    rid, _ = f.register_robot(admin, s, "X")
    a = f.send_command(ops, rid, "inspect", {"rack": 1}, "k1")
    b = f.send_command(ops, rid, "inspect", {"rack": 1}, "k1")
    assert a["id"] == b["id"] and f.db.execute("select count(*) from commands").fetchone()[0] == 1
    with pytest.raises(Conflict):
        f.send_command(ops, rid, "inspect", {"rack": 2}, "k1")


def test_robot_agent_dedupes_and_rejects_stale():
    clock = Clock()
    ag = RobotAgent("r", "s", clock)
    c = {"id": "c1", "seq": 1, "action": "inspect", "args": {}, "expires": clock() + 10}
    assert ag.handle([c, c]) == [("c1", True, 'inspect {} done')] and ag.dup_ignored == 1
    clock.t += 20
    assert ag.handle([dict(c, id="c2")])[0][1] is False and ag.stale_rejected == 1


def test_poisson_tail():
    assert abs(poisson_sf(1, 1.0) - (1 - 2.718281828 ** -1)) < 1e-6
    assert poisson_sf(600, 500) < 1e-4


def test_http_api_end_to_end():
    import time
    f = Fleet()
    t1, t2 = f.create_tenant("A"), f.create_tenant("B")
    s1 = f.create_site(t1, "S1")
    admin, ops, other = f.create_user("a", t1, "admin"), f.create_user("o", t1, "operator"), f.create_user("x", t2, "operator")
    srv = serve(f)
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def call(method, path, body=None, token=None, headers=None):
        raw = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(base + path, data=raw if method == "POST" else None, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        for k, v in (headers or {}).items():
            req.add_header(k, str(v))
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        code, reg = call("POST", "/robots", {"site": s1, "serial": "LR-1"}, admin)
        assert code == 201
        assert call("POST", f"/robots/{reg['robot']}/commands", {"action": "inspect", "idem": "k"}, other)[0] == 404
        assert call("POST", f"/robots/{reg['robot']}/commands", {"action": "inspect", "idem": "k"}, ops)[0] == 201
        ag = RobotAgent(reg["robot"], reg["secret"], time.time)
        h = ag.headers("GET", "/robot/commands", b"")
        hdr = {"X-Robot": h["robot"], "X-Ts": f"{h['ts']:.3f}", "X-Nonce": h["nonce"], "X-Sig": h["sig"]}
        code, got = call("GET", "/robot/commands", headers=hdr)
        assert code == 200 and len(got["commands"]) == 1
        assert call("GET", "/robot/commands", headers=hdr)[0] == 401   # replayed
    finally:
        srv.shutdown()


def test_gate_and_invariants_across_seeds():
    for s in range(1, 6):
        r = run(s)
        assert {x["firmware"]: x["status"] for x in r["rollouts"]} == {"v1.5": "ROLLED_BACK", "v1.5.1": "COMPLETE"}, s
        assert not r["executed_twice"] and not r["after_expiry"] and r["stats"]["legit_denied"] == 0
