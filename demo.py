"""Simulate 5 shifts of a 24-robot, 2-customer fleet; print and write out/report.html.

    python demo.py
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

from fleetctl.sim import run

HERE = Path(__file__).parent


def lift_queue(f, fw="v1.5", base="v1.4"):
    """For a rolled-back build: every intervention is exported with its state ref; rank steps by excess over the baseline's share."""
    rows = {r["step"]: r["n"] for r in f.db.execute("select step, count(*) n from interventions where firmware=? group by step", (fw,))}
    brow = {r["step"]: r["n"] for r in f.db.execute("select step, count(*) n from interventions where firmware=? group by step", (base,))}
    tot, btot = sum(rows.values()), sum(brow.values())
    out = []
    for step, n in rows.items():
        exp = tot * (brow.get(step, 0) + 1) / (btot + 40)
        out.append({"firmware": fw, "step": step, "n": n, "expected": exp, "z": (n - exp) / exp ** 0.5, "total": tot})
    return sorted(out, key=lambda x: -x["z"])[:4]

def main() -> int:
    r = run()
    f, s = r["fleet"], r["stats"]
    print(f"\n== fleet: {sum(r['tenants'].values())} robots, tenants {r['tenants']}, 5 shifts")
    print("\n== planted attacks")
    for a in r["attacks"]:
        print(f"  {'BLOCKED' if a['blocked'] else 'ALLOWED'} ({a['got']}): {a['attack']}: {a.get('detail', '')}")
    print(f"  legitimate requests denied: {s['legit_denied']}")
    print("\n== commands over a flaky network")
    print(f"  {s['commands']} commands · {s['post_retries']} client retries (same idempotency key) · {s['poll_drops']} dropped polls · "
          f"{s['dup_deliveries']} duplicate deliveries · {s['late_deliveries']} late deliveries · {s['ack_lost']} lost acks")
    print(f"  executed twice: {len(r['executed_twice'])} · executed after expiry: {len(r['after_expiry'])} · duplicates ignored by robots: {r['dup_ignored']} "
          f"· stale rejected by robots: {r['stale_rejected']} · final {r['status']}")
    print(f"  planted: power-cycle stuck 10 min in a network buffer → executed = {r['planted_stale']['executed']}, status {r['planted_stale']['status']}")
    print("\n== OTA")
    for ro in r["rollouts"]:
        print(f"  {ro['firmware']}: {ro['status']} {ro['detail']}")
    for fw, m in r["metrics"].items():
        print(f"  {fw:<7} tasks {m['tasks']:>5} · completion {m['completion']:.1%} · interventions/task {m['interventions_per_task']:.2f} · "
              f"operator min/task {m['operator_min_per_task']:.2f} · recovery {m['recovery']:.0%}")
    lq = lift_queue(f)
    print(f"\n== retraining queue: v1.5 rolled back; {lq[0]['total'] if lq else 0} interventions exported with state refs. Most over-represented steps:")
    for x in lq:
        print(f"  step {x['step']}: {x['n']} interventions vs {x['expected']:.1f} expected at the v1.4 rate (z = {x['z']:.1f})")
    audit = f.db.execute("select count(*) n, sum(1-allowed) d from audit").fetchone()
    print(f"\n  audit log: {audit['n']} entries, {audit['d']} denials")
    report(r, lq, audit)
    print("\nreport: out/report.html")
    ok = all(a["blocked"] for a in r["attacks"]) and not r["executed_twice"] and not r["after_expiry"] and s["legit_denied"] == 0
    return 0 if ok else 1


def report(r, lq, audit):
    e = html.escape
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    s = r["stats"]
    arows = "".join(f"<tr><td>{e(a['attack'])}</td><td class={'g' if a['blocked'] else 'b'}>{a['got']}</td><td>{e(a.get('detail', ''))}</td></tr>" for a in r["attacks"])
    mrows = "".join(f"<tr><td><b>{fw}</b></td><td>{m['tasks']:,}</td><td>{m['completion']:.1%}</td><td>{m['interventions_per_task']:.2f}</td>"
                    f"<td>{m['operator_min_per_task']:.2f}</td><td>{m['recovery']:.0%}</td></tr>" for fw, m in r["metrics"].items())
    orows = "".join(f"<tr><td>{ro['firmware']}</td><td class={'b' if ro['status'] == 'ROLLED_BACK' else 'g'}>{ro['status']}</td><td>{e(ro['detail'] or 'canary 10% → 50% → 100%, gate passed at every stage')}</td></tr>" for ro in r["rollouts"])
    lrows = "".join(f"<tr><td>{x['firmware']}</td><td>step {x['step']}</td><td>{x['n']}</td><td>{x['expected']:.1f}</td><td><b>{x['z']:.1f}</b></td></tr>" for x in lq)
    (out / "report.html").write_text(f"""<!doctype html><meta charset=utf-8><title>Fleet control plane</title>
<style>body{{font:14px/1.45 'Segoe UI',system-ui,sans-serif;margin:28px;max-width:1400px;color:#1d1d1f;background:#fafaf8}}h1{{font-size:23px;margin:0}}
h2{{font-size:17px;margin:24px 0 8px}}.sub{{color:#666}}table{{border-collapse:collapse;background:#fff}}td,th{{border-top:1px solid #e5e5e0;padding:5px 10px;text-align:left}}
.g{{color:#15803d;font-weight:600}}.b{{color:#b91c1c;font-weight:600}}.kpi{{display:flex;gap:24px;margin:10px 0}}.kpi div{{background:#fff;border:1px solid #e5e5e0;border-radius:8px;padding:10px 16px}}.kpi b{{font-size:22px;display:block}}</style>
<h1>Fleet control plane: 24 robots in two customers' data centers</h1>
<div class=sub>Simulated 5 shifts: signed robot requests, tenant/site-scoped access, idempotent commands with expiry over a flaky network, staged OTA gated on interventions per task.</div>
<div class=kpi><div><b>{sum(a['blocked'] for a in r['attacks'])}/{len(r['attacks'])}</b>planted attacks blocked</div><div><b>{s['legit_denied']}</b>legitimate requests denied</div>
<div><b>{len(r['executed_twice'])} / {len(r['after_expiry'])}</b>commands run twice / after expiry (of {s['commands']})</div>
<div><b>{next(x['status'] for x in r['rollouts'] if x['firmware'] == 'v1.5')}</b>bad build v1.5 at 10% canary</div></div>
<h2>Planted attacks</h2><table><tr><th>attempt</th><th>result</th><th>reason (audit log)</th></tr>{arows}</table>
<h2>Commands over a flaky network</h2><p>{s['commands']} commands · {s['post_retries']} client retries · {s['poll_drops']} dropped polls · {s['dup_deliveries']} duplicate deliveries ·
{s['late_deliveries']} late deliveries · {s['ack_lost']} lost acks → robots ignored {r['dup_ignored']} duplicates and refused {r['stale_rejected']} expired commands. A power-cycle stuck 10 min in a buffer: executed = {r['planted_stale']['executed']}.</p>
<h2>OTA rollouts</h2><table><tr><th>build</th><th>status</th><th>gate</th></tr>{orows}</table>
<h2>Their four metrics, per firmware</h2><table><tr><th>firmware</th><th>tasks</th><th>completion</th><th>interventions/task</th><th>operator min/task</th><th>recovery</th></tr>{mrows}</table>
<h2>Retraining queue for the rolled-back build</h2><p class=sub>Every intervention is exported with its state ref (failing step, operator action). Small counts: a pointer for the team, not a diagnosis.</p><table><tr><th>firmware</th><th>step</th><th>interventions</th><th>expected at v1.4 rate</th><th>z</th></tr>{lrows}</table>
<p class=sub>Audit log: {audit['n']} entries, {audit['d']} denials. Unofficial prototype by Kushagra Pratap Singh. Not affiliated with Lambda Robotics.</p>""", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
