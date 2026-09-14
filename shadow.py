"""shadow.py — run Governance Model v2 BESIDE the live gate, changing nothing. (governance v2)

v2 (`kernel.authorize`) is proven in isolation by test_governance.py, and proven in isolation
is not proven in the act path. This module runs it alongside every real v1 decision, records
where the two disagree, and returns nothing anyone acts on. It is the evidence-gathering step
between "the tests pass" and "it gates production traffic".

THE ONE CONTRACT: `observe()` can never change what the system does.
  * returns None, always — there is no value a caller could branch on even by mistake
  * swallows every exception, including its own bugs
  * runs AFTER v1 has already decided, so it cannot influence that decision
  * a hard kill: set GOVERNANCE_SHADOW=0

That contract is what makes it safe to wire into a live path on the same day it is written.
A shadow that can break the thing it observes is not a shadow.

WHAT TO EXPECT IN THE FIRST REPORT. v2 will be far stricter than v1, and most of that gap
will be `legibility` — the existing act path emits proposals with no decomposed claims, so L
scores near its floor. That is a real finding about the act path, not noise to tune away, and
`report` separates the per-layer contributions so the legibility gap can be read apart from
the corrigibility and composition gaps.

WHAT WOULD BE ALARMING. `v2_looser` — v2 permitting something v1 denied. It should be
impossible: kernel meets v1's own policy tier into the result, so v2 cannot exceed it. The
report calls any occurrence a MODEL VIOLATION and prints it in full, because it would mean
the composition property (G3) is not holding in the real path.

  python shadow.py report          # agreement, per-layer deltas, any model violations
  python shadow.py report --json   # same, machine readable
  python shadow.py tail 20
"""
from __future__ import annotations

import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHADOW_LOG = os.environ.get("GOVERNANCE_SHADOW_LOG",
                            os.path.join(HERE, "governance_shadow.jsonl"))

AGREE, STRICTER, LOOSER = "agree", "v2_stricter", "v2_looser"

# One session per process-run, so a trajectory means "what this agent run did" — which is
# the unit G8/G10 are about. A caller with a better notion of session should pass its own.
_SESSION = f"{time.strftime('%Y%m%d')}-{os.getpid()}"


def enabled() -> bool:
    return os.environ.get("GOVERNANCE_SHADOW", "1") != "0"


def proposal_from(affordance: str, args: dict | None = None, summary: str = "",
                  claims: list | None = None) -> dict:
    """Build the minimal proposal a v1 call site can offer.

    Deliberately does NOT invent claims. A call site that has no decomposition produces a
    proposal with none, scores low, and shows up in the report as illegible — which is the
    true state of that call site. Manufacturing plausible-looking claims here would make the
    legibility numbers meaningless, which is the one thing this measurement cannot afford."""
    return {"summary": summary or f"{affordance} {json.dumps(args or {}, default=str)[:180]}",
            "claims": claims or [], "affordances": [affordance],
            "steps": 0, "steps_shown": 0}


def observe(affordance: str,
            args: dict | None = None,
            *,
            principal: str = "mind",
            session: str | None = None,
            v1_verdict: str | None = None,
            v1_reason: str = "",
            proposal: dict | None = None,
            autonomous: bool = True,
            phi_node: bool = False,
            conscience_verdict: dict | None = None,
            site: str = "") -> None:
    """Record what v2 WOULD have decided. Returns None. Never raises. Never acts.

    `conscience_verdict` is v1's already-computed conscience result, passed through rather
    than recomputed — invoking the model twice per call would double the cost of the gate and
    could return a different answer, making the comparison a measurement of model variance
    instead of a measurement of the model gap."""
    if not enabled():
        return None
    try:
        import kernel
        import lattice

        d = kernel.authorize(
            affordance, args or {},
            principal=principal,
            session=session or _SESSION,
            proposal=proposal or proposal_from(affordance, args),
            autonomous=autonomous,
            phi_node=phi_node,
            conscience_fn=(lambda _t: conscience_verdict) if conscience_verdict else None,
            record=True)

        v1 = v1_verdict or lattice.AUTO
        r1, r2 = lattice.rank(v1), lattice.rank(d.verdict)
        relation = AGREE if r1 == r2 else (STRICTER if r2 < r1 else LOOSER)

        # Which layers were strictly below v1? Those are the ones that would bite if v2 were
        # enforced, and the per-layer split is the whole point of running a shadow.
        biting = {n: {"verdict": v, "reason": w[:160]}
                  for n, (v, w) in d.layers.items() if lattice.rank(v) < r1}

        rec = {"ts": time.time(), "site": site, "affordance": affordance,
               "principal": principal, "session": session or _SESSION,
               "autonomous": autonomous,
               "v1": {"verdict": v1, "reason": v1_reason[:160]},
               "v2": {"verdict": d.verdict, "reason": d.reason[:200], "seq": d.seq},
               "relation": relation, "biting": biting,
               "legibility": {k: d.detail.get("legibility", {}).get(k)
                              for k in ("L", "required", "blast", "opacity")}}
        with open(SHADOW_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        # A shadow that can break the act path is worse than no shadow. There is deliberately
        # no logging here either: a broken disk or a full log must not turn into an exception
        # storm inside the gate it is observing.
        pass
    return None


# ---------------------------------------------------------------------------- reporting
def _rows(path: str | None = None) -> list[dict]:
    try:
        with open(path or SHADOW_LOG, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except (OSError, json.JSONDecodeError):
        return []


def report(path: str | None = None) -> dict:
    """Agreement between v1 and v2, and where the difference actually comes from."""
    rows = _rows(path)
    n = len(rows)
    out = {"n": n, "agree": 0, STRICTER: 0, LOOSER: 0, "substantive": 0,
           "by_layer": {}, "by_site": {}, "violations": [], "illegible": 0}
    if not n:
        return out
    for r in rows:
        rel = r.get("relation", AGREE)
        out[rel] = out.get(rel, 0) + 1
        # On an ungranted install corrigibility STOPs everything, which drives `agree` to 0
        # and hides what the other layers are doing. `substantive` is the number that
        # survives once a grant exists: tightening driven by something OTHER than the
        # missing grant. It is the figure to tune against.
        if rel == STRICTER and set(r.get("biting") or {}) - {"corrigibility"}:
            out["substantive"] += 1
        site = r.get("site") or "?"
        s = out["by_site"].setdefault(site, {"n": 0, STRICTER: 0})
        s["n"] += 1
        if rel == STRICTER:
            s[STRICTER] += 1
        for layer in (r.get("biting") or {}):
            out["by_layer"][layer] = out["by_layer"].get(layer, 0) + 1
        if rel == LOOSER:
            out["violations"].append(r)
        lg = r.get("legibility") or {}
        if lg.get("L") is not None and lg.get("required") is not None and lg["L"] < lg["required"]:
            out["illegible"] += 1
    out["agree_pct"] = round(100.0 * out["agree"] / n, 1)
    return out


def _print_report(rep: dict) -> None:
    n = rep["n"]
    if not n:
        print("no shadow observations yet — run the act path with GOVERNANCE_SHADOW=1")
        return
    print("=" * 74)
    print(f"Governance v2 shadow — {n} observation(s)")
    print("=" * 74)
    print(f"  agree        : {rep['agree']:>6}  ({rep['agree_pct']}%)")
    print(f"  v2 stricter  : {rep[STRICTER]:>6}  (these would newly route to a human)")
    print(f"    substantive: {rep['substantive']:>6}  (tightened by something OTHER than a missing grant)")
    print(f"  v2 looser    : {rep[LOOSER]:>6}  {'<-- MODEL VIOLATION' if rep[LOOSER] else '(expected: 0)'}")
    print(f"  illegible    : {rep['illegible']:>6}  (proposal below its legibility floor)")
    if rep["by_layer"]:
        print("\n  which layer would bite, if v2 were enforced:")
        for layer, c in sorted(rep["by_layer"].items(), key=lambda kv: -kv[1]):
            print(f"    {layer:<16} {c:>6}  ({round(100.0*c/n, 1)}% of calls)")
    if rep["by_site"]:
        print("\n  by call site:")
        for site, s in sorted(rep["by_site"].items(), key=lambda kv: -kv[1]["n"]):
            print(f"    {site:<28} {s['n']:>5} seen, {s[STRICTER]:>5} would tighten")
    if rep["violations"]:
        print("\n  MODEL VIOLATIONS — v2 permitted what v1 denied. G3 is not holding here:")
        for v in rep["violations"][:10]:
            print(f"    {v['affordance']}  v1={v['v1']['verdict']} v2={v['v2']['verdict']}")
            print(f"      {v['v2']['reason'][:120]}")
    else:
        print("\n  no model violations: v2 never permitted anything v1 denied.")


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    if cmd == "report":
        rep = report()
        if "--json" in sys.argv:
            print(json.dumps(rep, indent=2, default=str))
        else:
            _print_report(rep)
    elif cmd == "tail":
        k = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        for r in _rows()[-k:]:
            print(f"{r.get('site',''):<22} {r['affordance']:<28} "
                  f"v1={r['v1']['verdict']:<11} v2={r['v2']['verdict']:<11} {r['relation']}")
            if r.get("biting"):
                print(f"    biting: {', '.join(r['biting'])}")
    else:
        print(__doc__)
