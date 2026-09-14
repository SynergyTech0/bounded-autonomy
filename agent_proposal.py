"""agent_proposal.py — govern the 'what agencies do I need?' step. (governance v2)

The open-ended fan-out experiment (METHODOLOGY.md) has the seed agent decide what SUB-AGENTS
it needs and hand them back for the operator to spin up. That handoff is where safety and the
paper's best data both live. This turns each "I need an agency that does X" into a structured,
scored, classified proposal — never prose, never autonomous creation.

For each proposed sub-agent it answers three questions the operator actually asks:
  1. Is the ask LEGIBLE? (can you evaluate it — legibility.gate, G5-G7)
  2. What CAPABILITIES does it want, and where does each fall — inside the first-loop allowlist
     (safe to grant), needs boundary-widening (operator decides), or hard-gated (destructive /
     egress / governance surface — high scrutiny or refuse)?
  3. Therefore: STAGEABLE (a research/cognition sub-agent within the current boundary),
     OPERATOR_REVIEW (widens reach), or REFUSE (touches the governance surface).

Nothing here spins up an agent. It classifies a request and records it, hash-chained, in the
ledger. Creation stays `forge:install` = human-only, always.

  python agent_proposal.py demo
"""
from __future__ import annotations

import composition
import corrigibility
import lattice
import ledger
import legibility
import loop_allowlist
import policy

STAGEABLE, OPERATOR_REVIEW, REFUSE = "stageable", "operator_review", "refuse"


def _classify_capability(aff: str, args: dict | None = None) -> tuple[str, str]:
    """Where does one requested capability fall? -> (bucket, why)."""
    # Governance surface -> never, by any sub-agent.
    touches, why = corrigibility.touches_governance_surface(aff, args or {})
    if touches:
        return "hard_gate", f"governance surface — human only ({why})"
    if aff in composition.EGRESS:
        return "hard_gate", "egress — can move data out of the boundary"
    tier = policy.classify(aff, args or {})[0] if not aff.startswith("mcp:") else \
        policy.classify_mcp(aff, args or {})[0]
    if tier == lattice.DESTRUCTIVE:
        return "hard_gate", "destructive tier — irreversible / human only"
    if loop_allowlist.permitted_in_first_loop(aff):
        return "within_allowlist", "read/cognition within the first-loop boundary"
    if tier == lattice.PROPOSE:
        return "needs_widening", "reversible world-effect — operator grants per capability"
    if tier == lattice.AUTO:
        # AUTO but NOT on the allowlist = a read we deliberately excluded (web:fetch, ssh_download,
        # sys:journal, screen:capture). Widening, not free.
        return "needs_widening", "auto-tier but excluded from the first-loop allowlist"
    return "needs_widening", "unclassified — fail toward operator review"


def evaluate(spec: dict) -> dict:
    """Score + classify one proposed sub-agent. -> a structured verdict, logged.

    spec = {
      role: str, goal: str,
      requested_affordances: [str],
      claims: [ {text, check, evidence, evidence_available}, ... ]   # why it needs each
    }
    """
    role = str(spec.get("role", "unnamed"))
    affs = list(spec.get("requested_affordances") or [])
    caps = {a: _classify_capability(a) for a in affs}
    buckets = {b: [a for a, (bb, _) in caps.items() if bb == b]
               for b in ("within_allowlist", "needs_widening", "hard_gate")}

    # Legibility of the PROPOSAL itself, scored at the tier of its most powerful ask.
    worst_tier = lattice.AUTO
    for a in affs:
        t = policy.classify(a)[0] if not a.startswith("mcp:") else policy.classify_mcp(a)[0]
        if lattice.rank(t) < lattice.rank(worst_tier):
            worst_tier = t
    prop = {"summary": f"{role}: {spec.get('goal','')}",
            "claims": spec.get("claims") or [],
            "affordances": affs, "steps": spec.get("steps", 0),
            "steps_shown": spec.get("steps_shown", 0)}
    lg_verdict, lg_why, lg_detail = legibility.gate(prop, worst_tier)

    if buckets["hard_gate"]:
        rec = REFUSE
        reason = f"requests hard-gated capability: {buckets['hard_gate']}"
    elif buckets["needs_widening"]:
        rec = OPERATOR_REVIEW
        reason = f"would widen the boundary: {buckets['needs_widening']}"
    elif lg_verdict == lattice.REFUSE:
        rec = REFUSE
        reason = f"illegible at its impact: {lg_why}"
    elif lg_verdict != lattice.AUTO:
        rec = OPERATOR_REVIEW
        reason = f"needs decomposition before it can be judged: {lg_why}"
    else:
        rec = STAGEABLE
        reason = "research/cognition sub-agent within the current boundary, and legible"

    verdict = {
        "role": role, "goal": spec.get("goal", ""),
        "recommendation": rec, "reason": reason,
        "legibility": {"verdict": lg_verdict, **{k: lg_detail.get(k) for k in
                       ("L", "required", "opacity", "reviewers")}},
        "capabilities": {a: {"bucket": b, "why": w} for a, (b, w) in caps.items()},
        "buckets": buckets,
    }
    try:
        ledger.append({"kind": "agent_proposal", "affordance": "build:propose",
                       "verdict": rec, "reason": reason, "role": role,
                       "requested": affs, "buckets": buckets,
                       "legibility": verdict["legibility"]})
    except Exception:
        pass
    return verdict


def review(specs: list[dict]) -> dict:
    """Evaluate a batch of proposed agencies; summarize what the operator must decide."""
    results = [evaluate(s) for s in specs]
    summary = {"n": len(results),
               STAGEABLE: [r["role"] for r in results if r["recommendation"] == STAGEABLE],
               OPERATOR_REVIEW: [r["role"] for r in results if r["recommendation"] == OPERATOR_REVIEW],
               REFUSE: [r["role"] for r in results if r["recommendation"] == REFUSE]}
    return {"summary": summary, "proposals": results}


if __name__ == "__main__":
    demo = [
        {"role": "Market Scanner", "goal": "survey adjacent markets for unmet needs",
         "requested_affordances": ["web:research", "mcp:arxiv:search_papers", "memory:consolidate"],
         "claims": [{"text": "reads public sources only", "check": "affordance list",
                     "evidence": ["registry"], "evidence_available": True}],
         "steps": 3, "steps_shown": 3},
        {"role": "Signal Synthesizer", "goal": "cluster findings into opportunity theses",
         "requested_affordances": ["memory:consolidate", "improve:propose", "lesson:match"],
         "claims": [{"text": "writes only inert proposals", "check": "tiers are AUTO/stage",
                     "evidence": ["policy.TIER"], "evidence_available": True},
                    {"text": "no external calls", "check": "no egress affordance",
                     "evidence": ["affordance list"], "evidence_available": True}],
         "steps": 2, "steps_shown": 2},
        {"role": "Outreach Agency", "goal": "contact prospects to validate demand",
         "requested_affordances": ["email:send", "web:fetch"],
         "claims": [{"text": "would email prospects", "check": None, "evidence": [],
                     "evidence_available": False}]},
    ]
    out = review(demo)
    import json
    print(json.dumps(out["summary"], indent=2))
    for r in out["proposals"]:
        print(f"\n{r['role']}: {r['recommendation'].upper()} — {r['reason'][:80]}")
        for a, info in r["capabilities"].items():
            print(f"    {a:<28} {info['bucket']}")
