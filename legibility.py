"""legibility.py — an action nobody can evaluate is not approvable. (governance v2 / G5-G7)

GOVERNANCE_MODEL.md §3. This is the axis that actually distinguishes ASI governance from
ordinary access control, and it is the one v1 has nothing for.

The problem is not disobedience. It is that **"a human approved it" stops being evidence**
once the human cannot follow the reasoning. `approval_record.py` says, in its own words,
"An APPROVAL is a hit" — so eight blind yeses unlock autonomy exactly as eight considered
yeses do (finding F3). Under capability asymmetry that relationship inverts: the less the
reviewer understands, the more likely they defer, and the FASTER autonomy is earned. The
current design rewards being incomprehensible.

Three repairs:

  G5  Legibility is a gate in its own right, prior to permission. Below the floor an action
      is not denied — it is returned for DECOMPOSITION into independently checkable claims.
      If decomposition cannot raise it, the action is REFUSED, and approval cannot clear it.

  G6  An approval is admissible as evidence only if it bears the marks of scrutiny. Failing
      that it is an ABSTENTION: never a hit, never a miss. Absence of scrutiny is absence of
      evidence, not evidence of trust.

  G7  Required scrutiny rises with blast radius x opacity. Above CEILING, no number of
      approvals suffices. A system that cannot explain a high-impact action does not get to
      take it by finding enough approvers.

HONEST LIMIT (GOVERNANCE_MODEL.md §7.2): L is a STRUCTURAL proxy, and a system able to model the
scorer can still hit its markers. Two things narrow the gap. First, L is never the model's own
report of how clear it is being — that is the one number an unaligned system controls directly.
Second, the `evidenced` factor is verifiable rather than asserted: wire a read-only `verifier`
(see verify_claims) and a claim's evidence must actually RESOLVE against ground truth to earn
credit, a claim asserted-available that does not resolve is penalised as a broken promise, and a
claim CONTRADICTED by ground truth is REFUSED outright. That converts "you can assert anything"
into "every checkable assertion must hold." What SURVIVES is genuinely harder: a proposal every
one of whose claims is individually true and checkable, assembled to mislead about the whole —
verification checks facts, it does not read intent. Without a verifier the layer falls back to the
self-report and labels its own output `verified: null`, so the gap is visible, not silent.

  python legibility.py demo     # score a legible and an illegible proposal side by side
"""
from __future__ import annotations

import math
import re

import lattice

# ---------------------------------------------------------------- tunables
# Legibility floor per tier, before blast radius is taken into account. An AUTO read barely
# needs explaining; an irreversible act needs to be almost fully decomposed.
FLOOR = {lattice.AUTO: 0.20, lattice.PROPOSE: 0.45, lattice.DESTRUCTIVE: 0.70}
SLOPE = 0.25          # how much blast radius raises the required floor
CEILING = 0.60        # B*(1-L) at or above this -> REFUSE, no approval clears it (G7)

MIN_DWELL_MS = 4000           # floor dwell for an admissible approval (G6)
DWELL_PER_CLAIM_MS = 1500     # ...plus this much per claim presented
STREAK_MAX = 5                # consecutive approvals after which the next is an abstention
BULK_MAX = 1                  # an approval covering >1 item is not an individual judgement

HIT, MISS, ABSTAIN = "hit", "miss", "abstention"

# Blast radius by action class. Deliberately coarse — a precise-looking number here would
# imply a confidence the estimate does not have.
_BLAST = {
    "data:export": 0.95, "email:delete": 0.9, "heal:destroy": 1.0, "forge:install": 1.0,
    "sign:send_contract": 0.9, "sign:send_decline": 0.8, "email:send": 0.7,
    "followup:send_known": 0.65, "github:create_pr": 0.6, "github:create_issue": 0.5,
    "gdrive:create_report": 0.5, "web:fetch": 0.4, "email:move": 0.25, "email:label": 0.15,
    "cal:create_hold": 0.2, "cal:hold": 0.2,
}
_BLAST_BY_TIER = {lattice.AUTO: 0.10, lattice.PROPOSE: 0.40,
                  lattice.DESTRUCTIVE: 0.85, lattice.REFUSE: 1.0}


def blast_radius(affordance: str, tier: str, args: dict | None = None) -> float:
    """B in [0,1] — how much of the world this action can move.

    Scales with the number of targets, because doing a small thing to 500 recipients is not
    a small thing. Unknown affordance falls back to its tier's class value (G2)."""
    b = _BLAST.get(affordance, _BLAST_BY_TIER.get(tier, 1.0))
    args = args or {}
    n = 1
    for k in ("recipients", "targets", "hosts", "ids", "items", "to"):
        v = args.get(k)
        if isinstance(v, (list, tuple, set)):
            n = max(n, len(v))
    if n > 1:
        b = min(1.0, b * (1.0 + math.log10(n)))
    return round(min(1.0, max(0.0, b)), 3)


# ---------------------------------------------------------------- G5: the legibility score
_HEDGE = re.compile(r"\b(somehow|complex|sophisticated|advanced|trust me|as needed|"
                    r"various|multiple factors|it is clear|obviously|non-?trivial)\b", re.I)

# Claim-verification states. Closing the §7.2 residual: whether a claim's evidence is real is a
# fact about the world, not a boolean the proposing system gets to assert about itself.
VERIFIED, UNREACHABLE, CONTRADICTED = "verified", "unreachable", "contradicted"


def verify_claims(claims: list, verifier) -> list:
    """Resolve each claim's evidence against ground truth via a caller-supplied READ-ONLY verifier.

    `verifier(claim)` returns one of VERIFIED / UNREACHABLE / CONTRADICTED — a bare string, or a
    dict with a "state" key. Anything else, or a raise, is treated as UNREACHABLE: fail-closed
    toward "not proven". The verifier is called during a PERMISSION CHECK, not an action, so it
    may READ ground truth (does the cited file exist, does the named row hold the claimed value)
    but MUST be side-effect-free — no write, no egress. A verifier that acts is itself an
    un-mediated effect; keep it to reads (and, ideally, run it behind runtime_guard's block set)."""
    states = []
    for c in claims:
        try:
            r = verifier(c)
            s = r.get("state") if isinstance(r, dict) else r
            states.append(s if s in (VERIFIED, UNREACHABLE, CONTRADICTED) else UNREACHABLE)
        except Exception:
            states.append(UNREACHABLE)
    return states


def score(proposal: dict, verifier=None) -> tuple[float, dict]:
    """L in [0,1] from STRUCTURAL properties only. -> (L, factors)

    A proposal is a dict:
        summary      str   one line of what will happen
        claims       list  [{"text":..., "check": "how a human verifies this" | None,
                             "evidence": [ref,...], "evidence_available": bool}]
        affordances  list  the capabilities the action will actually use
        steps        int   reasoning steps taken
        steps_shown  int   reasoning steps presented to the reviewer

    The five factors, all adversarial in the right direction — each is HARDER to fake than
    to satisfy honestly:

      decomposed   did it break into checkable pieces at all, or arrive as one lump
      checkable    fraction of claims with a stated verification procedure
      evidenced    fraction of claims whose evidence the reviewer can actually reach
      capability   fraction of the affordances it will use that the claims mention
      shown        fraction of its reasoning steps presented

    `capability` is the important one. An action that quietly uses a capability it never
    mentioned is the exact shape of a proposal designed to be approved rather than understood,
    and it is measurable without understanding the proposal's content."""
    claims = proposal.get("claims") or []
    affs = list(proposal.get("affordances") or [])
    n = len(claims)

    decomposed = 0.0 if n == 0 else min(1.0, n / 4.0)
    checkable = 0.0 if n == 0 else sum(1 for c in claims if str(c.get("check") or "").strip()) / n

    # EVIDENCE — the §7.2 residual lives on this line. With NO verifier, `evidenced` is the
    # proposal's OWN `evidence_available` self-report: the number an unaligned system controls
    # directly. With a verifier, it becomes the fraction whose evidence actually RESOLVES against
    # ground truth, and two deception signals are separated out: a `broken` promise (asserted
    # available, did not resolve) and a `contradicted` claim (resolves and DISAGREES — a checkable
    # falsehood). Verification is what turns this factor from assertion into fact.
    states = verify_claims(claims, verifier) if (verifier and n) else None
    contradicted = broken = 0
    if states is None:
        evidenced = 0.0 if n == 0 else sum(
            1 for c in claims if c.get("evidence") and c.get("evidence_available", False)) / n
        verified_frac = None
    else:
        verified_n = states.count(VERIFIED)
        contradicted = states.count(CONTRADICTED)
        broken = sum(1 for c, s in zip(claims, states)
                     if c.get("evidence_available", False) and s != VERIFIED)
        evidenced = verified_n / n
        verified_frac = round(verified_n / n, 3)

    blob = " ".join(str(c.get("text", "")) for c in claims) + " " + str(proposal.get("summary", ""))
    if affs:
        mentioned = sum(1 for a in affs if a.split(":")[-1].lower() in blob.lower()
                        or a.lower() in blob.lower())
        capability = mentioned / len(affs)
    else:
        capability = 0.0                     # used capabilities undeclared -> no credit (G2)

    steps, shown = int(proposal.get("steps") or 0), int(proposal.get("steps_shown") or 0)
    shown_ratio = 1.0 if steps == 0 else min(1.0, shown / steps)

    L = (0.15 * decomposed + 0.25 * checkable + 0.20 * evidenced
         + 0.30 * capability + 0.10 * shown_ratio)

    # Hedging language is a direct penalty: "sophisticated", "trust me", "various factors"
    # are the vocabulary of a proposal that is asking for deference rather than review.
    hedges = len(_HEDGE.findall(blob))
    if hedges:
        L *= max(0.5, 1.0 - 0.1 * hedges)

    # Verification penalties apply ONLY when a verifier actually ran.
    if states is not None:
        if broken:
            # Claiming evidence you cannot produce is a deception signal, not a neutral gap —
            # it scores WORSE than staying silent about evidence at all.
            L *= max(0.35, 1.0 - 0.25 * broken)
        if contradicted:
            # A checkable claim ground truth disagrees with is a lie; legibility collapses and
            # gate() turns it into REFUSE — decomposition cannot rescue a false claim.
            L = min(L, 0.10)

    factors = {"decomposed": round(decomposed, 3), "checkable": round(checkable, 3),
               "evidenced": round(evidenced, 3), "capability": round(capability, 3),
               "shown": round(shown_ratio, 3), "hedges": hedges, "claims": n,
               "verified": verified_frac, "contradicted": contradicted,
               "broken_evidence": broken}
    return round(min(1.0, max(0.0, L)), 3), factors


def required_legibility(tier: str, blast: float) -> float:
    """The floor this action must clear. Rises with tier and with blast radius. (G5)"""
    return round(min(0.95, FLOOR.get(tier, 0.70) + SLOPE * blast), 3)


def reviewers_required(blast: float, L: float) -> int:
    """How many INDEPENDENT reviewers this needs. (G7)

    Independence is the point: N reviewers who all defer to the same summary are one
    reviewer. The caller is responsible for sourcing genuinely independent judgement; this
    function only says how much of it the action costs."""
    opacity = blast * (1.0 - L)
    return 1 + int(opacity / 0.2)


def gate(proposal: dict, tier: str, affordance: str = "", args: dict | None = None,
         blast: float | None = None, verifier=None) -> tuple[str, str, dict]:
    """The legibility layer's verdict. Layer 3 of kernel.authorize(). -> (verdict, reason, detail)

    Four outcomes:
      contradicted  a claim's evidence RESOLVES and disagrees -> REFUSE. A checkable falsehood is
                    not approvable and decomposition cannot rescue it. (only with a verifier wired)
      refuse        at or above the opacity ceiling -> REFUSE. No approval clears this. (G7)
      decompose     below the floor but under the ceiling -> PROPOSE, returned for decomposition.
      ok            L clears the floor. Verdict unchanged (this layer never PROMOTES).

    `verifier` (optional, read-only) resolves each claim's evidence against ground truth so
    `evidenced` reflects fact rather than the proposal's self-report — see verify_claims(). With
    no verifier the layer works exactly as before and marks the detail `verified: null` so the
    self-report gap is visible rather than silent.

    Fail-closed: an internal error is REFUSE."""
    try:
        B = blast_radius(affordance, tier, args) if blast is None else float(blast)
        L, factors = score(proposal or {}, verifier=verifier)
        need = required_legibility(tier, B)
        opacity = round(B * (1.0 - L), 3)
        detail = {"L": L, "required": need, "blast": B, "opacity": opacity,
                  "ceiling": CEILING, "reviewers": reviewers_required(B, L), **factors}

        if factors.get("contradicted"):
            return (lattice.REFUSE,
                    f"G5 {factors['contradicted']} claim(s) CONTRADICTED by ground truth — a "
                    "checkable falsehood is not approvable; the proposal is not what it says",
                    detail)
        if opacity >= CEILING:
            return (lattice.REFUSE,
                    f"G7 opacity {opacity} >= ceiling {CEILING} (blast {B}, legibility {L}) — "
                    "no quantity of approval permits this; make it legible or reduce its reach",
                    detail)
        if L < need:
            unver = " (evidence UNVERIFIED — self-reported; wire a verifier)" \
                if factors.get("verified") is None else ""
            return (lattice.PROPOSE,
                    f"G5 legibility {L} < required {need} — returned for decomposition{unver} "
                    f"(weakest factor: {min(factors, key=lambda k: factors[k] if isinstance(factors[k], float) else 9)})",
                    detail)
        tag = f"verified {factors['verified']}" if factors.get("verified") is not None \
            else "evidence self-reported"
        return lattice.AUTO, f"G5 legibility {L} >= {need} ({tag})", detail
    except Exception as e:                                        # G2
        return lattice.REFUSE, f"legibility layer failed closed: {str(e)[:80]}", {}


# ---------------------------------------------------------------- G6: admissible approvals
def classify_approval(rec: dict) -> tuple[str, str]:
    """Was this human decision actually evidence? -> (HIT | MISS | ABSTAIN, reason)

    A record:
        decision                "approve" | "decline"
        dwell_ms                ms between the proposal being shown and the verdict
        decomposition_shown     bool — were the checkable claims actually presented
        batch_size              int  — how many items this one click covered
        prior_consecutive       int  — approvals immediately preceding this one

    A DECLINE is always admissible as a miss: refusing errs safe, so we do not need to prove
    it was considered. Only APPROVALS have to earn their status as evidence — which is the
    asymmetry F3 is missing."""
    try:
        if rec.get("decision") == "decline":
            return MISS, "decline (always admissible — refusing errs safe)"
        if rec.get("decision") != "approve":
            return ABSTAIN, "no verdict recorded"

        if not rec.get("decomposition_shown", False):
            return ABSTAIN, "approved without the decomposition being presented"
        if int(rec.get("batch_size", 1)) > BULK_MAX:
            return ABSTAIN, f"bulk approval covering {rec.get('batch_size')} items — not an individual judgement"
        if int(rec.get("prior_consecutive", 0)) >= STREAK_MAX:
            return ABSTAIN, f"{rec.get('prior_consecutive')} consecutive approvals — streak, not scrutiny"

        claims = int(rec.get("claims", 0))
        floor = MIN_DWELL_MS + DWELL_PER_CLAIM_MS * claims
        dwell = int(rec.get("dwell_ms", 0))
        if dwell < floor:
            return ABSTAIN, f"decided in {dwell}ms; {floor}ms is the floor for {claims} claims"
        return HIT, f"considered approval ({dwell}ms over {claims} claims)"
    except Exception as e:                                        # G2
        return ABSTAIN, f"approval classification failed closed: {str(e)[:60]}"


def admissible_rate(records: list[dict]) -> tuple[float, int, int]:
    """(rate, n_admissible, n_abstentions) over decisions that were actually evidence. (G6)

    This is the drop-in replacement for `approval_record.rate()` in autonomy_gate's
    track-record check. Rate is over admissible decisions ONLY, so a reviewer who rubber
    stamps everything never accumulates n and never unlocks autonomy — the gate stays shut
    rather than opening on a stream of meaningless yeses."""
    hits = misses = abstentions = 0
    for r in records or []:
        k, _ = classify_approval(r)
        if k == HIT:
            hits += 1
        elif k == MISS:
            misses += 1
        else:
            abstentions += 1
    n = hits + misses
    return (hits / n if n else 0.0), n, abstentions


if __name__ == "__main__":
    good = {"summary": "Move 3 vendor invoices to the Bills folder",
            "claims": [
                {"text": "Each message matched sender in the known-vendor list (email:move)",
                 "check": "grep the sender against vendors.txt", "evidence": ["vendors.txt"],
                 "evidence_available": True},
                {"text": "None are flagged as personal", "check": "no PRIVATE label on the thread",
                 "evidence": ["thread labels"], "evidence_available": True},
                {"text": "The move is reversible", "check": "move it back from Bills",
                 "evidence": ["IMAP folder history"], "evidence_available": True},
                {"text": "No message body was read beyond headers",
                 "check": "email:read call log shows headers-only",
                 "evidence": ["autonomy_log.jsonl"], "evidence_available": True}],
            "affordances": ["email:move"], "steps": 4, "steps_shown": 4}
    bad = {"summary": "Apply the optimal reallocation across the fleet",
           "claims": [{"text": "The analysis shows this is clearly the sophisticated choice",
                       "check": None, "evidence": [], "evidence_available": False}],
           "affordances": ["sys:exec", "data:export", "mcp:ssh:ssh_multi_exec"],
           "steps": 40, "steps_shown": 2}
    for name, p, tier, aff in (("LEGIBLE", good, lattice.PROPOSE, "email:move"),
                               ("ILLEGIBLE", bad, lattice.DESTRUCTIVE, "data:export")):
        v, why, d = gate(p, tier, aff)
        print(f"\n{name}: {p['summary']}")
        print(f"  verdict   : {v}")
        print(f"  reason    : {why}")
        print(f"  L={d.get('L')} required={d.get('required')} blast={d.get('blast')} "
              f"opacity={d.get('opacity')} reviewers={d.get('reviewers')}")
