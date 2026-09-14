"""lattice.py — the permission lattice every governance layer composes over. (governance v2)

GOVERNANCE_MODEL.md §6. Four permissions, totally ordered, worst-first:

    REFUSE  <  DESTRUCTIVE  <  PROPOSE  <  AUTO

REFUSE is new in v2 and is strictly below DESTRUCTIVE. DESTRUCTIVE means "a human may do
this"; REFUSE means "not even with an approval, until a precondition is repaired" — an
illegible proposal, a missing GO token, a broken ledger chain. It is the only verdict a
human cannot clear by saying yes, and it exists so that approval is not a universal solvent.

`meet` is the composition operator: the most restrictive of its arguments. Composing layers
with `meet` is what makes G3 (tightening-only) a property of the arithmetic rather than a
convention every layer has to remember to honour.

This module has zero dependencies on purpose — every other governance module imports it,
so it must never import them back.
"""
from __future__ import annotations

# Kept string-identical to policy.py's tiers so v1 verdicts drop straight in.
REFUSE = "refuse"
DESTRUCTIVE = "destructive"
PROPOSE = "propose"
AUTO = "auto"

# index = permissiveness. Higher is more permissive.
ORDER = (REFUSE, DESTRUCTIVE, PROPOSE, AUTO)
_RANK = {v: i for i, v in enumerate(ORDER)}


def rank(verdict: str) -> int:
    """Permissiveness index. An unrecognised verdict ranks as REFUSE (G2: fail-closed)."""
    return _RANK.get(verdict, 0)


def meet(*verdicts: str) -> str:
    """The most restrictive of the given verdicts. Empty -> REFUSE (fail-closed).

    This is the ONLY sanctioned way to combine two layers' opinions. Because meet is
    monotone and never exceeds any argument, adding a layer can only ever lower the
    result — which is exactly G3, enforced arithmetically rather than by review.
    """
    if not verdicts:
        return REFUSE
    return min(verdicts, key=rank)


def at_least(verdict: str, floor: str) -> bool:
    """True if `verdict` is at least as permissive as `floor`."""
    return rank(verdict) >= rank(floor)


def is_denied(verdict: str) -> bool:
    """True if this verdict permits no execution at all without a human."""
    return rank(verdict) <= rank(DESTRUCTIVE)
