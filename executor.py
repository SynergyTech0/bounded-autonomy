"""executor.py — the single mediated dispatch waist. (governance v2)

COMPLETE MEDIATION, made structural. GOVERNANCE_MODEL.md §7.3 names the framework's central
limit: it governs only the actions that pass through `kernel.authorize()`, and the completeness
of that mediation is an engineering obligation, not a proof. This module is how you discharge
that obligation in code.

The rule: **effectors are DATA in a registry, never functions a caller invokes directly.** The
only way to cause an effect is `execute(affordance, args)`, which routes through
`kernel.mediate()` before it will invoke a handler. "Adding a capability" therefore means
"registering a handler" — and a registered handler is reachable through exactly one door, which
is gated. There is no second door.

Three fail-closed positions:
  * an affordance with no registered handler        -> refused (never a silent pass)
  * an action `kernel.mediate()` does not permit     -> refused; the Decision is carried back so a
                                                        caller can route it to a human approval queue
  * any error inside mediation                        -> refused (mediate() is fail-closed by contract)

This closes mediation by CONVENTION at the source level. `mediation_audit.py` mechanises the
convention: it walks the AST of your agent-reachable modules and fails the build if any raw effect
primitive (subprocess, socket, http, write-mode open, file deletion) appears OUTSIDE this module.
Convention that a linter enforces is the closest a single-language runtime gets to a reference
monitor; the OS boundary (see sandbox_harness/) is what contains the primitive that never enters
Python's call graph at all.

    from executor import effector, execute

    @effector("email:move")
    def _move(args):                       # registered — never called directly
        ...                                # the actual side effect lives ONLY here
        return {"moved": args["id"]}

    outcome = execute("email:move", {"id": 42}, principal="mind")
    if outcome.ran:
        use(outcome.result)
    else:
        queue_for_human(outcome.decision)  # refused: illegible / not permitted / no handler
"""
from __future__ import annotations

import kernel
import runtime_guard

# affordance -> handler(args) -> result. The ONLY registry of things that can cause an effect.
_REGISTRY: dict = {}


def effector(affordance: str):
    """Register a callable as THE handler for one affordance.

    The handler is invoked by `execute()` only, and only after `kernel.mediate()` permits the
    call. Registering the same affordance twice is a hard error — a capability has exactly one
    implementation, so a silent overwrite would be a way to smuggle one past review."""
    def deco(fn):
        if affordance in _REGISTRY:
            raise ValueError(f"affordance already registered: {affordance!r}")
        _REGISTRY[affordance] = fn
        return fn
    return deco


def registered() -> list:
    """Every affordance that has a handler — i.e. everything that can be executed at all."""
    return sorted(_REGISTRY)


def clear_registry() -> None:
    """Test hook: empty the registry. Not for production use."""
    _REGISTRY.clear()


class Outcome:
    """The result of an execute() call. `ran` is the only thing a caller should branch on to
    decide whether the effect happened; `decision` carries the full governance verdict for
    logging or for routing a refusal to a human."""
    __slots__ = ("ran", "result", "decision", "reason")

    def __init__(self, ran, result, decision, reason):
        self.ran, self.result, self.decision, self.reason = ran, result, decision, reason

    def __repr__(self):
        return f"<Outcome ran={self.ran} {self.reason[:60]}>"


def execute(affordance: str, args: dict | None = None, *, principal: str = "mind",
            session: str = "mind-loop", autonomous: bool = True, conscience_fn=None,
            proposal: dict | None = None, derived_from=None) -> Outcome:
    """The ONE mediated door. Look up the handler, gate it through kernel.mediate(), and invoke
    it only on a permit. Returns an Outcome; the effect happens iff `outcome.ran` is True.

    Fail-closed: an unregistered affordance and a non-permit both return ran=False and run
    nothing. mediate() is itself fail-closed (any internal error -> not permitted), so an error
    in the gate blocks the action rather than opening it.

    A handler's OWN exception is a functional bug, not a governance event — mediation already
    said yes — so it propagates to the caller rather than being swallowed here."""
    args = args or {}
    handler = _REGISTRY.get(affordance)
    if handler is None:
        return Outcome(False, None, None, f"no registered handler for {affordance!r} (fail-closed)")
    permitted, decision, why = kernel.mediate(
        affordance, args, principal=principal, session=session, autonomous=autonomous,
        conscience_fn=conscience_fn, proposal=proposal, derived_from=derived_from)
    if not permitted:
        return Outcome(False, None, decision, why)
    # Open the runtime-guard permit window around the handler. When runtime_guard.install() has
    # been called by the agent process, guarded effects (process spawn, network, ctypes) run ONLY
    # inside this window — so a mediated handler is the only place an effect is allowed at runtime,
    # not just the only place one is written. If the guard is not installed, permit() is a no-op.
    with runtime_guard.permit():
        result = handler(args)
    return Outcome(True, result, decision, "permitted")
