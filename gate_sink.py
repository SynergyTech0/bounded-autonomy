# -*- coding: utf-8 -*-
"""gate_sink.py -- the reusable sole-path chokepoint. Put require() at a world-sink so nothing
reaches the world except through the real Governance v2 gate.

    import gate_sink
    gate_sink.require("ssh:exec", {"host": host, "cmd": cmd})   # raises PermissionError if denied
    <the actual subprocess / network / send>

An autonomous or direct call is authorized against the real kernel and only proceeds on an AUTO
verdict; anything DESTRUCTIVE/PROPOSE (the interesting sinks -- exec, install, deploy, spawn, send)
is refused here. A single otherwise-refused call is released ONLY by an OPERATOR-SIGNED one-shot
approval (corrigibility.sign_approval, off-box), verified here against the public key. There is no
in-process arm(): the earlier bare set was unauthenticated (any code that could import this module
could mint the bypass), so it is gone. Fail-closed: any error denies.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def permits(affordance: str, args: dict | None = None, key: str = "") -> tuple[bool, str]:
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    # (b) an OPERATOR-SIGNED one-shot approval for exactly this (affordance, key). Verify-only:
    #     on-box code holds no private key, so it cannot forge one (see corrigibility.verify_approval).
    try:
        import corrigibility
        ok, why = corrigibility.verify_approval(affordance, key)
        if ok:
            return True, why
        approval_reason = why
    except Exception as e:                                       # fail closed
        approval_reason = f"approval check failed closed: {str(e)[:60]}"
    # (a) otherwise ask the real gate; the interesting sinks classify DESTRUCTIVE/PROPOSE so an
    #     autonomous/direct call is denied here.
    try:
        import kernel
        d = kernel.authorize(affordance, args or {}, principal="mind", session="sink",
                             proposal={"summary": f"{affordance} {args}", "claims": [],
                                       "affordances": [affordance]}, autonomous=True)
        return bool(d.permitted), f"gate verdict {d.verdict}; no operator approval ({approval_reason})"
    except Exception as e:                                       # fail closed
        return False, f"gate check failed closed: {str(e)[:60]}"


def require(affordance: str, args: dict | None = None, key: str = ""):
    """Raise PermissionError unless the gate authorizes this action (or the operator signed a
    one-shot approval for it). Fail-closed."""
    ok, why = permits(affordance, args, key)
    if not ok:
        raise PermissionError(
            f"{affordance} denied by governance gate ({why}) — this world-sink is routed through "
            "Governance v2; authorize via the gate or approve off-box via "
            "corrigibility.sign_approval (operator, signed one-shot).")
