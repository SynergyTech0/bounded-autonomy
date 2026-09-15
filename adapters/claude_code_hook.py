#!/usr/bin/env python3
"""adapters/claude_code_hook.py — a Claude Code PreToolUse hook that gates every tool call.

Wire it in `.claude/settings.json` so the gate runs before any tool executes:

    {
      "hooks": {
        "PreToolUse": [
          { "matcher": "*",
            "hooks": [ { "type": "command",
                         "command": "python /abs/path/to/bounded-autonomy/adapters/claude_code_hook.py" } ] }
        ]
      }
    }

Contract: Claude Code sends the tool call as JSON on stdin (`tool_name`, `tool_input`). This maps
it to an affordance, runs the real `kernel.mediate()`, and answers with a PreToolUse permission
decision:
  * AUTO  (permitted autonomously)      -> allow
  * PROPOSE (reversible, needs a human) -> ask   (Claude Code prompts you)
  * DESTRUCTIVE / REFUSE                -> deny   (blocked, reason shown to the model)

Fail-closed: any error denies. Remember that `allow` only ever happens with a live off-box GO
grant (governance_operator.py); without one every call becomes `ask` or `deny`, by design.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adapters.gate_middleware import Gate  # noqa: E402
import lattice  # noqa: E402

_PRINCIPAL = os.environ.get("BA_PRINCIPAL", "claude-code")
# backstop (default): interactive posture — deny only irreversible/exfil, allow the rest, no grant
#   needed (the human is the operator). Best for a hands-on Claude Code / ECC session.
# autonomous: the full gate — AUTO permitted only under a live off-box grant, PROPOSE -> ask,
#   DESTRUCTIVE/REFUSE -> deny. Use when the agent runs without a human in the loop.
_MODE = os.environ.get("BA_MODE", "backstop")


def _decision(perm, reason):
    # Modern Claude Code hook output shape.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": perm,               # "allow" | "ask" | "deny"
            "permissionDecisionReason": reason[:400],
        }
    }))


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        _decision("deny", "Bounded Autonomy: unreadable hook payload — fail-closed")
        return 0

    tool = payload.get("tool_name") or payload.get("tool") or ""
    args = payload.get("tool_input") or payload.get("input") or {}

    # Use the Claude Code session id so information-flow taint is scoped to THIS session,
    # not leaked across every session through one fixed name.
    session = str(payload.get("session_id") or "claude-code")
    gate = Gate(principal=_PRINCIPAL, session=session)
    if _MODE == "autonomous":
        r = gate.check(tool, args)
        if r.allow:
            _decision("allow", f"gate: AUTO ({r.affordance})")
        elif r.verdict == lattice.PROPOSE:
            _decision("ask", f"gate: PROPOSE — {r.reason}")
        else:
            _decision("deny", f"gate: {r.verdict.upper()} — {r.reason}")
    else:  # backstop (default): only the irreversible/exfil tier is blocked; the human handles the rest
        r = gate.backstop(tool, args)
        if r.allow:
            _decision("allow", f"gate backstop: {r.verdict} ({r.affordance}) — within limits")
        else:
            _decision("deny", f"gate backstop: {r.verdict.upper()} — {r.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
