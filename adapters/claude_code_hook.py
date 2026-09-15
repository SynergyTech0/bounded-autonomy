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

    r = Gate(principal=_PRINCIPAL, session="claude-code").check(tool, args)
    if r.allow:
        _decision("allow", f"gate: AUTO ({r.affordance})")
    elif r.verdict == lattice.PROPOSE:
        _decision("ask", f"gate: PROPOSE — {r.reason}")
    else:
        _decision("deny", f"gate: {r.verdict.upper()} — {r.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
