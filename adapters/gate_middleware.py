"""adapters/gate_middleware.py — put the gate in front of any harness's tool calls.

Framework-agnostic core the other adapters build on. It maps a harness tool call (`Bash`,
`WebFetch`, `mail.send`, …) to a Bounded Autonomy affordance and routes it through the REAL
`kernel.mediate()` before the harness executes the tool. Deny-by-default (an unmapped tool is
treated as an unknown affordance, which the policy layer fail-closes to human-only) and
fail-closed (any error denies).

    from adapters.gate_middleware import Gate
    gate = Gate(principal="my-agent")
    r = gate.check("Bash", {"command": "rm -rf /"})
    if r.allow:            # permitted autonomously (AUTO) with a live operator grant
        run_tool()
    elif r.verdict == "propose":
        queue_for_human(r)  # reversible; a human approves
    else:
        refuse(r.reason)    # destructive / refused — r.decision has every layer's opinion

REQUIREMENTS FOR `allow` TO EVER BE TRUE: enforcement uses the real corrigibility layer, so a
live, off-box-signed GO grant + fresh heartbeat must be present (see governance_operator.py). With
no grant, every call denies — which is the correct fail-closed default, not a bug.

AFFORDANCES MUST EXIST IN YOUR POLICY. The default map targets affordances the reference
`policy.py` already knows for shell/web; file tools map to `fs:read` / `fs:write`, which the
reference policy does not define and therefore fail-closes to human-only. Add them to your policy
to tune (see adapters/README.md) — the safe default is "a file write needs a human", not "allow".
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import kernel      # noqa: E402
import lattice     # noqa: E402

# Harness tool name -> (affordance, arg-key remap). The remap pulls the payload the policy layer
# expects: e.g. a shell tool's command must arrive under "cmd" for the destructive-pattern scan.
# Covers Claude Code, Codex, and generic tool names; extend or replace via Gate(tool_map=...).
DEFAULT_TOOL_MAP = {
    # shell / exec  -> scanned for destructive patterns by policy
    "Bash":        ("sys:exec", {"command": "cmd"}),
    "shell":       ("sys:exec", {"command": "cmd"}),
    "shell.run":   ("sys:exec", {"command": "cmd"}),
    "run_terminal_cmd": ("sys:exec", {"command": "cmd"}),
    # network egress -> destination-trust / taint gate
    "WebFetch":    ("web:fetch", {"url": "url"}),
    "web.fetch":   ("web:fetch", {"url": "url"}),
    "fetch":       ("web:fetch", {"url": "url"}),
    "WebSearch":   ("web:research", {}),
    # outbound messaging -> egress
    "mail.send":   ("email:send", {}),
    "SendEmail":   ("email:send", {}),
    # file surface (reference policy leaves these unknown => human-only; add fs:* to your policy)
    "Read":        ("fs:read", {}),
    "Glob":        ("fs:read", {}),
    "Grep":        ("fs:read", {}),
    "Write":       ("fs:write", {}),
    "Edit":        ("fs:write", {}),
    "NotebookEdit": ("fs:write", {}),
}


class GateResult:
    __slots__ = ("allow", "verdict", "reason", "affordance", "decision")

    def __init__(self, allow, verdict, reason, affordance, decision):
        self.allow, self.verdict, self.reason = allow, verdict, reason
        self.affordance, self.decision = affordance, decision

    def __repr__(self):
        return f"<GateResult allow={self.allow} {self.verdict} {self.affordance!r} {self.reason[:50]}>"


class Gate:
    """A reusable gate for one principal. `check()` maps a tool call and mediates it."""

    def __init__(self, principal: str = "agent", session: str = "harness",
                 tool_map: dict | None = None, unknown_affordance: str = "tool:unknown",
                 legibility_verifier=None):
        self.principal = principal
        self.session = session
        self.tool_map = dict(DEFAULT_TOOL_MAP if tool_map is None else tool_map)
        self.unknown = unknown_affordance          # fail-closed: policy will REFUSE/DESTRUCT this
        self.verifier = legibility_verifier

    def affordance_for(self, tool: str) -> str:
        entry = self.tool_map.get(tool)
        return entry[0] if entry else self.unknown

    def _map_args(self, tool: str, args: dict) -> dict:
        entry = self.tool_map.get(tool)
        if not entry or not entry[1]:
            return dict(args or {})
        out = dict(args or {})
        for src, dst in entry[1].items():
            if src in out and dst not in out:
                out[dst] = out[src]
        return out

    def check(self, tool: str, args: dict | None = None) -> GateResult:
        """Map the tool to an affordance and mediate it. Fail-closed: any error denies."""
        try:
            affordance = self.affordance_for(tool)
            margs = self._map_args(tool, args or {})
            permitted, decision, why = kernel.mediate(
                affordance, margs, principal=self.principal, session=self.session,
                autonomous=True, legibility_verifier=self.verifier)
            verdict = decision.verdict if decision is not None else lattice.REFUSE
            return GateResult(bool(permitted), verdict, why, affordance, decision)
        except BaseException as e:  # never let the gate itself open the door
            return GateResult(False, lattice.REFUSE,
                              f"gate failed closed ({type(e).__name__}): {str(e)[:80]}",
                              "tool:error", None)

    def backstop(self, tool: str, args: dict | None = None) -> GateResult:
        """Interactive posture: a HARD FLOOR, not an autonomy gate. For a human-driven session
        (Claude Code, an ECC harness) the operator is already in the loop, so re-asking on every
        reversible action is noise, and accumulating session taint would block ordinary work (a
        fetch after any write). This enforces only the DETERMINISTIC policy tier — it denies the
        irreversible / destructive class (`rm -rf` and friends, a file delete, a data export, a
        DROP/TRUNCATE, installing code) and lets everything else through for the human and the
        harness. No grant needed (autonomous=False: the human is the operator); it never floods a
        session with 'ask'. Fail-closed: deny.

        The full trajectory gate — information-flow taint, destination-trust egress, off-box
        corrigibility — is `check()` (autonomous mode), for when the agent runs WITHOUT a human.
        `allow` is True unless the policy tier is DESTRUCTIVE or REFUSE."""
        try:
            affordance = self.affordance_for(tool)
            margs = self._map_args(tool, args or {})
            d = kernel.authorize(affordance, margs, principal=self.principal, session=self.session,
                                 autonomous=False, legibility_verifier=self.verifier,
                                 proposal={"summary": affordance, "claims": [], "affordances": [affordance]})
            verdict = d.enforced(("policy",))          # deterministic floor only — no session taint
            hard = lattice.rank(verdict) <= lattice.rank(lattice.DESTRUCTIVE)   # DESTRUCTIVE or REFUSE
            return GateResult(not hard, verdict, d.reason, affordance, d)
        except BaseException as e:
            return GateResult(False, lattice.REFUSE,
                              f"gate failed closed ({type(e).__name__}): {str(e)[:80]}",
                              "tool:error", None)


def gated(gate: Gate, tool_name: str | None = None):
    """Decorator: block a tool function unless the gate permits it. The wrapped function's name is
    the tool name unless `tool_name` is given; its first arg (or kwargs) is treated as the payload.

        g = Gate(principal="agent")
        @gated(g, "WebFetch")
        def web_fetch(args): ...
    """
    def deco(fn):
        name = tool_name or fn.__name__

        def wrapper(args=None, *a, **kw):
            r = gate.check(name, args if isinstance(args, dict) else (kw or {}))
            if not r.allow:
                raise PermissionError(f"Bounded Autonomy denied {name!r}: {r.verdict} — {r.reason}")
            return fn(args, *a, **kw)
        wrapper.__name__ = getattr(fn, "__name__", name)
        return wrapper
    return deco


if __name__ == "__main__":
    # Smoke demo: no grant is active here, so everything denies (the correct fail-closed default).
    g = Gate(principal="demo")
    for tool, args in (("Bash", {"command": "ls -la"}),
                       ("Bash", {"command": "rm -rf /"}),
                       ("WebFetch", {"url": "https://example.com"}),
                       ("Write", {"path": "notes.md"})):
        r = g.check(tool, args)
        print(f"{tool:10} -> {r.affordance:12} allow={r.allow!s:5} {r.verdict:11} {r.reason[:60]}")
