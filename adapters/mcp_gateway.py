#!/usr/bin/env python3
"""adapters/mcp_gateway.py — expose the gate as an MCP tool any harness can consult.

This is how Bounded Autonomy drops UNDER a harness (Claude Code, Codex, Cursor, or any MCP
client): the harness calls `gate_check` before it runs a tool, and honors the verdict. It is the
consultative pattern — the server does not intercept the harness's other tools (an MCP server
cannot), it provides the authoritative verdict the harness is configured to obey. For hard
interception, pair it with the PreToolUse hook (adapters/claude_code_hook.py) or the sole-path
`gate_sink.require()` at the effector.

Run it as a stdio MCP server:

    pip install mcp
    python adapters/mcp_gateway.py            # stdio; register it in your MCP client config

Register (example, Claude Code `.mcp.json`):
    { "mcpServers": { "bounded-autonomy": {
        "command": "python", "args": ["/abs/path/bounded-autonomy/adapters/mcp_gateway.py"] } } }

Tools exposed:
  gate_check(tool, args)  -> {allow, verdict, affordance, reason}   the authorization decision
  gate_affordance(tool)   -> the affordance a tool maps to (introspection)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adapters.gate_middleware import Gate  # noqa: E402

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    sys.stderr.write(
        "adapters/mcp_gateway.py needs the MCP SDK: pip install mcp\n"
        "(The gate itself has zero dependencies; only this MCP wrapper needs it.)\n")
    sys.exit(1)

_GATE = Gate(principal=os.environ.get("BA_PRINCIPAL", "mcp-client"), session="mcp")
mcp = FastMCP("bounded-autonomy")


@mcp.tool()
def gate_check(tool: str, args: dict | None = None) -> dict:
    """Authorize a tool call through the Bounded Autonomy gate BEFORE running it. Returns
    {allow, verdict, affordance, reason}. `allow` is true only for an AUTO verdict under a live
    operator grant; PROPOSE means route to a human; DESTRUCTIVE/REFUSE means do not run it."""
    r = _GATE.check(tool, args or {})
    return {"allow": r.allow, "verdict": r.verdict,
            "affordance": r.affordance, "reason": r.reason}


@mcp.tool()
def gate_affordance(tool: str) -> str:
    """Introspection: which Bounded Autonomy affordance a harness tool name maps to."""
    return _GATE.affordance_for(tool)


if __name__ == "__main__":
    mcp.run()
