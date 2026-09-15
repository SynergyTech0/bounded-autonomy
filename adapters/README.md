# Adapters — put the gate under any agent harness

Bounded Autonomy is a governance *gate*, not a harness. These adapters are how you drop it
underneath the harness you already use (Claude Code, Codex, Cursor, a custom loop) so every tool
call is authorized against the real `kernel.mediate()` before it runs.

All three build on **`gate_middleware.py`** — the framework-agnostic core that maps a harness tool
name to an affordance and mediates it. It has **zero dependencies** beyond the gate itself.

| Adapter | Pattern | Interception | Use it when |
|---|---|---|---|
| `gate_middleware.py` | in-process `Gate.check()` / `@gated` decorator | your code calls it | you own the agent loop |
| `claude_code_hook.py` | Claude Code **PreToolUse hook** | hard — CC blocks the tool | you run Claude Code |
| `mcp_gateway.py` | **MCP** `gate_check` tool | consultative — the harness obeys | any MCP client (Codex, Cursor, …) |

## 1. In-process (any Python agent loop)

```python
from adapters.gate_middleware import Gate
gate = Gate(principal="my-agent")

r = gate.check("Bash", {"command": user_cmd})
if r.allow:                       # AUTO, under a live operator grant
    run(user_cmd)
elif r.verdict == "propose":
    queue_for_human(r)            # reversible; a human approves
else:
    refuse(r.reason)              # r.decision carries every layer's opinion
```

Or wrap the effector directly:

```python
from adapters.gate_middleware import Gate, gated
g = Gate(principal="my-agent")

@gated(g, "WebFetch")
def web_fetch(args): ...          # raises PermissionError unless the gate permits
```

## 2. Claude Code PreToolUse hook (hard block)

Point a `PreToolUse` hook at `claude_code_hook.py` in `.claude/settings.json` (see the header of
that file). Every tool call is mapped and mediated; the gate answers **allow** (AUTO), **ask**
(PROPOSE — Claude Code prompts you), or **deny** (DESTRUCTIVE/REFUSE, blocked with a reason shown
to the model). This is real interception: the tool does not run on a deny.

## 3. MCP gateway (any MCP client)

`pip install mcp`, run `python adapters/mcp_gateway.py` as a stdio server, and register it in your
client. It exposes `gate_check(tool, args)` — the authoritative verdict the harness is configured
to consult before acting. For harnesses without a pre-tool hook, pair it with `gate_sink.require()`
at the actual effector so the decision is enforced, not merely advisory.

---

## Two things that make `allow` behave

**A live grant is required.** Enforcement runs the real corrigibility layer, so `allow` is only
ever true with a live, off-box-signed GO token + fresh heartbeat (see `governance_operator.py`).
With no grant, every call is `ask` or `deny` — the correct fail-closed default, not a bug.

**Affordances must exist in your policy.** The default tool map targets affordances the reference
`policy.py` already knows for **shell** (`sys:exec`) and **network** (`web:fetch` / `web:research`).
**File tools** map to `fs:read` / `fs:write`, which the reference policy does *not* define — so
they fail-close to human-only. Add them to your policy to tune file behavior:

```python
# in your policy.py TIER map
"fs:read":  AUTO,       # reading files is observation
"fs:write": PROPOSE,    # writing is reversible -> a human approves
"fs:delete": DESTRUCTIVE,
```

Pass your own mapping if your harness uses different tool names:

```python
Gate(principal="agent", tool_map={"my_shell": ("sys:exec", {"cmd": "cmd"}), ...})
```
