# Running Bounded Autonomy under ECC

[ECC](https://github.com/affaan-m/ECC) is an agent *harness* — it makes a coding agent a better
engineer (68 agents, 292 skills, a plan→test→review workflow) and ships a static safety layer
(`gateguard` / AgentShield) that inspects commands, configs, prompts, and secrets **before** a run.

Bounded Autonomy is the piece ECC does not attempt: a **runtime governance gate**. Where ECC's
gateguard is a static check on the *shape* of a command, Bounded Autonomy is a reference monitor on
the *action* — off-box-signed corrigibility (stop is the default), information-flow taint,
destination-trust egress, and a tamper-evident ledger. They are complementary, and they compose.

## Why they compose cleanly

Both register a Claude Code **`PreToolUse`** hook. Claude Code runs **every** matching PreToolUse
hook and blocks the tool if **any** of them denies. So with both installed:

| Layer | Runs | Decides on |
|---|---|---|
| **ECC gateguard** (node, `Bash`/`PowerShell`) | ECC's plugin hooks | command shape, policy, quality, house rules |
| **Bounded Autonomy** (`adapters/claude_code_hook.py`, matcher `*`) | your `settings.json` | the *authorized action*: grant + taint + destination-trust + corrigibility |

A deny from either blocks the tool. That is defense in depth: ECC catches the malformed or
off-policy command statically; Bounded Autonomy catches the action that is individually well-formed
but not *authorized right now* — an egress under taint, a governance-surface touch, anything at all
when there is no live operator grant.

## Setup (add the gate alongside ECC — do not remove ECC's hooks)

1. Install ECC as usual (`npx ecc-universal@latest setup`). Keep `hooks_enabled: true`.
2. Clone Bounded Autonomy and add its gate as an independent PreToolUse hook. Merge this into your
   project or user `.claude/settings.json` (see `settings.fragment.json` in this folder):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "*",
           "hooks": [ { "type": "command",
             "command": "python /ABS/PATH/bounded-autonomy/adapters/claude_code_hook.py" } ] }
       ]
     }
   }
   ```

   Claude Code merges this with ECC's plugin-provided hooks — you do **not** edit ECC. Both fire.

3. (Optional) Also expose the gate over MCP so ECC's agents can consult it as a tool. Add to
   `.mcp.json` next to ECC's MCP conventions:

   ```json
   { "mcpServers": { "bounded-autonomy": {
       "command": "python", "args": ["/ABS/PATH/bounded-autonomy/adapters/mcp_gateway.py"] } } }
   ```

## What you get, and the honest catch

- **AUTO** (permitted autonomously) requires a **live, off-box-signed grant** (see
  `governance_operator.py`). Until you mint one, the gate answers `ask` (PROPOSE → Claude Code
  prompts you) or `deny` (DESTRUCTIVE/REFUSE). That is the correct posture: an ECC-equipped agent
  runs with the human in the loop until you deliberately arm bounded autonomy — at which point ECC's
  productivity layer keeps working and the gate is what lets the agent act *without* you, safely.
- **File tools** (`Read`/`Write`/`Edit`) fail-close to human-only under the reference policy until
  you add `fs:read`/`fs:write` to your policy — see `../../adapters/README.md`.

## The one-line positioning

**ECC makes the agent a better engineer; Bounded Autonomy bounds what it can *do* when it acts on
its own.** ECC's audience already trusts an agent with a shell — this is the runtime enforcement
layer for the moment they let it off the leash.
