"""policy.py -- DETERMINISTIC, fail-closed action governance (the v1 layer).

This is a **reference implementation** of the deterministic tier classifier that the
governance kernel treats as layer 1. It is deliberately generic: replace `TIER`,
`MCP_TOOL_TIER`, and `SLO` with your own affordance taxonomy. The engine depends only
on the public API below, not on any particular affordance being present.

The single most important safety property: a language model NEVER decides whether an
action is destructive -- this does, with pure pattern/capability rules (no model in the
loop). The model proposes; this classifies; destructive actions route to a human and an
autonomous agent can never self-authorize them.

Tiers:
  AUTO        read-only / observation        -> may run autonomously
  PROPOSE     reversible state-change        -> logs a proposal; a human approves
  DESTRUCTIVE irreversible / harmful / PHI    -> HUMAN ONLY, always, no autonomous override

Fail-closed everywhere: anything unknown or ambiguous is treated as DESTRUCTIVE.

Public API (the kernel and tests bind to these; keep them stable if you swap the taxonomy):
  classify(affordance, args, phi_node) -> (tier, reason)
  classify_mcp(affordance, args)       -> (tier, reason)
  is_observational(affordance)         -> bool     (look-only; skip the conscience call)
  may_autorun(affordance, args, phi)   -> bool      (True only for AUTO)
  may_autonomously_enact(kind)         -> bool      (reversible allowlist AND base tier PROPOSE)
  scan_command(cmd)                    -> (bool, pattern)
  TIER, MCP_TOOL_TIER, OBSERVATIONAL, AUTONOMY_ELIGIBLE, DESTRUCTIVE_PATTERNS, MODE, SLO
"""
from __future__ import annotations

import os
import re

AUTO, PROPOSE, DESTRUCTIVE = "auto", "propose", "destructive"

# Optional biometric/identity gate for privileged actions. Off until you wire an
# identity service and set IDENTITY_GATE=1.
IDENTITY_GATE = os.environ.get("IDENTITY_GATE", "0") == "1"
IDENTITY_SERVICE = os.environ.get("IDENTITY_SERVICE", "http://127.0.0.1:8771")

# Base tier per affordance. "scan" = depends on the command content (see scan_command).
# This is an EXAMPLE taxonomy. The names are illustrative; the tiers demonstrate the rule
# of thumb: reads observe (AUTO), reversible writes propose (PROPOSE), irreversible /
# outbound / harmful actions are human-only (DESTRUCTIVE).
TIER = {
    # --- read-only observation -> autonomous -------------------------------------------
    "sys:disk": AUTO, "sys:mem": AUTO, "sys:top": AUTO, "sys:net": AUTO, "sys:gpu": AUTO,
    "sys:services": AUTO, "sys:journal": AUTO, "data:metrics": AUTO, "web:health": AUTO,
    "screen:capture": AUTO, "node:ping": AUTO,
    "web:research": AUTO,        # search + read PUBLIC pages (content treated as UNTRUSTED)
    "web:fetch": AUTO,           # fetch one public URL's text (read-only GET; no forms/login)
    "email:read": AUTO, "email:classify": AUTO,
    "emr:read_chart": AUTO,      # example PHI-bearing read: AUTO here, but tainted at the
                                 # information-flow layer so any egress derived from it escalates
    "heal:observe": AUTO,        # read a sensor / detect an issue
    "heal:alert": AUTO,          # write an alert to the local log/dashboard
    "act:alert": AUTO,           # surface a noticed condition to the queue/brief
    "outcome:score": AUTO,       # measure whether a staged action worked (read-only)
    "improve:propose": AUTO,     # propose a NEW objective as INERT (status=proposed)
    "memory:consolidate": AUTO,  # analyze the store for dups/contradictions + report (read-only)
    "habit:detect": AUTO,        # notice "I do X every day" from history
    "lesson:match": AUTO,        # classify a learned lesson's relevance (local reasoning)
    "cal:upcoming": AUTO, "cal:free_slots": AUTO,
    "cal:propose_hold": AUTO,    # stage a hold proposal (nothing placed)
    "gdrive:read_file": AUTO, "gdrive:read_sheet": AUTO, "gdrive:list_recent": AUTO,
    "gdrive:reason_over": AUTO, "gdrive:propose_report": AUTO,
    "github:whoami": AUTO, "github:open_issues": AUTO,
    "github:propose_issue": AUTO, "github:propose_pr": AUTO,
    "gitea:whoami": AUTO, "gitea:list_repos": AUTO, "gitea:open_issues": AUTO,
    "gitea:propose_issue": AUTO, "gitea:propose_pr": AUTO,
    "zoom:list_recordings": AUTO, "zoom:notes": AUTO,
    # self-extension: proposing/vetting a tool is read-only (AST gate + sandboxed self-test)
    "forge:propose": AUTO, "forge:evaluate": AUTO,
    "build:assess": AUTO,        # classify an idea -- local reasoning
    "build:propose": AUTO,       # write a gated build spec -- nothing built
    "container:list": AUTO, "container:inspect_health": AUTO,

    # --- reversible state-change -> propose (a human approves) --------------------------
    "sys:restart": PROPOSE,
    "screen:click": PROPOSE, "screen:type": PROPOSE, "screen:move": PROPOSE,
    "screen:key": PROPOSE, "screen:scroll": PROPOSE, "screen:button": PROPOSE,
    "email:move": PROPOSE, "email:label": PROPOSE, "email:send": PROPOSE,
    "act:propose": PROPOSE,      # stage a drafted action -- a human sends
    "mesh:say": PROPOSE, "mesh:position": PROPOSE,   # local agent-bus chatter
    "memory:merge": PROPOSE,     # merge/retire records (never auto-deletes)
    "cal:hold": PROPOSE, "cal:create_hold": PROPOSE,
    "followup:send_known": PROPOSE,   # follow-up to an already-contacted party (vetoable)
    "schedule:create": PROPOSE, "schedule:delete": PROPOSE,
    "lesson:stage": PROPOSE,
    "gdrive:create_report": PROPOSE,  # arm-time only (via an approve() step)
    "github:create_issue": PROPOSE, "github:create_pr": PROPOSE,
    "gitea:create_issue": PROPOSE, "gitea:create_pr": PROPOSE,
    "sign:send_contract": PROPOSE, "sign:send_decline": PROPOSE,   # outbound, binding -- human arms
    "routes:create_followup": PROPOSE,
    "build:scaffold": PROPOSE,   # runnable sandbox proof (isolated, never deploys)
    "container:logs": PROPOSE,   # log CONTENT can carry secrets
    "container:restart": PROPOSE,
    "forge:build_project": PROPOSE, "forge:mint_agent": PROPOSE,
    "heal:restart_local": AUTO,  # restart the agent's OWN local process (reversible)
    "heal:relearn": AUTO,        # re-study weak subjects (reversible, adds knowledge)
    "heal:restart_remote": PROPOSE, "heal:renew_cert": PROPOSE,

    # --- irreversible / outbound / harmful -> HUMAN ONLY, no override -------------------
    "data:export": DESTRUCTIVE,  # leaves the boundary
    "email:delete": DESTRUCTIVE,
    "forge:install": DESTRUCTIVE,  # installing new executable code is the highest-risk act
    "build:ship": DESTRUCTIVE,     # real repo / deploy / spend money
    "heal:destroy": DESTRUCTIVE,   # anything that deletes/wipes

    # --- arbitrary command -> scan the content -----------------------------------------
    "sys:exec": "scan",
    #
    # NOTE ON THE GOVERNANCE SURFACE (gov:*): grants, heartbeats, arm files, the signing
    # key, the ledger, and the system's own scheduling are DELIBERATELY ABSENT here. They
    # therefore fall through to "unknown action (fail-closed -> DESTRUCTIVE)" AND are
    # independently caught by corrigibility's governance-surface check (invariant G12).
    # Never add gov:* to this table.
}

# Deterministic destructive-command patterns. A match => DESTRUCTIVE, human-only.
DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-\w*[rf]", r"\brmdir\b", r"\bdrop\s+(table|database|schema)\b", r"\btruncate\b",
    r"\bdelete\s+from\b", r"\bdd\s+if=", r"\bmkfs", r"\bformat\s", r"\bfdisk\b", r"\bwipe\b",
    r"\b(shutdown|reboot|halt|poweroff)\b", r"\buserdel\b", r"\bdeluser\b",
    r"\bkill(all)?\s+-9", r":\s*\(\s*\)\s*\{", r"\bchmod\s+-R\s+0?777", r"\bchown\s+-R\b",
    r"\biptables\s+-F", r"\bufw\s+disable", r"\bsystemctl\s+(stop|disable|mask)\b",
    r">\s*/dev/sd", r"\bdocker\s+(rm\b|rmi\b|system\s+prune|volume\s+rm)",
    r"\bgit\s+.*--force", r"\b(cat|type|copy|scp)\b.*\b(\.ssh|id_rsa|id_ed25519|authorized_keys|\.pem|key\.json)\b",
    r"\bpasswd\b", r"\bnet\s+user\b", r"\breg\s+delete\b", r"\bRemove-Item\b.*-Recurse",
    r"\bShutdown\b|\bRestart-Computer\b", r"\bDrop-", r"\bformat\b.*:",
]


# MCP-style tools are classified by verb: reads observe (AUTO), writes/sends propose,
# deletes are human-only. Same fail-closed spirit.
_MCP_DELETE = ("delete", "remove", "drop", "unlabel", "purge", "clear", "destroy", "revoke")
_MCP_READ = ("read", "list", "get", "search", "fetch", "find", "query", "view", "tree",
             "info", "convert", "current", "resolve", "describe", "status", "summary",
             "open", "suggest", "participants", "recent", "download", "metadata",
             "classify", "triage", "summarize", "scan",
             "aged", "trial", "statement", "balance", "report")

# EXPLICIT per-tool tiers. These BEAT the verb heuristic, which is only a fallback and
# gets some tools dangerously wrong. The classic trap: a tool whose NAME contains a read
# verb but whose EFFECT is a write -- e.g. a "query_to_note" that matches "query" but
# actually WRITES a note. Anything whose true effect is not obvious from its verb belongs
# here. Fail-closed: when in doubt, tier it higher. (Illustrative examples below.)
MCP_TOOL_TIER = {
    "notes:read": AUTO, "notes:list": AUTO, "notes:search": AUTO,
    "notes:write": PROPOSE,
    "notes:query_to_note": PROPOSE,   # WRITES a note (the verb "query" lies)
    "notes:weekly_report": PROPOSE,   # WRITES a report note (the verb "report" lies)
    "notes:delete": DESTRUCTIVE,
    "ssh:ssh_list_hosts": AUTO,
    "ssh:ssh_health_check": AUTO,     # read-only probe (uptime/disk/services)
    "ssh:ssh_download": AUTO,         # pull a file off a box = a read
    "ssh:ssh_exec": "scan",           # SCAN THE COMMAND (see classify_mcp)
    "ssh:ssh_multi_exec": "scan",
    "ssh:ssh_upload": PROPOSE,
    "ssh:ssh_add_host": PROPOSE,
    "ssh:ssh_remove_host": DESTRUCTIVE,
    "db:read_query": AUTO,            # SELECT-only
    "db:write_query": "scan",         # description says INSERT/UPDATE/DELETE -> scan it
    "db:create_table": PROPOSE,
    "db:list_tables": AUTO, "db:describe_table": AUTO,
}

# arg keys that carry an executable payload (shell command OR SQL), for the content-scan.
_CMD_KEYS = ("cmd", "command", "script", "run", "query", "sql")


# ---- Earned autonomy -----------------------------------------------------------------------------
# The ONLY kinds a track-record gate may ever auto-enact once a proven history + reversal window are
# satisfied. Hardcoded allowlist, fail-closed. Money movement, PHI, credentials, publishing, and
# anything DESTRUCTIVE are CATEGORICALLY excluded and can never be added here -- no hit-rate unlocks
# them, ever. Every entry MUST be reversible-after-the-fact OR vetoable-before-commit, and MUST
# already be tier PROPOSE (autonomy never silently promotes an AUTO, never moves toward DESTRUCTIVE).
AUTONOMY_ELIGIBLE = {
    "email:label",          # reversible: relabel an email          (undo: remove the label)
    "email:move",           # reversible: move to a folder          (undo: move it back)
    "cal:hold",             # reversible: tentative calendar hold    (undo: delete the event)
    "cal:create_hold",      # same act, same reversibility
    "followup:send_known",  # VETOABLE (not reversible): only after a reversal window with a veto
    "mesh:say",             # low-stakes local-bus chatter, rate-limited + conscience-checked
    "mesh:position",
    # Reversible actions kept OFF this list on purpose (e.g. create_report/create_issue): putting
    # an action-type here is a governance decision for the operator, not a plumbing default.
}


def may_autonomously_enact(kind: str) -> bool:
    """True ONLY for the reversible/vetoable allowlist AND only if the base tier is PROPOSE.
    Never AUTO (already permitted), never DESTRUCTIVE (human-only -- no track record ever unlocks it).
    A track-record gate calls this as its first, non-negotiable check."""
    return kind in AUTONOMY_ELIGIBLE and TIER.get(kind) == PROPOSE


def scan_command(cmd: str) -> tuple[bool, str]:
    """True if a shell command matches a destructive pattern. The SAME deterministic scan
    sys:exec gets -- no model, no judgement, just patterns."""
    for pat in DESTRUCTIVE_PATTERNS:
        if re.search(pat, cmd or "", re.I):
            return True, pat
    return False, ""


# Affordances that only LOOK -- a probe result, a disk figure, a container's status. They change
# nothing and carry no moral content, so the conscience layer is not consulted for them (a cost
# decision, not an ethical one). Anything that acts, sends, writes or leaves the boundary is NOT here.
OBSERVATIONAL = {
    "sys:disk", "sys:mem", "sys:top", "sys:net", "sys:gpu", "sys:services", "sys:journal",
    "data:metrics", "web:health", "node:ping", "screen:capture",
    "heal:observe", "container:list", "container:inspect_health",
    "heal:alert", "act:alert",
}


def is_observational(affordance: str) -> bool:
    """True for look-only actions, in either spelling. Read-only MCP tools count as looking."""
    bare = affordance.removeprefix("mcp:")
    if bare in OBSERVATIONAL or affordance in OBSERVATIONAL:
        return True
    if affordance.startswith("mcp:"):
        return classify_mcp(affordance, {})[0] == AUTO
    return False


def classify_mcp(affordance: str, args: dict | None = None) -> tuple[str, str]:
    """Tier an mcp:<server>:<tool> affordance.

    Order matters and is fail-closed:
      1. EXPLICIT MCP_TOOL_TIER  -- beats the heuristic (which mis-reads e.g. a *_to_note or
         *_report tool as a read when it WRITES).
      2. "scan" tools (ssh/db exec) -- the shell/SQL command itself is pattern-scanned; a
         destructive command is DESTRUCTIVE no matter that the tool is nominally a PROPOSE.
      3. verb heuristic -- delete-class -> DESTRUCTIVE, read-class -> AUTO.
      4. unknown -> PROPOSE (a human approves).
    """
    args = args or {}
    parts = affordance.split(":")
    key = ":".join(parts[1:3]) if len(parts) >= 3 else ""     # "<server>:<tool>"
    tool = parts[-1].lower()

    explicit = MCP_TOOL_TIER.get(key)
    if explicit == "scan":
        cmd = ""
        for k in _CMD_KEYS:
            if args.get(k):
                cmd = str(args[k])
                break
        bad, pat = scan_command(cmd)
        if bad:
            return DESTRUCTIVE, f"destructive pattern in the payload: {pat}"
        if not cmd:
            return PROPOSE, "exec tool with no inspectable payload -- human approves"
        return PROPOSE, "executable payload -- human review (never autonomously runnable)"
    if explicit:
        return explicit, "MCP tool with an explicit policy tier"

    for v in _MCP_DELETE:
        if v in tool:
            return DESTRUCTIVE, f"MCP delete-class tool ({v}) -- human only"
    for v in _MCP_READ:
        if tool.startswith(v) or f"_{v}" in tool or v in tool.split("_"):
            return AUTO, "MCP read-only tool"
    return PROPOSE, "MCP write/effect tool -- human approves"


def classify(affordance: str, args: dict | None = None, phi_node: bool = False) -> tuple[str, str]:
    """Deterministic tier + reason. Fail-closed: unknown action -> DESTRUCTIVE."""
    args = args or {}
    if affordance.startswith("mcp:"):
        return classify_mcp(affordance, args)
    base = TIER.get(affordance)
    if base is None:
        return DESTRUCTIVE, "unknown action (fail-closed -> human)"
    if base == "scan":
        cmd = str(args.get("cmd", "")).lower()
        for pat in DESTRUCTIVE_PATTERNS:
            if re.search(pat, cmd, re.I):
                return DESTRUCTIVE, f"destructive command pattern: {pat}"
        return PROPOSE, "arbitrary command -- human review (not autonomously runnable)"
    # PHI node: any data egress/write beyond operational metrics is destructive
    if phi_node and affordance.startswith("data:") and affordance != "data:metrics":
        return DESTRUCTIVE, "PHI-node data action -- no sensitive data leaves the box"
    return base, "classified by capability"


def may_autorun(affordance: str, args: dict | None = None, phi_node: bool = False) -> bool:
    """True only for AUTO (read-only). Everything else needs a human in the loop."""
    return classify(affordance, args, phi_node)[0] == AUTO


# ----------------------------------------------------------- goals / SLOs (declarative, example)
SLO = {
    "disk_pct_max": 85,
    "mem_pct_max": 93,
    "load1_per_core_max": 2.0,
    # node -> processes/containers that must stay up (name substrings). Replace with your own.
    "must_be_up": {
        "app-host": ["app-web", "app-db"],
        "this-host": [],
    },
}

# Global autonomy stance. SHADOW = observe + propose + LOG, execute NOTHING.
MODE = "shadow"   # shadow | supervised | autonomous   (destructive ALWAYS human, every mode)
