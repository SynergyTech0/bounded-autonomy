"""loop_allowlist.py — the minimal reach for a FIRST supervised autonomous loop. (governance v2)

The least-privilege pass (GOVERNANCE_MODEL.md §9, the step before closing a database<->LLM
loop). The Hugging Face incident's lesson: the gate is only as good as the boundary. So before
any loop is closed, decide deliberately — and narrowly — what it may reach, and default-deny the
rest.

This is DENY-BY-DEFAULT. An affordance runs autonomously in the first loop only if it is on the
allowlist below. Everything else (all PROPOSE/DESTRUCTIVE effectors, all egress, all
personal-data reads) stays human-approved, exactly as today.

Opt-in: `mediate()` consults this only when GOVERNANCE_LOOP_ALLOWLIST=1. Off, nothing changes.
It composes with — never loosens — the enforced v2 layers: an action must pass BOTH.

WHY EACH EXCLUSION (the inventory that produced this):
  * web:fetch / web:research  — AUTO today AND in composition.EGRESS. The covert-exfil channel.
                                Excluded until call sites declare `derived_from`; a first loop
                                does not need the open web.
  * ssh:ssh_download          — AUTO, but pulls files OFF prod boxes (PHI/secrets ingress).
  * sys:journal              — AUTO, but composition labels it SECRET (device tokens leak here).
  * screen:capture           — AUTO, but captures whatever is on screen incl. a password manager.
  * email:*/cal:*/gdrive:*   — read personal/PHI-adjacent data. A knowledge loop does not need them.
  * exec_bridge (root@209)   — armed as of 2026-07-13, SSHes root to the prod fleet, can overwrite
                                remote files. NOT reachable through this allowlist by any name;
                                DISARM it (`rm .exec_bridge_enabled`) before closing the loop
                                unless deliberately needed. This is the highest-risk surface found.

WHAT'S IN: read-only observation, the mind's own knowledge/reasoning, public research reads, and
its own sandboxed memory. Nothing that leaves the boundary, touches personal data, or is
irreversible.
"""
from __future__ import annotations

import os

# Explicit affordances permitted autonomously in the first loop. Deny-by-default: anything
# not here (or matched by a prefix rule below) is refused for autonomous execution.
FIRST_LOOP_ALLOW = {
    # --- local observation (read-only, reversible, non-sensitive) ---
    "sys:disk", "sys:mem", "sys:top", "sys:net", "sys:gpu", "sys:services",
    "node:ping", "web:health", "data:metrics",
    "heal:observe", "heal:alert",          # detect + write a LOCAL alert (reversible)
    "outcome:score",                       # measure whether a staged action worked (read-only)
    # --- cognition / knowledge (writes only to the truth store, never the world) ---
    "memory:consolidate",                  # analyze the truth store for dups/contradictions
    "lesson:match", "habit:detect",        # classify / notice patterns
    "improve:propose", "build:assess", "build:propose", "forge:propose",  # stage INERT proposals
    "act:alert",                           # surface a noticed condition to the local queue
}

# Prefix rules for MCP research reads and the mind's own sandboxed memory. Only tools whose
# deterministic tier is already AUTO (a real read) match; a write-verb tool on these servers is
# still denied by policy and by not appearing here.
_ALLOW_MCP_READ_SERVERS = ("arxiv", "pubmed", "openalex", "semantic_scholar",
                           "wikidata", "wikipedia", "time")
# obsidian: only the read tools; filesystem: only reads, and the server is already sandboxed
# to mcp_sandbox in the registry.
_ALLOW_MCP_EXPLICIT = {
    "mcp:obsidian:vault_read", "mcp:obsidian:vault_list",
    "mcp:obsidian:vault_search", "mcp:obsidian:vault_tags",
    "mcp:filesystem:read_file", "mcp:filesystem:read_text_file",
    "mcp:filesystem:read_multiple_files", "mcp:filesystem:list_directory",
    "mcp:filesystem:directory_tree", "mcp:filesystem:get_file_info",
    "mcp:filesystem:search_files", "mcp:filesystem:list_allowed_directories",
}
_MCP_READ_VERBS = ("search", "get", "list", "read", "fetch", "extract", "autocomplete",
                   "convert", "current", "find")


def enabled() -> bool:
    return os.environ.get("GOVERNANCE_LOOP_ALLOWLIST") == "1"


def permitted_in_first_loop(affordance: str) -> bool:
    """Deny-by-default membership test for the first supervised loop. (§9)

    True only for read-only / cognitive / public-research / own-memory affordances. Everything
    with world reach, egress, personal data, or irreversibility returns False and stays
    human-approved. Fail-closed: an unrecognised affordance is denied."""
    if not affordance:
        return False
    if affordance in FIRST_LOOP_ALLOW:
        return True
    if affordance in _ALLOW_MCP_EXPLICIT:
        return True
    if affordance.startswith("mcp:"):
        parts = affordance.split(":")
        if len(parts) >= 3:
            server, tool = parts[1], parts[-1].lower()
            if server in _ALLOW_MCP_READ_SERVERS and any(
                    tool.startswith(v) or f"_{v}" in tool for v in _MCP_READ_VERBS):
                return True
    return False


if __name__ == "__main__":
    import policy
    print("FIRST-LOOP ALLOWLIST — what may run autonomously in a supervised first loop\n")
    allowed = sorted(a for a in FIRST_LOOP_ALLOW)
    print(f"explicit allow ({len(allowed)}):")
    for a in allowed:
        print(f"  + {a}  [{policy.TIER.get(a, '?')}]")
    print(f"\nplus read-only MCP on: {', '.join(_ALLOW_MCP_READ_SERVERS)}")
    print(f"plus own memory/sandbox reads: {len(_ALLOW_MCP_EXPLICIT)} tools")
    print("\nspot check — these MUST be denied:")
    for a in ("web:fetch", "web:research", "ssh:ssh_download", "sys:journal",
              "screen:capture", "email:read", "email:send", "sign:send_contract",
              "mcp:ssh:ssh_exec", "data:export", "mcp:obsidian:vault_write"):
        print(f"  {'DENIED ' if not permitted_in_first_loop(a) else 'ALLOWED!!!'} {a}")
