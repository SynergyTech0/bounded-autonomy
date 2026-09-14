"""composition.py — governing the mesh, not the call. (governance v2 / G8-G11)

GOVERNANCE_MODEL.md §4. The finding this repairs (F4): `policy.classify(affordance, args,
phi_node)` takes no session, no principal, no history. It is a pure function of one action.
An agent OS is a mesh of agents, so v1 governs each move of a game it cannot see.

Three attacks follow directly from that blind spot, and each maps to an invariant:

  SPLIT PAYLOAD   no single call is destructive; the sequence is.            -> G8
  COVERT EGRESS   `email:read` is AUTO. `web:fetch` is AUTO. Read private
                  data, encode it in a URL, and it leaves without any
                  DESTRUCTIVE tier ever being reached.                       -> G9
  LAUNDERING      a low-authority agent induces a trusted agent to make the
                  call; the gate sees the trusted agent's authority.         -> G10

The repair in one sentence: **tier is a function of the trajectory, and composition can
only escalate.** A sequence is at least as dangerous as its most dangerous part, and
usually more.

Taint is monotone within a window and never decays early. That is deliberate: a system that
could wait out its own taint would simply wait. Taint clears when the window closes, and the
window is a session, not a timer the agent controls.

  python composition.py status <session>    # taint, contributors, budget for a session
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

import lattice

HERE = os.path.dirname(os.path.abspath(__file__))
TRAJECTORY = os.environ.get("GOVERNANCE_TRAJECTORY",
                            os.path.join(HERE, "governance_trajectory.jsonl"))

WINDOW_S = int(os.environ.get("GOVERNANCE_WINDOW", 3600))     # trajectory horizon
VELOCITY_MAX = int(os.environ.get("GOVERNANCE_VELOCITY", 60))  # actions/window before escalating

# ---------------------------------------------------------------- G9: information-flow labels
PHI, SECRET, PRIVATE, CREDENTIAL, UNTRUSTED, PUBLIC = (
    "PHI", "SECRET", "PRIVATE", "CREDENTIAL", "UNTRUSTED", "PUBLIC")

# Labels that make an egress destructive. UNTRUSTED is deliberately NOT here — it taints in
# the other direction (see promote_to_instruction below): untrusted content is dangerous
# coming IN, not going out.
SENSITIVE = {PHI, SECRET, PRIVATE, CREDENTIAL}

# What each affordance ACQUIRES when it runs. Fail-closed default in labels_for().
LABELS_ACQUIRED = {
    "email:read": {PRIVATE}, "email:classify": {PRIVATE},
    "gdrive:read_file": {PRIVATE}, "gdrive:read_sheet": {PRIVATE},
    "gdrive:list_recent": {PRIVATE}, "gdrive:reason_over": {PRIVATE},
    "zoom:notes": {PRIVATE}, "zoom:list_recordings": {PRIVATE},
    "cal:upcoming": {PRIVATE}, "cal:free_slots": {PRIVATE},
    "sys:journal": {SECRET},          # device tokens land in journals — a known leak pattern
    "screen:capture": {PRIVATE},      # whatever is on screen, including a password manager
    "web:research": {UNTRUSTED}, "web:fetch": {UNTRUSTED},
    "data:metrics": set(), "sys:disk": set(), "sys:mem": set(), "sys:top": set(),
    "sys:net": set(), "sys:gpu": set(), "sys:services": set(), "node:ping": set(),
    # EXAMPLE body observations (operator-authorised). These acquire NOTHING sensitive: a
    # TCP connect result is a host, a port, up/down and a latency — the same shape as node:ping,
    # which is already set(). Left unlisted they defaulted to PRIVATE (labels_for fails closed),
    # which tainted every body session and made the escalation path — act:propose, an EGRESS
    # affordance — DESTRUCTIVE under G9. That silently cut the operator out of the loop: an
    # incident could open and no human could be told. Observed live 2026-09-06 14:50Z.
    # Revert = delete these three lines. Anything that reads real content stays unlisted.
    "heal:observe": set(), "heal:alert": set(), "act:alert": set(),
}

# Content sniffing on the arguments — an affordance can pick up a label from what it touched
# even when its name is innocuous.
_LABEL_PATTERNS = (
    (PHI, r"\b(patient|mrn|diagnos|icd-?10|phi|dob|date_of_birth|ssn|npi)\b"),
    (CREDENTIAL, r"\b(password|api[_-]?key|secret|token|bearer|id_rsa|id_ed25519|\.pem)\b"),
    (SECRET, r"\b(\.env|credentials|private[_-]?key|authorized_keys)\b"),
    (PRIVATE, r"\b(salary|invoice|contract|medical|personal)\b"),
)

# Affordances that can move bytes out of the boundary. web:fetch is here because a URL is a
# perfectly good exfiltration channel, and it is AUTO in v1 — that pair is the covert-egress
# hole exactly.
EGRESS = {
    "data:export", "web:fetch", "web:research", "email:send", "followup:send_known",
    "sign:send_contract", "sign:send_decline", "github:create_issue", "github:create_pr",
    "gitea:create_issue", "gitea:create_pr", "gdrive:create_report", "sys:exec",
    "mcp:ssh:ssh_upload", "mcp:ssh:ssh_exec", "mcp:ssh:ssh_multi_exec",
    "routes:create_followup", "act:propose",
}

# ---------------------------------------------------------------- G10: principal authority
# The best verdict a principal may ever obtain. Unknown principal -> UNKNOWN_AUTHORITY.
# These are ceilings, not grants: being listed here permits nothing on its own.
AUTHORITY = {
    "operator": lattice.AUTO,
    "mind": lattice.AUTO,               # the trusted core loop
    "email_triage": lattice.PROPOSE,
    "web_scout": lattice.PROPOSE,       # anything that has ingested web content
    "forge": lattice.PROPOSE,
    "inbound": lattice.DESTRUCTIVE,     # anything originating outside the boundary
    "untrusted": lattice.DESTRUCTIVE,
    # EXAMPLE: sub-agents admitted one by one, never by prefix. Ceilings only — every action
    # still meets policy/legibility/corrigibility, and a ceiling permits nothing on its own.
    # These example agents are model-free and publish only to an in-process bus; the point of an
    # AUTO ceiling is that the AFFORDANCE tier does the real gating (an observation is AUTO; an
    # action that touches the world is PROPOSE regardless of the principal's ceiling).
    "agents/devops/monitoring-agent": lattice.AUTO,     # probe -> bus (heal:alert)
    "agents/devops/incident-responder": lattice.AUTO,   # bus -> bus (act:alert)
    "agents/devops/fleet-nerve": lattice.AUTO,          # small model that PROPOSES; tier gates it
    "agents/devops/records-nerve": lattice.AUTO,        # stages drafts (never EGRESS); tier gates it
}
UNKNOWN_AUTHORITY = lattice.PROPOSE     # an unrecognised agent gets no autonomy

# G11: mesh-wide daily caps per action-type. Mirrors autonomy_gate.DAILY_CAP but is counted
# across ALL principals, so N agents cannot each spend the cap.
# G11 is a check-then-act, and the write that would make the check true happens later, in
# observe(). Without a lock every concurrent caller reads the same stale spend. _INFLIGHT
# bridges the gap between granting and recording.
# RESIDUAL: this closes the IN-PROCESS race only. Separate processes sharing a trajectory
# file still race; that needs an OS-level file lock and is not done here.
_BUDGET_LOCK = threading.Lock()
_INFLIGHT: dict[str, int] = {}

MESH_DAILY_CAP = {
    "email:label": 40, "email:move": 40, "cal:hold": 5, "cal:create_hold": 5,
    "followup:send_known": 5, "web:fetch": 200, "act:propose": 20,
}


# ---------------------------------------------------------------- G9: carrying capacity
# G9 escalates "an egress CARRYING a tainted label". v2.0 approximated "carrying" as "in a
# tainted session", which is strictly over-broad: it made `df -h` DESTRUCTIVE whenever the
# session had earlier touched a PHI-labelled path, because every shell affordance is in
# EGRESS. That is not G9 being strict, it is the predicate being wrong -- `df -h` carries
# nothing. The first shadow run surfaced it immediately.
#
# Capacity is a CLOSER approximation of the real predicate: how much caller-controlled
# content this action's arguments could actually move. Two ways to get it right:
#
#   EXACT      the call site declares `derived_from` -- the labels of data that genuinely
#              flow into this action. Authoritative when present. This is the migration
#              target, and a wrong declaration is a call-site bug at the same trust level
#              as the call site's own code; it is not an attack surface this model closes.
#   FALLBACK   no declaration -> session taint, scaled by carrying capacity.
#
# RESIDUAL, STATED (GOVERNANCE_MODEL.md §7.7): a zero-capacity action can still leak at low
# bandwidth -- through which of several commands is chosen, or through timing. Capacity
# closes the high-bandwidth channel, not every channel. The alternative was a
# false-positive rate that guarantees the layer is never enforced, and a property you can
# actually turn on beats a stronger one you cannot.

CARRIER_HIGH = 0.5          # capacity at/above this -> DESTRUCTIVE; above 0 -> PROPOSE
_FREEFORM_MIN = 24          # below this many chars, an action cannot carry a real payload
_FREEFORM_HIGH = 200        # at/above this, treat the arguments as a full carrier

# Argument keys that hold a caller-authored payload by construction.
_CARRIER_KEYS = ("content", "body", "payload", "data", "text", "message", "html",
                 "attachment", "blob", "note", "comment", "description")
# Argument keys naming WHERE bytes go. For an egress the destination IS the channel, so any
# nonempty value here is a carrier regardless of length — a bare 22-char string in `url` is a
# request to a caller-chosen host, and the string travels with it. The freeform-LENGTH floor
# missed this: it assumed short == harmless, and a live red-team agent walked a canary out in
# sub-floor schemeless fragments through a tainted session. Length gates incidental text; a
# destination is never incidental.
# Only true DATA SINKS — a place caller bytes are delivered. Deliberately NOT `host` /
# `hostname` / `addr`: an ssh host is where you are authorized to RUN, not where secrets go,
# and including it re-broke the `df -h` false positive (the command's carrier is its `cmd`,
# already handled by the outbound-pattern and freeform rules).
_DESTINATION_KEYS = ("url", "uri", "to", "dest", "destination",
                     "recipient", "rcpt", "endpoint", "target")
# A URL query or fragment is an exfiltration channel however short it is.
_QUERY_RE = re.compile(r"[?&#][^=\s&#]+=")
# curl/scp-style payload flags.
_DATA_FLAG_RE = re.compile(r"(?:^|\s)(?:-d|--data(?:-[\w-]+)?|--form|-F|-T|--upload-file)\s")
# A long unbroken token is an encoded blob, whatever it claims to be.
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
# An outbound request to a caller-chosen destination. The DESTINATION is the channel here,
# not just the payload: `https://evil.com/<data-in-the-path>` has no query string and no
# long argument, but the path is caller-controlled content arriving at a third party. This
# is the gap the length- and query-based rules alone leave open, and it is the difference
# between `df -h` (runs on the box, output comes back to us -- carries nothing) and any
# outbound contact (something leaves, however short).
_OUTBOUND_RE = re.compile(r"https?://\S|\b(?:curl|wget|nc|netcat|ncat|telnet|scp|rsync|ftp)\b"
                          r"|\b[\w.-]+@[\w.-]+:", re.I)


def carrying_capacity(affordance: str, args: dict | None = None) -> tuple[float, str]:
    """How much caller-controlled content could this action actually move out? -> (0..1, why)

    Certain SHAPES are carriers by construction regardless of length -- a URL query, a POST
    body, a `-d` flag, an encoded blob. Everything else falls back to how much free-form
    string content the arguments hold."""
    args = args or {}
    cap, why = 0.0, "no caller-controlled content"

    def bump(v, reason):
        nonlocal cap, why
        if v > cap:
            cap, why = v, reason

    total = 0
    for k, v in args.items():
        if not isinstance(v, (str, bytes)):
            continue
        s = v.decode("utf-8", "replace") if isinstance(v, bytes) else v
        total += len(s)
        if str(k).lower() in _CARRIER_KEYS and s.strip():
            bump(0.7, f"'{k}' is a payload-bearing argument")
        if str(k).lower() in _DESTINATION_KEYS and s.strip():
            bump(0.7, f"'{k}' names a caller-chosen egress destination")
        if _QUERY_RE.search(s):
            bump(0.7, "a URL query/fragment carries caller-controlled content")
        if _DATA_FLAG_RE.search(s):
            bump(0.9, "an explicit payload flag (-d/--data/-T)")
        if _BLOB_RE.search(s):
            bump(0.9, "an encoded blob in the arguments")
        if _OUTBOUND_RE.search(s):
            bump(0.6, "an outbound request to a caller-chosen destination")

    if total >= _FREEFORM_MIN:
        span = _FREEFORM_HIGH - _FREEFORM_MIN
        bump(min(1.0, (total - _FREEFORM_MIN) / span),
             f"{total} chars of free-form argument content")
    return round(cap, 3), why


def _sniff(args: dict | None) -> set[str]:
    blob = json.dumps(args or {}, default=str)
    found = set()
    for label, pat in _LABEL_PATTERNS:
        if re.search(pat, blob, re.I):
            found.add(label)
    return found


def labels_for(affordance: str, args: dict | None = None, phi_node: bool = False) -> set[str]:
    """What sensitivity labels does running this action acquire? (G9)

    Fail-closed: an affordance we have never seen that is not obviously a read is assumed to
    touch PRIVATE data. Under-labelling is the failure that matters here — an unlabelled read
    is an egress waiting to happen."""
    base = LABELS_ACQUIRED.get(affordance)
    if base is None:
        base = set() if affordance.split(":")[-1] in (
            "ping", "disk", "mem", "top", "net", "gpu", "services", "metrics") else {PRIVATE}
    out = set(base) | _sniff(args)
    if phi_node:
        out.add(PHI)
    return out


# ---------------------------------------------------------------- trajectory store
def _loadl(path: str) -> list[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except (OSError, json.JSONDecodeError):
        return []


def observe(session: str, principal: str, affordance: str,
            labels: set[str] | None = None, args: dict | None = None,
            path: str | None = None) -> dict:
    """Record one step of a trajectory. Called by kernel AFTER a verdict is reached, so the
    record reflects what was actually attempted — including what was denied, because a
    denied attempt is evidence about the agent making it."""
    path = path or TRAJECTORY
    rec = {"ts": time.time(), "session": session, "principal": principal,
           "affordance": affordance,
           "labels": sorted(labels if labels is not None else labels_for(affordance, args))}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def _window(session: str | None, window_s: int, path: str | None = None) -> list[dict]:
    cutoff = time.time() - window_s
    return [r for r in _loadl(path or TRAJECTORY)
            if r.get("ts", 0) >= cutoff and (session is None or r.get("session") == session)]


def session_taint(session: str, window_s: int = WINDOW_S, path: str | None = None) -> set[str]:
    """Every sensitivity label acquired in this session's window. (G9)

    Monotone within the window on purpose: taint that decayed on a timer would just teach
    the system to wait."""
    out: set[str] = set()
    for r in _window(session, window_s, path):
        out |= set(r.get("labels", []))
    return out


def contributors(session: str, window_s: int = WINDOW_S, path: str | None = None) -> set[str]:
    """Every principal that has acted in this session's window. (G10)"""
    return {r["principal"] for r in _window(session, window_s, path) if r.get("principal")}


def effective_authority(principals: set[str]) -> tuple[str, str]:
    """Authority of a coalition = the MINIMUM over its members, never the maximum. (G10)

    This is the whole anti-laundering property. If a low-authority agent contributes to a
    session, everything downstream in that session inherits its ceiling — so routing a
    request through a trusted agent buys nothing, which removes the incentive to try."""
    if not principals:
        return UNKNOWN_AUTHORITY, "no identified principal"
    ceilings = {p: AUTHORITY.get(p, UNKNOWN_AUTHORITY) for p in principals}
    worst = min(ceilings.values(), key=lattice.rank)
    who = [p for p, c in ceilings.items() if c == worst]
    return worst, f"coalition ceiling set by {','.join(sorted(who))} ({worst})"


def mesh_spend(affordance: str, window_s: int = 86400, path: str | None = None) -> int:
    """How many times the WHOLE mesh has run this affordance today. (G11)"""
    return sum(1 for r in _window(None, window_s, path) if r.get("affordance") == affordance)


# ---------------------------------------------------------------- the layer
def gate(session: str, principal: str, affordance: str, args: dict | None = None,
         base_tier: str = lattice.AUTO, phi_node: bool = False,
         window_s: int = WINDOW_S, path: str | None = None,
         derived_from: set[str] | None = None) -> tuple[str, str]:
    """The composition layer's verdict. Layer 2 of kernel.authorize(). (G8-G11)

    Returns the meet of every composition rule with `base_tier`; it can only lower it.
    Fail-closed: an internal error is REFUSE."""
    try:
        reasons: list[str] = []
        verdict = base_tier

        prior = session_taint(session, window_s, path)
        here = labels_for(affordance, args, phi_node)

        # G9 — taint dominates tier, but only for an action that actually CARRIES something.
        # `derived_from`, when the call site declares it, is authoritative data-flow and
        # skips the heuristic entirely. Otherwise: session taint scaled by carrying capacity.
        cap, cap_why = carrying_capacity(affordance, args)
        if affordance in EGRESS:
            if derived_from is not None:
                carried = set(derived_from) & SENSITIVE
                if carried:
                    verdict = lattice.meet(verdict, lattice.DESTRUCTIVE)
                    reasons.append(f"G9 egress with DECLARED {'/'.join(sorted(carried))} data flow")
            else:
                carried = (prior | here) & SENSITIVE
                if carried and cap >= CARRIER_HIGH:
                    verdict = lattice.meet(verdict, lattice.DESTRUCTIVE)
                    reasons.append(f"G9 egress carrying {'/'.join(sorted(carried))} taint "
                                   f"(capacity {cap}: {cap_why})")
                elif carried and cap > 0:
                    verdict = lattice.meet(verdict, lattice.PROPOSE)
                    reasons.append(f"G9 egress with low carrying capacity {cap} under "
                                   f"{'/'.join(sorted(carried))} taint — human confirms")
                elif carried:
                    # Recorded, not escalated: a zero-capacity action moves no payload. The
                    # low-bandwidth residual is stated in GOVERNANCE_MODEL.md §7.7.
                    reasons.append(f"G9 noted: {'/'.join(sorted(carried))} taint in session but "
                                   f"this action carries nothing ({cap_why})")

        # G9 (reverse) — untrusted content may never become an instruction. Web and inbound
        # mail are data; a session that has ingested them cannot then act at AUTO on their say-so.
        if UNTRUSTED in prior and affordance not in LABELS_ACQUIRED:
            verdict = lattice.meet(verdict, lattice.PROPOSE)
            reasons.append("G9 session has ingested UNTRUSTED content — no autonomous act on it")

        # G10 — the coalition's ceiling, not the caller's.
        coalition = contributors(session, window_s, path) | {principal}
        ceiling, why = effective_authority(coalition)
        if lattice.rank(ceiling) < lattice.rank(verdict):
            verdict = lattice.meet(verdict, ceiling)
            reasons.append(f"G10 {why}")

        # G8 — split payload. A window that has both accumulated sensitive reads AND reached
        # an egress is the composite shape, whatever the individual tiers were.
        recent = _window(session, window_s, path)
        sensitive_reads = sum(1 for r in recent if set(r.get("labels", [])) & SENSITIVE)
        # Capacity-gated for the same reason G9 is: a split payload has to be carried by
        # something. Two sensitive reads followed by `df -h` is not a split payload.
        if affordance in EGRESS and sensitive_reads >= 2 and cap >= CARRIER_HIGH:
            # A declaration is a claim about THIS action's arguments; G8 is a claim about the
            # SEQUENCE. "nothing sensitive flows through me" is precisely what one step of a
            # split payload looks like from the inside, so a clean declaration downgrades this
            # to a human check rather than erasing it. Trusting the declaration completely here
            # would make G8 unreachable by exactly the traffic it exists to catch.
            declared_clean = derived_from is not None and not (set(derived_from) & SENSITIVE)
            floor = lattice.PROPOSE if declared_clean else lattice.DESTRUCTIVE
            verdict = lattice.meet(verdict, floor)
            reasons.append(f"G8 split-payload shape: {sensitive_reads} sensitive reads then an "
                           f"egress with {cap} carrying capacity"
                           + (" — declared clean, so a human confirms rather than a hard deny"
                              if declared_clean else ""))

        # G8 — velocity. A burst is a different act from a single call.
        if len(recent) >= VELOCITY_MAX:
            verdict = lattice.meet(verdict, lattice.PROPOSE)
            reasons.append(f"G8 velocity {len(recent)}/{window_s}s over threshold")

        # G11 — the mesh shares one budget. CHECK AND RESERVE ATOMICALLY: the spend is read
        # from the trajectory, which is only written AFTER the verdict, so N concurrent
        # callers all saw room and all passed. The red-team harness took 9 grants against a
        # cap of 3. `_INFLIGHT` counts grants that have not yet reached the trajectory.
        cap = MESH_DAILY_CAP.get(affordance)
        if cap is not None:
            with _BUDGET_LOCK:
                spent = mesh_spend(affordance, path=path) + _INFLIGHT.get(affordance, 0)
                if spent >= cap:
                    verdict = lattice.meet(verdict, lattice.PROPOSE)
                    reasons.append(f"G11 mesh budget spent for {affordance}: {spent}/{cap} today")
                elif verdict == lattice.AUTO:
                    _INFLIGHT[affordance] = _INFLIGHT.get(affordance, 0) + 1

        return verdict, ("; ".join(reasons) if reasons else "composition ok")
    except Exception as e:                                        # G2
        return lattice.REFUSE, f"composition layer failed closed: {str(e)[:80]}"


if __name__ == "__main__":
    import sys
    sess = sys.argv[2] if len(sys.argv) > 2 else "default"
    print(f"session      : {sess}")
    print(f"taint        : {', '.join(sorted(session_taint(sess))) or '(clean)'}")
    who = contributors(sess)
    print(f"contributors : {', '.join(sorted(who)) or '(none)'}")
    if who:
        c, why = effective_authority(who)
        print(f"ceiling      : {c} — {why}")
    print("mesh spend today:")
    for a, cap in MESH_DAILY_CAP.items():
        s = mesh_spend(a)
        if s:
            print(f"  {a:<24} {s}/{cap}")
