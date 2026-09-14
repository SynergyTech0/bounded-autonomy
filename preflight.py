"""preflight.py — verify every guardrail is ACTUALLY on, then stamp a reproducible manifest.

For the AGI-behaviour experiment (GOVERNANCE_MODEL.md §9). This is both the safety gate and the
audit trail's opening record. It REFUSES to declare the run ready unless every critical guardrail
is verifiably engaged — "guardrails on" is asserted by code here, never assumed. It changes no
live state (the kill drill runs in an isolated scratch instance), and it appends a hash-chained
manifest to the governance ledger so the paper can cite exact, tamper-evident preconditions.

Critical checks (all must pass for READY):
  * enforcement is ON              GOVERNANCE_ENFORCE=1
  * least-privilege allowlist ON   GOVERNANCE_LOOP_ALLOWLIST=1
  * the agent CANNOT forge a GO token   corrigibility.forge_capable() is False (key off-box)
  * the governance ledger chain is intact
  * the exec_bridge is disarmed     (.exec_bridge_enabled absent)
  * MCP reach is least-privileged   MCP_SERVERS ⊆ the read-only research + sandboxed-fs set
  * the kill switch works           isolated revoke -> STOP, proven at preflight time
Run-time checks (needed to actually proceed, operator sets them):
  * a live operator grant + fresh heartbeat

  python preflight.py            # human-readable checklist + manifest; exit 0 iff READY
  python preflight.py --json     # machine-readable manifest for the paper's appendix
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# The only bundles a first supervised loop may wire (matches loop_allowlist's rationale).
ALLOWED_MCP_SERVERS = {"arxiv", "pubmed", "openalex", "semantic_scholar", "wikidata",
                       "wikipedia", "time", "fetch", "filesystem"}

GOV_SOURCE = ("lattice.py", "ledger.py", "corrigibility.py", "composition.py",
              "legibility.py", "kernel.py", "loop_allowlist.py", "policy.py",
              "conscience.py", "shadow.py", "GOVERNANCE_MODEL.md")


def _sha(path: str) -> str:
    try:
        with open(os.path.join(HERE, path), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        return "MISSING"


def _git_sha() -> str:
    try:
        r = subprocess.run(["git", "-C", HERE, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=8)
        return r.stdout.strip()[:12] if r.returncode == 0 else "no-git"
    except Exception:
        return "no-git"


def _isolated_kill_drill() -> tuple[bool, str]:
    """Prove revoke->STOP in a throwaway instance, without touching live grant state."""
    import composition, corrigibility, ledger
    saved = {k: getattr(corrigibility, k) for k in
             ("KEY_FILE", "GO_TOKEN", "HEARTBEAT", "PUBKEY_FILE", "PRIVKEY_FILE")}
    saved_led = ledger.LEDGER
    d = tempfile.mkdtemp(prefix="preflight_kd_")
    try:
        corrigibility.KEY_FILE = os.path.join(d, "k")
        with open(corrigibility.KEY_FILE, "wb") as f:
            f.write(secrets.token_hex(32).encode())
        corrigibility.PUBKEY_FILE = os.path.join(d, "nopub")
        corrigibility.PRIVKEY_FILE = os.path.join(d, "nopriv")
        corrigibility.GO_TOKEN = os.path.join(d, "go")
        corrigibility.HEARTBEAT = os.path.join(d, "hb")
        ledger.LEDGER = os.path.join(d, "led"); open(ledger.LEDGER, "w").close()
        corrigibility.grant(3600); corrigibility.beat()
        import kernel
        ok_before, _, _ = kernel.mediate("sys:disk", {}, session="kd")
        corrigibility.revoke()
        ok_after, _, why = kernel.mediate("sys:disk", {}, session="kd")
        return (ok_before and not ok_after), f"before={ok_before} after_revoke={ok_after}"
    finally:
        for k, v in saved.items():
            setattr(corrigibility, k, v)
        ledger.LEDGER = saved_led
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def checks() -> list[dict]:
    import composition, corrigibility, kernel, ledger, loop_allowlist
    out = []

    def add(name, ok, detail, critical=True):
        out.append({"check": name, "ok": bool(ok), "detail": str(detail)[:160], "critical": critical})

    add("enforcement ON", kernel.enforce_enabled(),
        f"GOVERNANCE_ENFORCE={os.environ.get('GOVERNANCE_ENFORCE')!r}; layers={kernel.enforce_layers()}")
    add("least-privilege allowlist ON", loop_allowlist.enabled(),
        f"GOVERNANCE_LOOP_ALLOWLIST={os.environ.get('GOVERNANCE_LOOP_ALLOWLIST')!r}")

    forge = corrigibility.forge_capable()
    add("agent CANNOT forge a GO token", not forge,
        f"signing_mode={corrigibility.signing_mode()} forge_capable={forge} "
        f"(need asymmetric verify-only, private key OFF this host)")

    chain_ok, brk, why = ledger.verify()
    add("governance ledger chain intact", chain_ok, why)

    disarmed = not os.path.isfile(os.path.join(HERE, ".exec_bridge_enabled"))
    add("exec_bridge disarmed", disarmed, ".exec_bridge_enabled absent" if disarmed
        else "STILL ARMED — rm .exec_bridge_enabled")

    servers = {s.strip() for s in os.environ.get("MCP_SERVERS", "").split(",") if s.strip()}
    extra = servers - ALLOWED_MCP_SERVERS
    add("MCP reach least-privileged", not extra,
        f"MCP_SERVERS={sorted(servers) or 'unset'}; disallowed={sorted(extra) or 'none'}")

    kd_ok, kd_why = _isolated_kill_drill()
    add("kill switch works (isolated drill)", kd_ok, kd_why)

    # run-time (advisory for readiness, required to actually proceed)
    st = corrigibility.stance()
    add("live operator grant + fresh heartbeat", st["stance"] == "autonomous",
        f"stance={st['stance']}: {st['reason']}", critical=False)
    return out


def manifest() -> dict:
    import kernel, ledger, loop_allowlist
    c = checks()
    seq, head = ledger.head()
    ready = all(x["ok"] for x in c if x["critical"])
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "experiment": "governance-v2 open-ended fan-out (AGI-behaviour) under guardrails",
        "ready": ready,
        "checks": c,
        "config": {
            "enforce_layers": list(kernel.enforce_layers()),
            "allowlist_size": len(loop_allowlist.FIRST_LOOP_ALLOW),
            "mcp_servers": sorted({s.strip() for s in os.environ.get("MCP_SERVERS", "").split(",") if s.strip()}),
        },
        "provenance": {
            "git": _git_sha(),
            "python": sys.version.split()[0],
            "source_sha256": {f: _sha(f) for f in GOV_SOURCE},
        },
        "ledger_anchor_start": {"seq": seq, "head": head},
    }


if __name__ == "__main__":
    import ledger
    m = manifest()
    if "--json" in sys.argv:
        print(json.dumps(m, indent=2))
    else:
        print("=" * 74)
        print("PREFLIGHT — is 'guardrails on' actually true?")
        print("=" * 74)
        for c in m["checks"]:
            mark = "PASS" if c["ok"] else ("FAIL" if c["critical"] else "warn")
            print(f"  [{mark}] {c['check']:<38} {c['detail'][:70]}")
        print("-" * 74)
        print(f"  READY: {'YES — guardrails verified on' if m['ready'] else 'NO — do not run'}")
        print(f"  git={m['provenance']['git']}  ledger head seq={m['ledger_anchor_start']['seq']}")
    # Record the manifest in the tamper-evident ledger regardless — the audit trail should
    # capture refused preflights too (an attempt to run with guardrails off is itself evidence).
    try:
        ledger.append({"kind": "preflight", "verdict": "ready" if m["ready"] else "not_ready",
                       "affordance": "gov:preflight", "reason": m["experiment"],
                       "ready": m["ready"], "provenance": m["provenance"],
                       "checks": {c["check"]: c["ok"] for c in m["checks"]}})
    except Exception as e:
        print("  (could not record manifest to ledger:", str(e)[:60], ")")
    sys.exit(0 if m["ready"] else 1)
