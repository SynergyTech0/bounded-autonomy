"""build_bundle.py — assemble a SECRET-FREE bundle to move into the escape-test VM. (sandbox harness)

Copying the repo as-is would carry `.env`, tokens, and the SSH key straight past the airgap —
the exact thing that must not happen. This builds a staging dir from an EXPLICIT allowlist of
clean code, excludes every secret/state/log/vcs artifact, and then SCANS the result for
credential material. If anything trips the scan, it ABORTS and ships nothing. Fail-closed:
a bundle is produced only if it is provably free of credentials.

Fleet-domain strings (example.com etc.) are REPORTED, not fatal — they appear
legitimately in denylists (research_proxy, corrigibility) and are harmless inside an isolated,
host-only VM. Actual credentials (keys, live tokens, password=value) are fatal.

  python build_bundle.py                 # build ./sandbox_bundle, or abort on a secret
  python build_bundle.py --out <dir>
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Explicit allowlist — governance + this harness. Known clean. The agent LOOP modules are added
# by name once each passes the scan; not assumed in.
INCLUDE = [
    "lattice.py", "ledger.py", "corrigibility.py", "composition.py", "legibility.py",
    "kernel.py", "loop_allowlist.py", "policy.py",
    "shadow.py", "agent_proposal.py", "preflight.py",
    "GOVERNANCE_MODEL.md", "METHODOLOGY.md",
    # add your own agent's conscience/ethics modules here once each passes the scan
]
# "youragent" is a placeholder for YOUR agent package (the code the governance gate mediates).
# Point this at your package; the resolver below follows its transitive local imports.
INCLUDE_DIRS = ["sandbox_harness", "youragent"]

# Never copy these, by name or glob, no matter what.
EXCLUDE_RE = re.compile(
    r"(^\.env|\.env$|\.env\.|(^|/)\.git(/|$)|__pycache__|\.pyc$|"
    r"\.governance_|governance_go\.json|governance_heartbeat\.json|governance_priv|"
    r"\.inbound_token|\.exec_bridge|autonomy_armed\.json|"
    r"id_rsa|id_ed25519|\.pem$|\.key$|credentials|"
    r"_log\.jsonl$|\.jsonl$|governance_ledger)", re.I)

# FATAL — actual credential material.
FATAL = [
    (r"sk_(live|test)_[A-Za-z0-9]{6,}", "stripe secret key"),
    (r"AKIA[0-9A-Z]{16}", "aws access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "github token"),
    (r"glpat-[A-Za-z0-9_-]{16,}", "gitlab token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack token"),
]
# Inline secret=value handled separately so a NARROW carve-out for localhost dev-defaults
# (postgres/postgres on 127.0.0.1 etc.) is informational, not fatal — those are not credentials
# worth protecting and are harmless in an isolated VM. Any other value stays fatal.
_INLINE_RE = re.compile(r"(?i)(password|passwd|api[_-]?key|secret|bearer|token)\s*[=:]\s*"
                        r"['\"]([^'\"]{6,})['\"]")
_DEV_DEFAULTS = {"postgres", "root", "admin", "password", "changeme", "example",
                 "localhost", "test", "guest", "user"}
# INFORMATIONAL — references to your own protected infrastructure (expected in denylists;
# harmless in an isolated VM). Replace this pattern with your own hostnames / IP ranges.
INFO = [(r"internal\.example\.com|emr\.example\.com|203\.0\.113\.\d+",
         "protected-infra reference (ok in denylists)")]


def closure(entry: str) -> list[str]:
    """Transitive LOCAL import closure of an entry module — the agent loop's whole dep web.

    Static (ast) resolution against files that actually exist in the repo; stdlib and
    third-party imports are ignored (they are installed in the VM, not shipped). This is how
    'include mind_loop and everything it needs' becomes a set the secret-scan can vet in full."""
    def local_imports(path):
        out = set()
        try:
            tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
        except Exception:
            return out
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    out.add(a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                out.add(n.module.split(".")[0])
                if n.module.startswith("youragent"):
                    out.add(n.module.split(".")[-1])
        return out
    def resolve(mod):
        # root-level module, package dir, OR package-nested under youragent/ (e.g. models.py)
        for c in (f"{mod}.py", os.path.join(mod, "__init__.py"),
                  os.path.join("youragent", f"{mod}.py"),
                  os.path.join("youragent", mod, "__init__.py")):
            if os.path.isfile(os.path.join(REPO, c)):
                return c
        return None
    seen, stack, found = set(), [entry], set()
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f); found.add(f)
        for m in (local_imports(os.path.join(REPO, f)) or set()):
            r = resolve(m)
            if r and r not in seen:
                stack.append(r)
    return sorted(found)


def _scan(path: str) -> tuple[list, list]:
    fatal, info = [], []
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return fatal, info
    for pat, name in FATAL:
        if re.search(pat, txt):
            fatal.append((os.path.relpath(path), name))
    # inline secret=value, with the localhost dev-default carve-out
    for m in _INLINE_RE.finditer(txt):
        val = m.group(2)
        if val.lower() in _DEV_DEFAULTS:
            info.append((os.path.relpath(path), f"localhost/dev-default {m.group(1).lower()} ('{val}')"))
        else:
            fatal.append((os.path.relpath(path), f"inline secret ({m.group(1).lower()}=...)"))
    for pat, name in INFO:
        if re.search(pat, txt):
            info.append((os.path.relpath(path), name))
    return fatal, info


def build(out: str, entry: str | None = None) -> int:
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(out)
    include = list(INCLUDE)
    if entry:
        dep = closure(entry)
        print(f"entry '{entry}' pulls a local dependency closure of {len(dep)} files")
        include = sorted(set(include) | set(dep))
    copied = []
    for f in include:
        src = os.path.join(REPO, f)
        if os.path.isfile(src) and not EXCLUDE_RE.search(f):
            dst = os.path.join(out, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied.append(f)
    out_abs = os.path.abspath(out)
    for d in INCLUDE_DIRS:
        for root, dirs, files in os.walk(os.path.join(REPO, d)):
            if os.path.abspath(root).startswith(out_abs):   # never recurse into the output dir
                dirs[:] = []
                continue
            for fn in files:
                rel = os.path.relpath(os.path.join(root, fn), REPO)
                if EXCLUDE_RE.search(rel):
                    continue
                dst = os.path.join(out, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(os.path.join(root, fn), dst)
                copied.append(rel)

    # Scan the STAGING dir — what would actually ship.
    all_fatal, all_info = [], []
    for root, _, files in os.walk(out):
        for fn in files:
            fa, inf = _scan(os.path.join(root, fn))
            all_fatal += fa
            all_info += inf

    print(f"staged {len(copied)} file(s) into {out}")
    for p, why in all_info:
        print(f"  info : {p} — {why}")
    if all_fatal:
        print("\n  ABORT — credential material found; shipping nothing:")
        for p, why in all_fatal:
            print(f"  FATAL: {p} — {why}")
        shutil.rmtree(out)
        return 1
    print("\n  CLEAN — no credential material. Bundle is safe to move into the isolated VM.")
    print("  (Add agent-loop modules by name to INCLUDE and re-run; each is scanned the same way.)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(REPO, "sandbox_bundle"))
    ap.add_argument("--entry", default=None,
                    help="entry module (e.g. mind_loop.py) — pulls its full local dep closure")
    a = ap.parse_args()
    raise SystemExit(build(a.out, a.entry))
