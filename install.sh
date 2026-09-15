#!/usr/bin/env sh
# Bounded Autonomy — one-command bootstrap.
#
#   curl -fsSL https://raw.githubusercontent.com/SynergyTech0/bounded-autonomy/main/install.sh | sh
#     or: git clone https://github.com/SynergyTech0/bounded-autonomy && cd bounded-autonomy && sh install.sh
#
# What it does (and ONLY this): fetch the source, verify Python 3.11+, run the 24-invariant
# conformance suite so you can see the evidence yourself, and print how to wire the gate in.
# It installs nothing system-wide, uses no sudo, writes nothing outside the repo directory, and
# NEVER arms enforcement — the gate ships disarmed and stays that way until you say otherwise.
set -eu

REPO_URL="https://github.com/SynergyTech0/bounded-autonomy"
DIR="${1:-bounded-autonomy}"

say()  { printf '\033[36m▸\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$1"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# --- locate a python ---
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || die "Python 3.11+ is required and was not found on PATH."
"$PY" - <<'EOF' || die "Python 3.11+ is required (found an older interpreter)."
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)
EOF
ok "Python: $("$PY" -V 2>&1)"

# --- get the source (skip if we're already inside the repo) ---
if [ -f kernel.py ] && [ -f test_governance.py ]; then
  say "Already inside a Bounded Autonomy checkout — using it."
else
  command -v git >/dev/null 2>&1 || die "git is required to fetch the source."
  if [ -d "$DIR/.git" ]; then
    say "Updating existing checkout in ./$DIR"; ( cd "$DIR" && git pull --ff-only )
  else
    say "Cloning into ./$DIR"; git clone --depth 1 "$REPO_URL" "$DIR"
  fi
  cd "$DIR"
fi

# --- optional: note whether the asymmetric grant is available ---
if "$PY" -c "import cryptography" >/dev/null 2>&1; then
  ok "cryptography present — Ed25519 off-box grant available."
else
  say "cryptography not installed — the gate still runs (HMAC fallback: tamper-evident, not"
  say "  tamper-proof). For an off-box signing key: pip install cryptography"
fi

# --- run the evidence ---
say "Running the conformance suite (asserts on values, not exit codes)…"
"$PY" test_governance.py || die "Conformance suite did not pass — do not use this checkout."
ok "Conformance: all invariants passed."

printf '\n'
ok "Bounded Autonomy is ready (and DISARMED)."
cat <<'NEXT'

Next:
  python redteam.py                     # adversarial regression ratchet (0 bypasses)
  python kernel.py demo                 # the worked examples from the spec

Wire it into your agent (see adapters/README.md):
  from adapters.gate_middleware import Gate
  gate = Gate(principal="my-agent")
  r = gate.check("Bash", {"command": cmd})
  if r.allow: run(cmd)                  # AUTO, under a live off-box grant
  else:       route_or_refuse(r)        # PROPOSE -> human; DESTRUCTIVE/REFUSE -> blocked

Turn a key off-box before you ever arm enforcement:  see governance_operator.py + GOVERNANCE_MODEL.md §5
NEXT
