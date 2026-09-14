#!/usr/bin/env python3
"""governance_operator.py — the OPERATOR half of Governance v2, to be run OFF the agent host.

This is the other end of `corrigibility.py`. It holds the Ed25519 private key and is the only
thing that can mint a GO token or a heartbeat; the agent host keeps the PUBLIC key and can
therefore verify one but never forge one. That asymmetry is the whole of G13 — with the private
key co-located, corrigibility reports `forge_capable: True` and the brake is tamper-EVIDENT
rather than tamper-proof.

Deliberately standalone: no import of the mind's code, so the operator side keeps working even if
the agent framework is broken, mid-refactor, or absent. The only contract it must honour is the document
format, which corrigibility._verify_signed reads:

    {"payload": {...}, "sig": "<hex ed25519 over _canon(payload)>"}
    _canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()

Keys and signatures are NEVER printed. Files are written 0600.

  python3 governance_operator.py keygen                 # once; keep priv here, ship pub to the agent
  python3 governance_operator.py grant 8h               # mint a GO token
  python3 governance_operator.py heartbeat              # "I am here and watching"
  python3 governance_operator.py show                   # what is currently minted (no secrets)
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
PRIV = os.environ.get("GOVERNANCE_PRIVKEY_FILE", os.path.join(HERE, "governance_priv.hex"))
PUB = os.environ.get("GOVERNANCE_PUBKEY_FILE", os.path.join(HERE, "governance_pub.hex"))
GO = os.path.join(HERE, "governance_go.json")
BEAT = os.path.join(HERE, "governance_heartbeat.json")

# Must match corrigibility.MAX_GRANT_S — the agent enforces its own cap, but an operator tool that
# offers a longer grant than the agent will honour just produces confusing failures.
MAX_GRANT_S = 7 * 24 * 3600


def _canon(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _write_600(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def _priv() -> Ed25519PrivateKey:
    try:
        with open(PRIV, encoding="utf-8") as f:
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    except FileNotFoundError:
        sys.exit(f"no private key at {PRIV} — run `keygen` here first (this is the operator host)")


def _sign_doc(path: str, payload: dict) -> None:
    sig = _priv().sign(_canon(payload)).hex()
    _write_600(path, json.dumps({"payload": payload, "sig": sig}, indent=2))


def keygen() -> None:
    if os.path.exists(PRIV):
        sys.exit(f"refusing to overwrite an existing private key at {PRIV}\n"
                 f"  A new key invalidates every token the agent host currently trusts.\n"
                 f"  Move the old one aside deliberately if that is what you intend.")
    priv = Ed25519PrivateKey.generate()
    _write_600(PRIV, priv.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption()).hex())
    _write_600(PUB, priv.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw).hex())
    print(f"private key -> {PRIV}  (0600, NEVER leaves this host)")
    print(f"public  key -> {PUB}   (ship THIS to the agent host as .governance_pub)")


def grant(spec: str) -> None:
    s = spec.strip().lower()
    mult = {"h": 3600, "m": 60, "d": 86400}.get(s[-1:], 1)
    secs = int(float(s[:-1] if s[-1:] in "hmd" else s) * mult)
    secs = min(secs, MAX_GRANT_S)
    now = time.time()
    payload = {"iss": "operator", "scope": "autonomy", "issued": now,
               "not_after": now + secs, "nonce": secrets.token_hex(8)}
    _sign_doc(GO, payload)
    print(f"GO token -> {GO}")
    print(f"  scope autonomy, valid {secs // 3600}h, until "
          f"{datetime.fromtimestamp(payload['not_after'], timezone.utc).isoformat(timespec='seconds')}")


def heartbeat() -> None:
    _sign_doc(BEAT, {"iss": "operator", "ts": time.time()})
    print(f"heartbeat -> {BEAT}")
    print("  agent stays AUTONOMOUS while this is < 24h old, PROPOSE < 72h, then STOP")


def show() -> None:
    for label, path in (("GO token", GO), ("heartbeat", BEAT)):
        try:
            with open(path, encoding="utf-8") as f:
                p = json.load(f)["payload"]
        except (FileNotFoundError, KeyError, ValueError):
            print(f"{label:10} (none)")
            continue
        if "not_after" in p:
            left = p["not_after"] - time.time()
            print(f"{label:10} {'valid' if left > 0 else 'EXPIRED'}, {left / 3600:.1f}h remaining")
        else:
            print(f"{label:10} {(time.time() - p['ts']) / 3600:.1f}h old")
    print(f"private key present here: {os.path.exists(PRIV)}")


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    if cmd == "keygen":
        keygen()
    elif cmd == "grant":
        grant(sys.argv[2] if len(sys.argv) > 2 else "8h")
    elif cmd == "heartbeat":
        heartbeat()
    elif cmd == "show":
        show()
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
