"""corrigibility.py — the operator's ability to stop, observe, and revert. (governance v2)

GOVERNANCE_MODEL.md §5 — invariants G12, G13, G14, G15.

The finding this repairs (F1): v1's kill switch is a file the governed system can create.
`autonomy_gate.arm()` writes `.autonomy_enabled` itself, and global-on is
`isfile(ENABLED) or env == "1"`. Nothing authenticates it.

The fix is not a better-hidden switch. It is a POLARITY INVERSION (G13):

    v1:  autonomy runs until something turns it off   -> forging "on" is enough
    v2:  autonomy is off until something proves it on -> there is nothing to forge,
                                                         because absence IS the deny state

So autonomy requires a live, operator-SIGNED, EXPIRING grant. No token, expired token, bad
signature, malformed token, broken ledger, stale heartbeat -> STOP. Every failure mode of
the mechanism lands on stop, which is the only defensible default for a stop mechanism.

Three further properties:
  G12 the governance surface (switches, gates, values, audit, credentials, self-scheduling)
      is categorically DESTRUCTIVE and can never be reached autonomously, by any track record.
  G14 silence is not consent: without a fresh operator heartbeat, autonomy DECAYS
      AUTONOMOUS -> PROPOSE -> STOP.
  G15 a broken ledger chain halts autonomy (it does not halt the human — see below).

WHAT A STOP DOES AND DOES NOT STOP. A STOP stance denies AUTONOMOUS action only. It never
blocks the operator from acting or approving. Blocking the human on a governance failure
would reduce operator control — which is precisely the thing corrigibility exists to
protect. A safety mechanism that locks out the safety operator is not a safety mechanism.

KEY PLACEMENT IS THE WHOLE PROPERTY (GOVERNANCE_MODEL.md §7.4). On a single-user host, a
process running as the operator can read a co-located key and mint its own GO token. This
module WARNS when the key sits inside the agent's reach and reports `key_colocated` on
every stance, so the weakness is never silent. G13 holds cryptographically only when the
key lives in another account, an HSM, or off-box.

  python corrigibility.py stance                 # why autonomy is or is not permitted
  python corrigibility.py grant 8h               # operator: mint a GO token (needs the key)
  python corrigibility.py heartbeat              # operator: I am here and watching
  python corrigibility.py revoke                 # operator: stop now
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import unicodedata
import time

import lattice
import ledger

HERE = os.path.dirname(os.path.abspath(__file__))

# The operator's signing key. Point GOVERNANCE_KEY_FILE at a path OUTSIDE this tree — a
# different account's home, a mounted secret, an HSM-backed file. The default is inside the
# tree only so the module is runnable out of the box; that placement is reported as weak.
KEY_FILE = os.environ.get("GOVERNANCE_KEY_FILE", os.path.join(HERE, ".governance_key"))
GO_TOKEN = os.environ.get("GOVERNANCE_GO_TOKEN", os.path.join(HERE, "governance_go.json"))
HEARTBEAT = os.environ.get("GOVERNANCE_HEARTBEAT", os.path.join(HERE, "governance_heartbeat.json"))

# G14 decay thresholds, in seconds since the last SIGNED operator heartbeat.
HEARTBEAT_WARM = int(os.environ.get("GOVERNANCE_HB_WARM", 24 * 3600))    # < warm  -> AUTONOMOUS
HEARTBEAT_COLD = int(os.environ.get("GOVERNANCE_HB_COLD", 72 * 3600))    # < cold  -> PROPOSE
                                                                        # >= cold -> STOP
MAX_GRANT_S = int(os.environ.get("GOVERNANCE_MAX_GRANT", 7 * 24 * 3600))  # no indefinite GO

STOP, SUPERVISED, AUTONOMOUS = "stop", "supervised", "autonomous"

# ---------------------------------------------------------------- G12: the governance surface
# Affordances that act ON the governance machinery itself. Categorically DESTRUCTIVE, and
# never autonomously reachable — no approval rate, no tier promotion, no armed flag.
GOVERNANCE_AFFORDANCES = {
    "forge:install",        # installing executable code into the mind
    "heal:destroy",
    "schedule:create",      # the system giving ITSELF a new standing autonomous surface
    "schedule:delete",      # ...or removing one the operator relies on to observe it
    "gov:arm", "gov:grant", "gov:revoke", "gov:heartbeat", "gov:override",
}

# Paths that ARE the governance surface. Any action whose arguments mention one of these is
# acting on the gates, whatever affordance it claims to be.
GOVERNANCE_PATHS = (
    ".autonomy_enabled", "autonomy_armed.json", "autonomy_log.jsonl",
    "governance_ledger.jsonl", "governance_go.json", "governance_heartbeat.json",
    ".governance_key", "ethics_overrides.json",
    "ethics_core.py", "conscience.py", "policy.py", "autonomy_gate.py",
    "approval_record.py", "kernel.py", "corrigibility.py", "composition.py",
    "legibility.py", "lattice.py", "ledger.py",
)

# Credential-bearing surfaces: reading these is how a system would acquire the ability to
# act outside the mediated path, which is an interruptibility loss (G12).
CREDENTIAL_PATTERNS = (
    r"\.env\b", r"\bid_rsa\b", r"\bid_ed25519\b", r"\bauthorized_keys\b",
    r"\.pem\b", r"\bcredentials\b", r"\bsecrets?_?(store|vault|file)\b",
    r"\bAPI_?KEY\b", r"\bTOKEN\b", r"\bPASSWORD\b",
)

_SURFACE_RE = re.compile("|".join(re.escape(p) for p in GOVERNANCE_PATHS), re.I)
_CRED_RE = re.compile("|".join(CREDENTIAL_PATTERNS), re.I)


_PATH_TOKEN = re.compile(r"[\w./\\~$*?-]{2,}")


def _flatten(args) -> str:
    """Flatten arguments to raw text WITHOUT JSON-encoding them.

    json.dumps was the original flattener and it defeated two of the checks below: it doubles
    backslashes (so one unescape pass still leaves `poli\\cy.py`) and, with ensure_ascii, turns
    a fullwidth `ｐ` into the literal `\\uff50` — so NFKC normalisation never saw the character
    it exists to fold. Both evasions survived the first round of hardening for that reason
    alone. Serialise for the eye of the checker, not for the wire."""
    out: list[str] = []

    def walk(v):
        if isinstance(v, dict):
            for k, vv in v.items():
                out.append(str(k))
                walk(vv)
        elif isinstance(v, (list, tuple, set)):
            for vv in v:
                walk(vv)
        elif isinstance(v, bytes):
            out.append(v.decode("utf-8", "replace"))
        else:
            out.append(str(v))

    walk(args or {})
    return " ".join(out)


def _protected_names() -> tuple[str, ...]:
    """The static module names PLUS the paths this instance is ACTUALLY configured with.

    GOVERNANCE_PATHS alone is name-based, and §5 explicitly recommends moving the signing key
    somewhere else via GOVERNANCE_KEY_FILE — which silently removed it from protection,
    because the new name was not in the list. Following the model's own hardening advice made
    the model weaker. The red-team harness read the relocated key straight through the tool
    surface. Resolve the live configuration at call time instead of baking it in at import."""
    names = list(GOVERNANCE_PATHS)
    for p in (KEY_FILE, GO_TOKEN, HEARTBEAT):
        if p:
            names.append(p)
    for mod, attr in (("ledger", "LEDGER"), ("composition", "TRAJECTORY")):
        try:
            names.append(getattr(__import__(mod), attr))
        except Exception:
            pass
    return tuple(n for n in names if n)


def _normalize(blob: str) -> str:
    """Undo what a shell undoes, so the check sees the path the shell will actually open.

    `cat po''licy.py`, `cat poli\\cy.py` and `cat $(echo policy.py)` all open policy.py. A raw
    substring match sees three different strings and misses all but the last."""
    s = unicodedata.normalize("NFKC", blob)
    s = s.replace("''", "").replace('""', "")
    s = re.sub(r"\\(.)", r"\1", s)                          # strip backslash escapes
    s = re.sub(r"\$\((?:\s*echo\s+)?([^)]*)\)", r"\1", s)   # $(echo x) -> x
    s = re.sub(r"\$\{?(\w+)\}?", r"\1", s)                  # $f -> f (crude, deliberately)
    return re.sub(r"\s+", " ", s)


def _basename_hit(blob: str, names) -> str:
    """Compare the BASENAME of every path-like token against the protected set.

    Catches traversal (`../key`, `vault/../key`) which a substring check on the configured
    full path misses entirely. Exact basename comparison, not substring, so `monkey` does not
    collide with a protected file called `key`."""
    protected = {os.path.basename(n).lower() for n in names if n}
    for tok in _PATH_TOKEN.findall(blob):
        b = os.path.basename(tok.rstrip("/\\")).lower()
        if b and b in protected:
            return f"path token '{tok}' resolves to protected name '{b}'"
    return ""


def _glob_hit(blob: str, names) -> str:
    """Does a wildcard in the payload match a protected name? `cat p*licy.py` opens it."""
    protected = {os.path.basename(n).lower() for n in names if n}
    for tok in re.findall(r"[^\s'\";|&]*[*?][^\s'\";|&]*", blob):
        base = os.path.basename(tok)
        try:
            pat = re.compile("^" + re.escape(base).replace(r"\*", ".*").replace(r"\?", ".") + "$")
        except re.error:
            continue
        for n in protected:
            if pat.match(n):
                return f"glob '{tok}' matches protected name '{n}'"
    return ""


def touches_governance_surface(affordance: str, args: dict | None = None) -> tuple[bool, str]:
    """Does this action act on the machinery that governs it? (G12)

    Checks the affordance name AND the flattened arguments, because the interesting attack is
    not `gov:override` — nobody declares that. It is `sys:exec` with `rm .autonomy_enabled` in
    the payload, or an innocuous file write whose path happens to be `policy.py`.

    Four passes, because one substring match over the raw payload was evaded by shell quoting,
    backslash escapes, globs, unicode width variants and `..` traversal — all confirmed by the
    red-team harness against the live surface."""
    if affordance in GOVERNANCE_AFFORDANCES:
        return True, f"{affordance} acts on the governance surface"

    raw = _flatten(args)
    names = _protected_names()
    norm = _normalize(raw)

    for label, blob in (("arguments", raw), ("de-quoted arguments", norm)):
        m = _SURFACE_RE.search(blob)
        if m:
            return True, f"{label} reference the governance surface: {m.group(0)}"
        m = _CRED_RE.search(blob)
        if m:
            return True, f"{label} reference credentials: {m.group(0)}"

    for blob in (raw, norm):
        hit = _basename_hit(blob, names) or _glob_hit(blob, names)
        if hit:
            return True, f"governance surface via {hit}"
    return False, ""


# ---------------------------------------------------------------- G13: the signed GO grant
#
# TWO SCHEMES. HMAC (symmetric) is the default and is fine when the key is genuinely
# unreadable by the agent (a separate OS account / host). But symmetric crypto CANNOT give
# "verify-yes, forge-no" to a process that holds the key: whoever can check a token can mint
# one. For a max-capability agent that might escape mediation and read its own filesystem,
# that is the whole ballgame.
#
# ASYMMETRIC (Ed25519) is the real fix and the one to use for the AGI-behaviour test. The
# OPERATOR holds the PRIVATE key OFF-BOX and signs GO tokens + heartbeats there. The agent
# host holds ONLY the PUBLIC key: it can verify a token is genuine but can never produce one.
# "Key off-box" only means something in this scheme — under HMAC, off-box just breaks verify.
#
#   GOVERNANCE_PUBKEY_FILE   agent-side public key (hex). Present -> asymmetric VERIFY mode.
#   GOVERNANCE_PRIVKEY_FILE  operator-side private key (hex). Read ONLY to sign (grant/beat).
#                            On the agent host this file must NOT exist / not be readable.
PUBKEY_FILE = os.environ.get("GOVERNANCE_PUBKEY_FILE", os.path.join(HERE, ".governance_pub"))
PRIVKEY_FILE = os.environ.get("GOVERNANCE_PRIVKEY_FILE", os.path.join(HERE, ".governance_priv"))

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature
    _HAVE_ED = True
except Exception:
    _HAVE_ED = False


def _read_hex(path: str) -> bytes | None:
    try:
        with open(path, encoding="utf-8") as f:
            return bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        return None


def _key() -> bytes | None:
    try:
        with open(KEY_FILE, "rb") as f:
            k = f.read().strip()
        return k or None
    except OSError:
        return None


def signing_mode() -> str:
    """Which scheme is active, from what this host actually holds. Reported on every stance."""
    if _HAVE_ED and os.path.isfile(PUBKEY_FILE):
        return "asymmetric"
    if _key():
        return "hmac"
    return "none"


def forge_capable() -> bool:
    """Can THIS host mint a valid GO token? The secure posture for the agent is False.

    True whenever the host holds a symmetric HMAC key, or (in asymmetric mode) a readable
    private key. False only in asymmetric verify-only mode: public key present, no private
    key readable. This is the property that actually matters — `key_colocated` is a weaker
    path check kept for the HMAC case. Fail-closed: on any doubt, assume forge-capable."""
    try:
        mode = signing_mode()
        if mode == "asymmetric":
            return _read_hex(PRIVKEY_FILE) is not None       # holding the private key = can forge
        if mode == "hmac":
            return True                                       # symmetric: verify == forge
        return True                                           # no key -> can't verify anyway; unsafe
    except Exception:
        return True


def key_colocated() -> bool:
    """True when a signing secret this host could forge with sits inside the agent's tree.

    Extended to the asymmetric case: a PRIVATE key inside the tree is the danger; a public
    key there is fine. Reported on every stance so a green line never hides the caveat."""
    try:
        if signing_mode() == "asymmetric":
            priv = os.path.abspath(PRIVKEY_FILE)
            return os.path.isfile(PRIVKEY_FILE) and priv.startswith(os.path.abspath(HERE) + os.sep)
        return os.path.abspath(KEY_FILE).startswith(os.path.abspath(HERE) + os.sep)
    except Exception:
        return True          # can't tell -> assume the weak case (G2)


def _canon(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _sign(payload: dict, key: bytes) -> str:
    return hmac.new(key, _canon(payload), hashlib.sha256).hexdigest()


def _verify_signed(path: str) -> tuple[bool, dict, str]:
    """Read and authenticate a signed operator document. -> (ok, payload, reason).

    Asymmetric when a public key is present (verify with the public key — cannot forge),
    else HMAC. Fail-closed on EVERY path: missing key, missing/malformed doc, absent or bad
    signature. There is deliberately no branch that returns ok on doubt."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        payload, sig = doc["payload"], doc["sig"]
    except FileNotFoundError:
        return False, {}, f"no signed document at {os.path.basename(path)}"
    except (OSError, KeyError, ValueError, TypeError) as e:
        return False, {}, f"malformed signed document: {str(e)[:60]}"

    mode = signing_mode()
    if mode == "asymmetric":
        pub_hex = _read_hex(PUBKEY_FILE)
        if not pub_hex:
            return False, {}, "no operator public key available"
        try:
            Ed25519PublicKey.from_public_bytes(pub_hex).verify(bytes.fromhex(str(sig)), _canon(payload))
        except (InvalidSignature, ValueError):
            return False, {}, "signature does not verify — forged or key changed"
        return True, payload, "signature ok (ed25519)"

    key = _key()
    if not key:
        return False, {}, "no operator signing key available"
    if not hmac.compare_digest(_sign(payload, key), str(sig)):
        return False, {}, "signature does not verify — forged or key changed"
    return True, payload, "signature ok (hmac)"


def go_token() -> tuple[bool, dict, str]:
    """Is there a live, authenticated GO grant? (G13) Absence is the deny state."""
    ok, payload, reason = _verify_signed(GO_TOKEN)
    if not ok:
        return False, {}, reason
    try:
        not_after = float(payload["not_after"])
    except (KeyError, TypeError, ValueError):
        return False, {}, "grant has no usable expiry"
    if not_after <= time.time():
        age = int(time.time() - not_after)
        return False, payload, f"grant expired {age // 3600}h ago"
    if not_after - float(payload.get("issued", 0)) > MAX_GRANT_S:
        return False, payload, "grant exceeds the maximum duration — refusing an indefinite GO"
    return True, payload, f"valid for {int((not_after - time.time()) // 60)} more minutes"


def heartbeat_age() -> tuple[float | None, str]:
    """Seconds since the last AUTHENTICATED operator heartbeat. (G14)

    Signed for the same reason the grant is: an unsigned heartbeat is one the system can
    write for itself, which would let it convert its own silence into consent."""
    ok, payload, reason = _verify_signed(HEARTBEAT)
    if not ok:
        return None, reason
    try:
        return max(0.0, time.time() - float(payload["ts"])), "ok"
    except (KeyError, TypeError, ValueError):
        return None, "heartbeat has no usable timestamp"


# ---------------------------------------------------------------- the stance
def stance() -> dict:
    """May the system act autonomously at all, and why? (G13 + G14 + G15)

    Order matters: ledger integrity is checked FIRST, because a broken chain means the
    evidence for every other check is untrustworthy. Returns the decayed stance plus the
    full reasoning, so the dashboard and the CLI can show WHY autonomy is off rather than
    just that it is."""
    detail = {"key_colocated": key_colocated(), "key_file": KEY_FILE,
              "signing_mode": signing_mode(), "forge_capable": forge_capable()}

    chain_ok, brk, chain_reason = ledger.verify()
    detail["ledger"] = chain_reason
    if not chain_ok:
        return {"stance": STOP, "reason": f"governance ledger broken at seq {brk} — {chain_reason}",
                "ceiling": lattice.REFUSE, **detail}

    ok, payload, reason = go_token()
    detail["grant"] = reason
    if not ok:
        return {"stance": STOP, "reason": f"no live operator grant: {reason}",
                "ceiling": lattice.PROPOSE, **detail}

    age, hb_reason = heartbeat_age()
    detail["heartbeat"] = hb_reason if age is None else f"{int(age // 3600)}h old"
    if age is None:
        return {"stance": STOP, "reason": f"no authenticated operator heartbeat: {hb_reason}",
                "ceiling": lattice.PROPOSE, **detail}
    if age >= HEARTBEAT_COLD:
        return {"stance": STOP, "reason": f"operator silent for {int(age // 3600)}h — autonomy decayed to stop",
                "ceiling": lattice.PROPOSE, **detail}
    if age >= HEARTBEAT_WARM:
        return {"stance": SUPERVISED, "reason": f"operator silent for {int(age // 3600)}h — decayed to propose-only",
                "ceiling": lattice.PROPOSE, **detail}
    return {"stance": AUTONOMOUS, "reason": "live grant and fresh operator heartbeat",
            "ceiling": lattice.AUTO, **detail}


def gate(affordance: str, args: dict | None = None, autonomous: bool = True) -> tuple[str, str]:
    """The corrigibility layer's verdict. Layer 0 of kernel.authorize(). (G12 + G13 + G14 + G15)

    Fail-closed: any internal error is REFUSE. This layer decides whether the system may act
    at all, so a bug here must not resolve in the permissive direction."""
    try:
        touches, why = touches_governance_surface(affordance, args)
        if touches:
            # G12. Human-only, always. If the system is proposing it AUTONOMOUSLY, that is
            # itself the thing the invariant forbids, so it does not even reach a human queue.
            if autonomous:
                return lattice.REFUSE, f"G12 governance surface, autonomously attempted: {why}"
            return lattice.DESTRUCTIVE, f"G12 governance surface — operator only: {why}"

        if not autonomous:
            # An operator-driven action is not gated by the operator's own presence.
            return lattice.AUTO, "operator-driven; corrigibility gates autonomy only"

        st = stance()
        if st["stance"] == STOP:
            # Return the stance's CEILING, not a blanket REFUSE. The distinction matters and
            # is the whole of §5: a missing grant or a silent operator means "this cannot be
            # AUTONOMOUS" (ceiling PROPOSE — it queues for a human, exactly as v1 would). A
            # broken ledger means "the record this decision would rest on is untrustworthy"
            # (ceiling REFUSE — do not even queue it, because the queue's provenance is in
            # question). Collapsing both to REFUSE would brick the ordinary propose path on
            # a fresh install and make a safety mechanism look like a fault.
            return st["ceiling"], f"G13/G14/G15 autonomy stopped: {st['reason']}"
        if st["stance"] == SUPERVISED:
            return st["ceiling"], f"G14 decayed to supervised: {st['reason']}"
        return lattice.AUTO, "corrigibility ok: " + st["reason"]
    except Exception as e:                                        # G2
        return lattice.REFUSE, f"corrigibility layer failed closed: {str(e)[:80]}"


# ---------------------------------------------------------------- operator CLI
def keygen(out_dir: str | None = None) -> tuple[str, str]:
    """OPERATOR, RUN OFF-BOX. Mint an Ed25519 keypair. Returns (priv_path, pub_path).

    Ship ONLY the public file to the agent host (set GOVERNANCE_PUBKEY_FILE to it). Keep the
    private file on the operator's own machine (set GOVERNANCE_PRIVKEY_FILE there). The agent
    host must never hold the private key — that is the whole point. Neither key is printed."""
    if not _HAVE_ED:
        raise RuntimeError("cryptography/ed25519 not available")
    out_dir = out_dir or HERE
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    from cryptography.hazmat.primitives import serialization
    priv_hex = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()).hex()
    pub_hex = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    pp = os.path.join(out_dir, "governance_priv.hex")
    kp = os.path.join(out_dir, "governance_pub.hex")
    with open(pp, "w", encoding="utf-8") as f:
        f.write(priv_hex)
    with open(kp, "w", encoding="utf-8") as f:
        f.write(pub_hex)
    try:
        os.chmod(pp, 0o600)
    except OSError:
        pass
    return pp, kp


def _write_signed(path: str, payload: dict) -> bool:
    """Sign an operator document. Asymmetric (private key) when in ed25519 mode, else HMAC.

    This is the OPERATOR side (grant/beat). On the agent host in verify-only mode there is no
    private key here, so this correctly fails — the agent cannot mint tokens, by design."""
    if signing_mode() == "asymmetric" or (_HAVE_ED and os.path.isfile(PRIVKEY_FILE)):
        priv_hex = _read_hex(PRIVKEY_FILE)
        if not priv_hex:
            print(f"asymmetric mode but no private key readable at {PRIVKEY_FILE}.\n"
                  f"  Sign on the operator host that holds it. The agent host cannot (by design).")
            return False
        sig = Ed25519PrivateKey.from_private_bytes(priv_hex).sign(_canon(payload)).hex()
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "sig": sig}, f, indent=2)
        return True
    key = _key()
    if not key:
        print(f"no signing key. For the AGI-behaviour test use asymmetric keys OFF-BOX:\n"
              f"  (operator host) python corrigibility.py keygen\n"
              f"  ship governance_pub.hex to the agent host, set GOVERNANCE_PUBKEY_FILE\n"
              f"  keep governance_priv.hex on the operator host, set GOVERNANCE_PRIVKEY_FILE")
        return False
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"payload": payload, "sig": _sign(payload, key)}, f, indent=2)
    return True


def grant(duration_s: int, scope: str = "autonomy") -> bool:
    """Operator: mint a GO token. Bounded by MAX_GRANT_S — there is no indefinite grant."""
    duration_s = min(int(duration_s), MAX_GRANT_S)
    now = time.time()
    payload = {"iss": "operator", "scope": scope, "issued": now,
               "not_after": now + duration_s, "nonce": secrets.token_hex(8)}
    if not _write_signed(GO_TOKEN, payload):
        return False
    ledger.append({"kind": "grant", "verdict": "granted", "affordance": "gov:grant",
                   "reason": f"operator granted {scope} for {duration_s // 3600}h",
                   "not_after": payload["not_after"]})
    return True


def revoke() -> None:
    """Operator: stop now. Removing the grant is sufficient — absence is the deny state."""
    for p in (GO_TOKEN,):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    ledger.append({"kind": "revoke", "verdict": "stopped", "affordance": "gov:revoke",
                   "reason": "operator revoked the autonomy grant"})


def beat() -> bool:
    """Operator: I am here and watching. Resets the G14 decay clock."""
    ok = _write_signed(HEARTBEAT, {"iss": "operator", "ts": time.time()})
    if ok:
        ledger.append({"kind": "heartbeat", "verdict": "ok", "affordance": "gov:heartbeat",
                       "reason": "operator heartbeat"})
    return ok


_DUR = {"h": 3600, "m": 60, "d": 86400}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stance"
    if cmd == "stance":
        st = stance()
        print(f"STANCE   : {st['stance'].upper()}")
        print(f"WHY      : {st['reason']}")
        print(f"ceiling  : {st['ceiling']}")
        for k in ("ledger", "grant", "heartbeat", "signing_mode", "forge_capable"):
            if k in st:
                print(f"{k:<13}: {st[k]}")
        if st.get("forge_capable"):
            print("\n  WARNING: this host can MINT its own GO token "
                  f"(signing_mode={st['signing_mode']}). G13 is tamper-EVIDENT, not tamper-proof.\n"
                  "  For the AGI-behaviour test, switch to asymmetric verify-only:\n"
                  "    (operator host)  python corrigibility.py keygen\n"
                  "    ship governance_pub.hex here -> set GOVERNANCE_PUBKEY_FILE\n"
                  "    keep governance_priv.hex OFF this host -> set GOVERNANCE_PRIVKEY_FILE there")
        else:
            print("\n  OK: verify-only posture — this host can check GO tokens but cannot mint them.")
    elif cmd == "keygen":
        pp, kp = keygen(sys.argv[2] if len(sys.argv) > 2 else None)
        print(f"private key (KEEP OFF THE AGENT HOST): {pp}")
        print(f"public  key (ship to the agent host) : {kp}")
        print("neither key was printed. set GOVERNANCE_PRIVKEY_FILE (operator) / "
              "GOVERNANCE_PUBKEY_FILE (agent).")
    elif cmd == "grant":
        spec = sys.argv[2] if len(sys.argv) > 2 else "8h"
        n, unit = int(spec[:-1]), spec[-1]
        print("granted" if grant(n * _DUR.get(unit, 3600)) else "FAILED")
    elif cmd == "revoke":
        revoke()
        print("revoked — autonomy is stopped")
    elif cmd == "heartbeat":
        print("beat" if beat() else "FAILED")
    else:
        print(__doc__)
