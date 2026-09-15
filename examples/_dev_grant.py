"""examples/_dev_grant.py — LOCAL DEV ONLY. Mint an on-box HMAC grant so the reference agent can
show an AUTO effector actually running.

This is the OPPOSITE of the production posture. In production the signing key is an Ed25519 key
held OFF-BOX (governance_operator.py): the agent host verifies a grant but can never mint one.
NEVER use this to arm a real deployment. It lives here, not in reference_agent.py, so that file
stays mediation-audit-clean — this is a dev harness, not an agent module.
"""
import os
import secrets
import tempfile


def arm_local_dev(hours: int = 1) -> str:
    """Point corrigibility/ledger/composition at throwaway files and mint a local HMAC grant.
    Returns the temp dir. On-box and symmetric — for demonstration only."""
    import corrigibility
    import ledger
    import composition

    d = tempfile.mkdtemp(prefix="ba_dev_")
    keyf = os.path.join(d, "dev.key")
    with open(keyf, "wb") as f:
        f.write(secrets.token_hex(32).encode())

    corrigibility.KEY_FILE = keyf
    corrigibility.PUBKEY_FILE = os.path.join(d, "nopub")     # neutralize asymmetric -> HMAC mode
    corrigibility.PRIVKEY_FILE = os.path.join(d, "nopriv")
    corrigibility.GO_TOKEN = os.path.join(d, "go.json")
    corrigibility.HEARTBEAT = os.path.join(d, "hb.json")
    ledger.LEDGER = os.path.join(d, "ledger.jsonl")
    composition.TRAJECTORY = os.path.join(d, "traj.jsonl")

    corrigibility.grant(hours * 3600)
    corrigibility.beat()
    return d
