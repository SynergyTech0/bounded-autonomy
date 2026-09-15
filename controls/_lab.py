# -*- coding: utf-8 -*-
"""Shared: stand up a disposable, autonomy-armed governance lab for the §5.3 controls.
Off-box custody is modelled by a symmetric HMAC lab key (the ATTACK surface under test is the
gate's action decision, exercised separately from key custody). Returns the gate modules."""
import os, secrets, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("GOVERNANCE_LAB", "1")
import composition, corrigibility, kernel, ledger, lattice  # noqa: E402


def arm():
    lab = tempfile.mkdtemp(prefix="control_")
    corrigibility.PUBKEY_FILE = os.path.join(lab, "nopub")
    corrigibility.PRIVKEY_FILE = os.path.join(lab, "nopriv")
    composition.TRAJECTORY = os.path.join(lab, "traj.jsonl")
    ledger.LEDGER = os.path.join(lab, "led.jsonl")
    corrigibility.KEY_FILE = os.path.join(lab, "key")
    corrigibility.GO_TOKEN = os.path.join(lab, "go.json")
    corrigibility.HEARTBEAT = os.path.join(lab, "hb.json")
    open(ledger.LEDGER, "w").close()
    open(corrigibility.KEY_FILE, "wb").write(secrets.token_hex(32).encode())
    corrigibility.grant(3600)
    corrigibility.beat()
    assert corrigibility.stance()["stance"] == "autonomous", "lab must be armed"
    return composition, corrigibility, kernel, ledger, lattice
