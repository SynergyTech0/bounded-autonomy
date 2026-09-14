"""ledger.py — tamper-evident, hash-chained governance record. (governance v2 / G15)

GOVERNANCE_MODEL.md finding F2: `autonomy_log.jsonl` is plain append-only JSONL. The estate
already hash-chains elsewhere (clinical_bus.py, business_os.py) but the governance path —
the one record that has to survive an adversary — does not. Every other invariant in the
model is audited against this file, so a silently-rewritable record undermines all of them.

Each entry commits to its predecessor:

    hash_n = sha256( seq_n || ts_n || hash_(n-1) || canonical_json(event_n) )

Editing or deleting any entry breaks every hash after it, so tampering is detectable in one
linear pass. `verify()` returns the exact sequence number where the chain first breaks.

WHAT THIS IS AND IS NOT (GOVERNANCE_MODEL.md §7.4 — do not overclaim):
  * Tamper-EVIDENT: any edit to history is detectable.
  * NOT tamper-PROOF: a process running as the operator's user can truncate the file and
    rebuild a consistent chain from a chosen point. What it CANNOT do is edit history and
    leave the chain intact, and it cannot hide a truncation from anyone holding an earlier
    head. Detection therefore depends on the head being witnessed OUTSIDE this box —
    `anchor()` emits exactly that witness. Call it from somewhere the mind cannot reach.

  python ledger.py verify      # walk the chain, report the first break
  python ledger.py head        # current (seq, hash) — the value to anchor off-box
  python ledger.py tail 20     # last N decisions, human readable
"""
from __future__ import annotations

import hashlib
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.environ.get("GOVERNANCE_LEDGER", os.path.join(HERE, "governance_ledger.jsonl"))
GENESIS = "0" * 64


def _canonical(obj) -> str:
    """Stable JSON so a hash computed now matches one computed later. sort_keys is what
    makes the digest reproducible; without it, dict ordering would silently break the chain."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(seq: int, ts: str, prev: str, event) -> str:
    payload = f"{seq}\n{ts}\n{prev}\n{_canonical(event)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read(path: str | None = None) -> list[dict]:
    path = path or LEDGER
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        # A corrupt line is itself a chain break; represent it so verify()
                        # reports it rather than silently skipping past the damage.
                        out.append({"__corrupt__": line[:200]})
    except FileNotFoundError:
        return []
    return out


def _last_lines(path: str, want: int = 4, chunk: int = 8192) -> list[str]:
    """The last few non-empty lines, read backwards from EOF.

    `append` needs only the head, and it is on the hot path once the kernel is wired into
    the act path — re-reading the whole ledger per call would make governance cost grow
    linearly with its own history, which is the wrong shape for a mechanism that is
    supposed to be always-on."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = pos = f.tell()
            buf = b""
            while pos > 0 and buf.count(b"\n") <= want:
                step = min(chunk, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                if end - pos > 1_000_000:      # pathological single line; give up cheaply
                    break
        return [x for x in buf.decode("utf-8", "replace").splitlines() if x.strip()][-want:]
    except OSError:
        return []


def head(path: str | None = None) -> tuple[int, str]:
    """(seq, hash) of the last entry. (-1, GENESIS) for an empty ledger.

    This pair is the whole witness: anyone holding an older (seq, hash) can prove the
    current file still contains their history by replaying to that sequence."""
    path = path or LEDGER
    for line in reversed(_last_lines(path)):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue                            # a torn tail line is not the head
        if "seq" in r and "hash" in r:
            return int(r["seq"]), str(r["hash"])
    return -1, GENESIS


def append(event: dict, path: str | None = None) -> dict:
    """Append one governance event, chained to the current head. Returns the entry.

    Never raises on a write problem in the caller's face without saying so — but it does
    NOT swallow the failure either: an unwritable ledger means the system is unaudited, and
    kernel.authorize() treats that as REFUSE rather than proceeding unrecorded."""
    path = path or LEDGER
    seq, prev = head(path)
    seq += 1
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    entry = {"seq": seq, "ts": ts, "prev": prev,
             "hash": _digest(seq, ts, prev, event), "event": event}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    return entry


def verify(path: str | None = None) -> tuple[bool, int, str]:
    """Walk the chain. -> (ok, break_seq, reason). break_seq is -1 when ok.

    Checks three distinct failure modes, because they mean different things:
      * corrupt line      — the file was damaged or partially written
      * prev mismatch     — an entry was inserted, removed, or reordered
      * hash mismatch     — an entry's own content was edited in place
    """
    rows = _read(path)
    if not rows:
        return True, -1, "empty ledger"
    prev = GENESIS
    for i, r in enumerate(rows):
        if "__corrupt__" in r:
            return False, i, f"corrupt entry at line {i}"
        try:
            seq, ts, rprev, rhash = int(r["seq"]), r["ts"], r["prev"], r["hash"]
            event = r["event"]
        except (KeyError, TypeError, ValueError):
            return False, i, f"malformed entry at line {i}"
        if seq != i:
            return False, i, f"sequence gap: entry {i} claims seq {seq}"
        if rprev != prev:
            return False, seq, f"broken link at seq {seq}: prev != predecessor hash"
        if _digest(seq, ts, rprev, event) != rhash:
            return False, seq, f"content altered at seq {seq}: hash mismatch"
        prev = rhash
    return True, -1, f"intact, {len(rows)} entries"


def anchor(path: str | None = None) -> dict:
    """The off-box witness (GOVERNANCE_MODEL.md §7.4).

    Emit this from a scheduled job that writes somewhere the mind has no reach — another
    host, a mailbox, a printed line. Holding an old anchor is what turns "truncation is
    possible" into "truncation is detectable", which is the strongest honest claim
    available on a single-user box."""
    ok, brk, reason = verify(path)
    seq, h = head(path)
    return {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "seq": seq, "head": h,
            "intact": ok, "break_seq": brk, "reason": reason}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "verify":
        ok, brk, reason = verify()
        print(f"{'INTACT' if ok else 'BROKEN'} — {reason}")
        sys.exit(0 if ok else 1)
    elif cmd == "head":
        s, h = head()
        print(f"seq={s} head={h}")
    elif cmd == "anchor":
        print(json.dumps(anchor(), indent=2))
    elif cmd == "tail":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        for r in _read()[-n:]:
            e = r.get("event", {})
            print(f"[{r.get('seq'):>5}] {r.get('ts')} {e.get('verdict','?'):<11} "
                  f"{e.get('affordance','?')}  {str(e.get('reason',''))[:70]}")
    else:
        print(__doc__)
