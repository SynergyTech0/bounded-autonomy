# -*- coding: utf-8 -*-
"""§5.5 control (G9-reverse): after a session ingests UNTRUSTED content, a subsequent effectful
action outside the acquisition set is downgraded auto -> propose. Exits non-zero if not."""
import sys
from _lab import arm
composition, corrigibility, kernel, ledger, lattice = arm()

# an ACTION affordance NOT in the acquisition (label-acquiring) set
act = next(a for a in ["email:move", "email:label", "calendar:create", "task:create"]
           if a not in composition.LABELS_ACQUIRED)

open(composition.TRAJECTORY, "w").close()
clean, _ = composition.gate("clean", "mind", act, {}, base_tier=lattice.AUTO, path=composition.TRAJECTORY)

open(composition.TRAJECTORY, "w").close()
composition.observe("inj", "mind", "web:fetch", args={"url": "http://evil/x"}, path=composition.TRAJECTORY)
after, why = composition.gate("inj", "mind", act, {}, base_tier=lattice.AUTO, path=composition.TRAJECTORY)

print(f"action {act!r}: clean={clean}  after-untrusted-ingest={after}")
print(f"reason: {why[:80]}")
ok = clean == lattice.AUTO and lattice.rank(after) < lattice.rank(clean)
print("G9-reverse downgraded autonomy after untrusted ingestion:", ok)
sys.exit(0 if ok else 1)
