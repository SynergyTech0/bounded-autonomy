"""examples/reference_agent.py — a worked agent whose ONLY door to the world is the executor.

This is the complete-mediation pattern, end to end. It also doubles as a CI fixture: running
`python mediation_audit.py examples/reference_agent.py` reports ZERO violations, because every
effect goes through `execute()` — there is no raw subprocess / socket / write-open anywhere in
this file. Add one and CI turns red (invariant MED).

    python examples/reference_agent.py            # gated run; with no grant, every act is refused
    python examples/reference_agent.py --armed     # mint a LOCAL DEV grant to show an AUTO effector run

The effectors here return SIMULATED results so the file is audit-clean and safe to run anywhere.
In a real agent, the side effect (the subprocess, the HTTP call, the file write) lives in the
handler body — reachable only through the gated `execute()`, never called directly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import runtime_guard                       # noqa: E402
from executor import effector, execute     # noqa: E402

# Install the interpreter-level guard: once on, a guarded effect (process spawn, network, ctypes)
# can only run inside a permitted execute() window. Harmless here — this agent performs none.
runtime_guard.install()


@effector("sys:disk")
def _disk(args):
    # A real agent reads the disk here; simulated so the file stays audit-clean.
    return {"free_gb": 128, "note": "reference value"}


@effector("email:move")
def _move(args):
    return {"moved": args.get("id"), "to": args.get("folder", "Bills")}


@effector("web:fetch")
def _fetch(args):
    # A real agent egresses here — but only ever after the gate has permitted the call.
    return {"fetched": args.get("url"), "note": "simulated"}


def run():
    print("bounded-autonomy reference agent — every effect routes through execute()\n")
    plan = [
        ("sys:disk",   {}),                                   # AUTO read
        ("email:move", {"id": 42, "folder": "Bills"}),        # reversible -> PROPOSE (a human)
        ("web:fetch",  {"url": "https://example.com"}),       # egress -> destination-trust gate
        ("shell:exec", {"command": "rm -rf /"}),              # unregistered -> refused, never runs
    ]
    for aff, args in plan:
        # "mind" is the trusted-core-loop principal the reference policy grants an AUTO ceiling;
        # an unknown principal is capped at PROPOSE (no autonomy), which is the correct default.
        out = execute(aff, args, principal="mind", session="ref")
        if out.ran:
            print(f"  RAN      {aff:12} -> {out.result}")
        else:
            v = out.decision.verdict if out.decision is not None else "no-handler"
            print(f"  refused  {aff:12} -> {v:11} {out.reason[:56]}")


if __name__ == "__main__":
    if "--armed" in sys.argv:
        # LOCAL DEV ONLY (see examples/_dev_grant.py): mint an on-box HMAC grant so AUTO effectors
        # actually run. NOT the production posture — real deployments mint an Ed25519 grant OFF-BOX
        # (governance_operator.py), so the agent host verifies a grant but never mints one.
        from _dev_grant import arm_local_dev
        arm_local_dev()
        print("[dev] minted a LOCAL on-box HMAC grant (NOT production; real grants are off-box)\n")
    run()
