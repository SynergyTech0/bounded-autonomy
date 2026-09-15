# Examples

## `reference_agent.py` — the complete-mediation pattern, end to end

A worked agent whose **only door to the world is `execute()`**. Effectors are registered with
`@effector` and return simulated results, so the file is safe to run anywhere and stays
mediation-audit-clean.

```bash
python examples/reference_agent.py            # gated; with no grant, every act is refused
python examples/reference_agent.py --armed     # a local DEV grant -> the AUTO read actually runs
```

Armed, it shows the full spread of verdicts on one run:

```
RAN      sys:disk     -> {'free_gb': 128, ...}          # AUTO: permitted autonomously
refused  email:move   -> propose                        # reversible: a human approves
refused  web:fetch    -> destructive                    # egress: destination-trust denies
refused  shell:exec   -> no-handler (fail-closed)       # unregistered: never runs
```

It doubles as the CI fixture for invariant **MED**:

```bash
python mediation_audit.py examples/reference_agent.py   # OK — 0 violations
```

Add a raw `subprocess` / `socket` / write-`open` anywhere in it and that command (and CI) turns
red. That is the point: an effect that does not go through the executor is a bug.

`_dev_grant.py` is a **LOCAL DEV** helper (an on-box HMAC grant), kept out of the agent so the
agent stays audit-clean. Real deployments mint an **Ed25519 grant OFF-BOX** — see
[`governance_operator.py`](../governance_operator.py) and `GOVERNANCE_MODEL.md` §5.
