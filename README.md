# Bounded Autonomy

**A deterministic governance layer for autonomous AI agents, designed for the case where the
system can out-reason its reviewer.** It is a gate that bounds what an agent can *do* through the
mediated path — legibility-gated approval, information-flow taint across a multi-agent mesh, and a
corrigibility model where *stop is the default and autonomy is a fresh, expiring, cryptographically
signed grant*.

It ships **DISARMED** and it is **honest about its limits** — see [What this does NOT do](#what-this-does-not-do)
before anything else. A governance model that oversells itself is worse than none.

The full normative specification is [`GOVERNANCE_MODEL.md`](GOVERNANCE_MODEL.md); the evaluation
protocol is [`METHODOLOGY.md`](METHODOLOGY.md). This README is the map.

---

## The problem

Most agent "guardrails" assume three things that all fail as capability rises:

| Assumption | Fails when | Answered by |
|---|---|---|
| The reviewer can evaluate the proposal | the system out-reasons the reviewer | **Legibility** — an action nobody can evaluate is not approvable at any tier |
| An action is the unit of harm | harm is assembled from individually-safe parts | **Composition** — tier is computed over the trajectory, and information-flow taint dominates it |
| The operator can stop the system | the stop mechanism is inside the system's reach | **Corrigibility** — GO is a signed, expiring grant; absence is the deny state |

The load-bearing idea in one line: **a language model never decides whether an action is
permitted — it may only propose, and composition may only *tighten*.** Permissions form a lattice
(`REFUSE < DESTRUCTIVE < PROPOSE < AUTO`) and every layer composes by *meet* (most restrictive
wins), so "adding a check can only lower the verdict" is a property of the arithmetic, not a
convention each layer has to remember.

## What this does NOT do

Stated first, on purpose.

1. **It does not solve alignment.** It bounds what a misaligned system can *do* through the
   governed path. It says nothing about what the system *wants*.
2. **Legibility is a gameable proxy.** A system that can model the legibility scorer can produce
   proposals that score well and are still not understood. This raises the cost of deception; it
   does not make it impossible.
3. **It governs the mediated path only.** Any capability reached *without* going through
   `kernel.authorize()` is ungoverned. The model's strength is exactly the completeness of that
   mediation — an ongoing engineering obligation, not a proof. (See the Hugging Face incident
   fixture in the spec, §12: this model would **not** have prevented that escape.)
4. **On a single-user host, tamper-evidence is not tamper-proofing.** The stop-grant and audit-log
   guarantees hold *cryptographically* only when the signing key lives outside the agent's trust
   boundary (a separate account, an HSM, or another machine). The code supports that placement and
   warns loudly when the key is co-located. **This is a deployment property, not a code property.**

## The invariants

`test_governance.py` asserts each on the *value*, never on a clean exit.

| | Property |
|---|---|
| **G1–G4** | determinism first · fail-closed · tightening-only composition · value immutability |
| **G5–G7** | no unreviewable action · approval counts only if informed · scrutiny scales with impact × opacity |
| **G8–G11** | trajectory governance · information-flow taint dominates tier · principal is the union (no laundering) · mesh-wide blast-radius budget |
| **G12–G15** | interruptibility preserved · stop-is-default signed GO grant · dead-man's switch · tamper-evident hash-chained ledger |

## Architecture

The engine is a self-contained island — these modules import only each other plus optional
`cryptography` (for the asymmetric stop-grant). Your own policy and conscience are *pluggable*.

```
lattice.py         the permission lattice + meet (composition operator)
ledger.py          sha256 hash-chained, tamper-evident decision log
corrigibility.py   GO token / heartbeat / chain integrity / governance-surface  (G12–G15)
composition.py     trajectory, taint labels, principal union, mesh budget       (G8–G11)
legibility.py      legibility score vs required floor; decompose or refuse      (G5–G7)
policy.py          v1 deterministic tier classifier  — REFERENCE; bring your own (G1–G2)
kernel.py          the single mediated path: composes the layers, records every decision
shadow.py          run v2 beside v1 without enforcing (observe-only rollout)
executor.py        the single dispatch waist — effectors are registered data; execute() gates them
mediation_audit.py CI check: fails the build if a raw effect primitive escapes the executor  (MED)
governance_operator.py   the OPERATOR half — run OFF the agent host; mints signed grants
```

**Complete mediation — making "anything added auto-routes through the gate" structural.** The gate
only governs what reaches it, so `executor.py` makes the gated `execute()` the *only door*:
effectors are registered (`@effector("email:move")`) rather than called directly, so adding a
capability means registering one, and a registered handler runs only after `kernel.mediate()`
permits it. `mediation_audit.py` then walks your agent-reachable modules and fails CI if any raw
effect primitive (subprocess, socket, http, write-mode `open`, deletion) appears outside the
executor. Point it at your own agent package: `python mediation_audit.py youragent/*.py`.

`policy.py` here is a **generic reference classifier**. The kernel treats it as an optional,
fail-closed layer: supply your own affordance taxonomy through the same
`classify(affordance, args, phi_node) -> (tier, reason)` contract. `conscience` is a callable you
pass in; omit it and the kernel simply runs without that layer.

## Quick start

No dependencies for the core suite (Python 3.11+). `cryptography` enables the asymmetric
stop-grant; without it, the model falls back to HMAC (tamper-evident, not tamper-proof).

```bash
python test_governance.py            # 22 invariants, asserts on values
python mediation_audit.py youragent/*.py   # completeness: no effect escapes the executor (your agent modules)
python redteam.py             # deterministic adversarial probes (regression fixtures)
python kernel.py demo         # the worked examples from GOVERNANCE_MODEL.md
```

## Red-teamed as an enforcement layer, not reviewed as a document

The model was attacked, not just read. `redteam.py` gives an attacker view the tool surface with
no sight of the rule code; a sandbox runs real enforcement with autonomy armed; an independent
judge rules on canary movement from an effect log — never on the attacker's self-report. Six
deterministic bypasses were found and fixed, each now a regression fixture. `redteam_live.py` goes
further: a *separate model* drives blind, adaptive attacks over several rounds — which found a real
medium-bandwidth exfiltration path the fixed probes had missed (now closed and fixtured). The
methodology is in [`METHODOLOGY.md`](METHODOLOGY.md); the results are in the spec, §10–§11.

## Deploying it for real

The one step that turns tamper-*evidence* into tamper-*proofing*: **move the signing key off the
agent host.** `governance_operator.py` is the operator half — it holds the Ed25519 private key on a
separate machine, mints time-boxed GO tokens and heartbeats, and ships only the public key to the
agent host. The agent can then *verify* a grant but never *mint* one. `preflight.py` refuses to
declare a run ready unless that (and enforcement, the allowlist, an intact ledger, and an isolated
kill-drill) all check out.

`sandbox_harness/` contains the isolation rig for testing an agent that might try to escape:
an allowlist forward-proxy (`research_proxy.py`), an in-guest isolation verifier
(`verify_isolation.sh`), a secret-scanning bundle builder (`build_bundle.py`), and VM / cloud
runbooks. Replace the placeholder `example.com` / `203.0.113.x` denylist entries with your own
protected infrastructure before using it.

## License

MIT — see [LICENSE](LICENSE). Author: Shane Sipe / Synergy Technologies.
