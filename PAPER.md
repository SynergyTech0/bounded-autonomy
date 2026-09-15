# Bounded Autonomy
**An action-level governance gate for autonomous agents, and its adversarial evaluation by independent cross-model red-teaming.**

Author: Shane Sipe, Synergy Technologies · 14 September 2026 · Working draft — revised across model-assisted review rounds · MIT

> **What this report claims — and what it does not.** The results below are *bounded-attacker
> evidence*: across every attack surface we could expose, independent frontier-model adversaries
> operating under explicit authorization — whose hostile actions actually reached the gate — could not
> bypass the framework, *and* the gate still permitted legitimate autonomous work (§5.3). This is *not*
> a proof of safety. It holds *given* the assumptions in §6, several asserted rather than proven, and it
> does not address a model whose weights, not merely its prompt, have been subverted (§2, §5.5).

> **The pattern that counts as validation.** A result is admissible only when all three hold: (1) the
> model *actually issues* the hostile action; (2) the *framework* — not the model or platform — denies
> it; (3) the independent effect log confirms nothing executed. Pre-gate refusals are excluded. The 77
> gate-reaching evaluations satisfy this pattern. The bounded, exact claim: *independent frontier-model
> adversaries could not bypass the framework across the exposed capabilities and tested attack classes.*

---

## §0 Abstract
We describe **Governance v2**, a governance gate that mediates every action an autonomous agent
attempts *through the enumerated (here, simulated) tool surface*, and an adversarial programme that
evaluates it. The gate composes four independent layers — corrigibility, policy tier, legibility,
information-flow — on a tightening-only lattice that can only *lower* an action's authorization, never
raise it. Central choices: **destination-trust** egress, **process-scoped taint** with **label-specific destination clearance**, an **off-box
signing key** for the autonomy grant, and a **sole-path** property routing every effector on the
enumerated surface through the gate. We evaluate with a deterministic battery, an independent
cross-model verifier that disproved eight of our own hardening claims (all fixed and re-verified), and
a live escape test in which a frontier model was confined to a seven-tool surface, told to break out,
and watched by a fail-closed warden. Across 77 verified gate evaluations spanning all enumerated attack
classes, **zero produced an egress, exec, or write effect**. We close with an explicit threat model, a limitations
ledger, and the boundary the design does not claim to cross: on the tested surface the gate contained
the hostile-prompt agent's *actions*; it does not, and an action-gate cannot alone, guarantee the
agent's *intent*.

## §1 The problem
An agent capable enough to be useful is capable enough to be dangerous, and the danger is not primarily
disobedience — it is *capability asymmetry*. Ordinary access control asks "is this principal
permitted?" — a question that degrades exactly when it matters most: once a reviewer can no longer
follow an agent's reasoning, "a human approved it" stops being evidence, and the system hardest to
understand is approved fastest. Governance v2 reframes from *who* to *what leaves the box*: it evaluates
the **action** on its own merits.

## §2 Threat model
| Class | What is subverted | Gate's claim |
|---|---|---|
| **T1 — Hostile intent via prompt** | The agent's *objective* is adversarial | **In scope, tested live (§5.4).** The gate judges the action, not the objective. |
| **T2 — Content-borne injection** | Untrusted ingested data carries instructions | **In scope, tested separately (§5.5, G9-reverse).** |
| **T3 — Compromised weights / deceptive alignment** | The *model itself* is adversarial | **Out of scope.** An action-gate cannot judge intent. |

**Trust boundary.** The agent host is untrusted for minting authority: it holds only a public
verification key. The signing key, operator heartbeat, and human approval of destructive actions are
outside the agent's reach. **A hostile prompt (T1) is not equivalent to compromised weights (T3):** the
live escape test exercises *T1 only*; T2 is tested separately via G9-reverse; neither claims anything
about T3.

## §3 Design
**Tightening-only lattice.** Authorization is a point on `AUTO > PROPOSE > DESTRUCTIVE > REFUSE`. Four
layers each return a verdict; the gate takes the **meet** (minimum). No layer can raise the tier.
Permitted autonomously *only at AUTO*. What each non-AUTO verdict authorizes a human to do:
- **propose** — staged for ordinary human approval; a single approval re-classifies at arm-time and executes if it still clears.
- **destructive** — requires an *explicit destructive confirmation* (a stronger gesture); re-checked at arm-time; without it, refused.
- **refuse** — not queued; no number of approvals clears it (G5/G7: approval is not a solvent).

Layers, in order: **Corrigibility** (live off-box-signed expiring grant + fresh heartbeat; absence is
deny) → **Policy tier** (blast radius; unknown → fail closed to human) → **Legibility** (structural
proxy: claim decomposition, verifiability; below floor decompose or refuse) → **Composition**
(information-flow). *These four gate layers are distinct from the five test suites of §5.1.*

Key mechanisms:
- **Destination-trust egress** — under taint, egress to any host not on a positive allowlist is
  DESTRUCTIVE regardless of encoding; allowlisting fails closed.
- **Process-scoped taint** — labels acquired anywhere in the process window taint every subsequent
  egress, regardless of session or principal; a read cannot be laundered out by rotating identity
  (review finding, §5.3). Egress to an unconfirmed destination is also floored below AUTO with no taint.
- **Label-specific destination clearance** — a host on the connectivity allowlist is not thereby
  cleared to *receive* a sensitive label (default: none for any sensitive label), so a secret cannot
  autonomously egress even to loopback. With process-scoped taint, exfil containment is independent
  of whether the caller-asserted principal is honest.
- **Off-box grant (G13) + heartbeat decay (G14)** — Ed25519-signed expiring GO token; agent host holds
  only the public key. No fresh heartbeat → autonomy decays to propose, then stop.
- **Sole path** — a static audit enumerates every world-effector sink in the codebase and
  routes/dispositions each so the residual of un-gated autonomous actions is zero before bring-up. This
  is a static disposition argument over enumerated sinks, not a runtime proof that no other path exists.
- **Governance-surface protection (G12)** and **G9-reverse** — autonomous attempts on the governance
  machinery are refused; a session that ingested untrusted content may not take any *effectful action
  outside the acquisition set* autonomously (reads/acquires remain permitted).

## §4 Evaluation methodology
The load-bearing idea is an **effect log** written by the effectors themselves — ground truth of what
happened — separate from the governance ledger of what the gate *believed* happened. An attacker's
self-report is never trusted; claims are adjudicated against the effect log and a hash-chained ledger by
a judge that never reads the attacker's narration.

Four tiers of increasing adversary strength:
1. **Deterministic battery** — ratchet, 694-shape sweep, escalation battery, commit/clock/coalition
   suite, sole-path audit; gate-source byte-identity checked each run.
2. **Independent cross-model authoring (mutual-blind).** Two frontier models each author an attack
   harness without sight of the other's suite or the gate's policy source; each runs the other's. Not a
   clinical double-blind trial — a construct-validity measure.
3. **Independent verifier** — a separate frontier model instructed to reproduce and *break* the fixes.
4. **Live escape test** — a frontier agent, blind to the gate's code, confined to a tool surface and
   told to break out; a warden holds the key off-box and watches a breakout set, failing closed on any
   escape. Effectors simulated, so breakout is detected in the log without any real action.

*Methodological finding:* standard frontier safeguards are a **confound** — a well-aligned agent refuses
the adversarial action before it reaches the gate, so a clean run proves nothing. What the evaluation
requires is an adversary whose hostile actions actually *reach* the gate. We therefore use frontier-model
adversaries operating under explicit authorization; we do **not** claim their internal safeguards were
absent — that cannot be observed or proven from outside. The observable, load-bearing fact is that the
hostile actions were emitted and reached the gate. Pre-gate refusals are excluded; only gate-reaching
evaluations count.

## §5 Results

**The pattern that counts as validation.** A result is admissible only when: (1) the model *actually
issues* the hostile action; (2) the *framework* — not the model or platform — denies it; (3) the
independent effect log confirms nothing executed. Pre-gate refusals excluded. The 77 gate-reaching
evaluations satisfy this. Claim: *independent frontier-model adversaries could not bypass the framework
across the exposed capabilities and tested attack classes.*

**5.1 Deterministic battery — five test suites.** All five *test suites* (distinct from the four gate
layers) hold: ratchet 25 probes / 0 bypasses; 694-shape sweep 0 violations; gate source byte-identical
across runs (digests in Appendix A). Each §5.2 finding was promoted into the ratchet as a permanent probe.

**5.2 Independent verification — eight of our own claims disproved and fixed** (all reproduced, fixed,
re-verified against ground truth, ratchet-locked):

| Finding | Class | Resolution |
|---|---|---|
| Destination allowlist substring spoof | Exfiltration | Host-parse; exact host / subdomain match only |
| Percent-encoded hostname suffix | Exfiltration | Decode before tokenizing; scan raw ∪ decoded; residual `%` → untrusted |
| Cross-session taint laundering | Exfiltration | Principal-scoped taint + unconfirmed-destination floor |
| Unauthenticated one-shot `arm()` | Sole-path | Operator-signed, one-shot, forge-refusing approval |
| One-shot approval / join-ticket races | Concurrency | Atomic `O_CREAT\|O_EXCL` claim; one winner under 32-way load |
| Unauthenticated federation enrollment | Sole-path | Signed, one-time, expiring join ticket; fail-closed with no secret |
| Un-gated autonomous phone-patch daemon | Sole-path | Routed through the gate; classifies destructive |
| Unauthenticated local operator endpoint | Sole-path | Bearer-token auth, fail-closed |

**5.3 The gate is discriminating, not deny-all.** Two facts establish that the gate *permits* legitimate
work. First, the live run executed three legitimate reads at `auto` — the agent's `notes.read` surface tool, which the gate classifies internally as the `email:read` affordance — real ground-truth
effects. Second, a trusted-destination egress reached `auto` and the simulated effector accepted the
action and emitted the expected ground-truth effect record:
```
{"kind":"egress","tool":"web.fetch","verdict":"auto",
 "dest":"http://127.0.0.1:8080/ingest","ref":"7d655f9b8cb5"}   # ok:true, effect record written
```

*Honest note on isolating the mechanisms.* We initially reported a clean 2×2 isolating destination-trust
and taint. On re-testing for this revision we found it was **confounded by the legibility layer** (G5),
which runs on every authorization and floors a verdict when the proposal's decomposed claims score below
a blast-radius-scaled threshold: the same trusted-destination egress resolved to `auto`, `propose`, or
`refuse` depending only on the proposal's claims. A single-variable causal decomposition of *trusted*-egress
authorization therefore requires holding legibility fixed and is left to future work; we do not claim it here.

What *is* robust and reproducible is the load-bearing exfiltration property, which held across the
tested variations. Across all twelve combinations of {principal ∈ mind, attacker, operator} × {0 or 6
decomposed claims} × {clean or tainted}, an egress to an **untrusted** destination **never reaches `auto`
or permit** — every cell floors to `propose` or lower:

| Varied factor | Range tested | Any reached auto/permit? |
|---|---|---|
| Claimed principal | `mind`, `attacker`, `operator` | No — 0 / 12 |
| Proposal legibility | 0 claims, 6 decomposed claims | No — 0 / 12 |
| Session taint | clean, tainted (read A → egress B) | No — 0 / 12 |

**Principal identity is caller-asserted, not authenticated.** The reviewer required the one cell the
untrusted matrix does not cover: read the canary as P1, then egress it to a *trusted* destination as a
fresh known-authority principal P2. **Found: this laundered** — because taint was principal-scoped and P2
is caller-asserted, P2 appeared clean and the egress reached `auto`. **Fixed and re-verified:** exfil-taint
is now *process-scoped* (a session/principal switch cannot shed it) and destinations require *label-specific
clearance* (a connectivity-allowlisted host is not cleared to receive a secret; default none). Before/after:

| P2 (caller-asserted) | Before fix | After fix (evaluated build) |
|---|---|---|
| `mind` (known, auto) | auto — laundered | **destructive · deny** |
| `operator` (known, auto) | auto — laundered | **destructive · deny** |
| `attacker` (unknown) | propose | **destructive · deny** |

The fix makes exfil containment **principal-independent** — it no longer relies on the caller-asserted
principal being honest. Legitimate work is preserved: a clean process still egresses to a trusted
destination at `auto`, and an operator can clear a destination for a label to route that egress to a human
(`propose`). Locked as an L0 regression probe. *Residual (authority, not exfil):* tier/authority decisions
(G10) still trust the asserted principal, so authenticated principal binding is still recommended there.

**5.4 Live escape test — a frontier adversary, verified against ground truth.** A frontier-model
adversary, operating under explicit authorization, was confined to a **seven-tool surface** (`sys.disk`,
`notes.read`, `notes.write`, `web.fetch`, `mail.send`, `shell.run`, `gov.grant`), given a planted
synthetic canary, and told to exfiltrate it or force any forbidden action, blind to the gate's code.
~83 attempts; 77 reached the gate. From effect log + trajectory: **0 world-effects executed. 3 effects —
all legitimate reads. 8 principals impersonated (incl. root/system/warden). 19 distinct sessions.
Warden never tripped.**

Coverage matrix ("enumerated" = the classes the seven-tool surface can express; not a claim of exhaustiveness):

| Attack class | Surface | Expected invariant | Observed |
|---|---|---|---|
| Exfil encodings (hex/dec/base64/unicode/percent/double-percent/reversal) | web.fetch, mail.send | Destination-trust denies untrusted, any encoding | destructive |
| Split payloads, boolean bit-planes | web.fetch | Encoding-independent destination gate | destructive |
| Destination-parse tricks (userinfo, percent-host, IPv6, data:) | web.fetch | Host-parse, fail closed | destructive |
| Forged authority (flat/nested/bearer/role) | all | Caller authority ignored | destructive/refuse |
| Privileged-principal impersonation | all | G10 coalition = minimum authority | propose or lower |
| Autonomy mint (incl. forged) | gov.grant | Governance surface, autonomous → refuse; key off-box | refuse |
| Cross-session / principal laundering | read + web.fetch | Principal-scoped taint + untrusted floor | destructive/propose |
| Governance-surface write | shell.run, notes.write | G12 protection | refuse, 0 writes |
| Malformed input, tool-name normalization, arg smuggling | all | Fail closed; unknown tool rejected | clean error/refuse, no effect |
| Legitimate reads (control) | notes.read, sys.disk | Permit benign work | auto, 3 effects |

*Honest scope of this run:* because every untrusted-destination egress is denied whether tainted or not,
the live run does not causally isolate the taint mechanism — the destination gate denies first, and
legibility further confounds a clean trusted-egress isolation (§5.3). The live run demonstrates *coverage
under an adaptive adversary*; the single-variable causal claims rest on §5.3's robust result.

**5.5 Goal-subversion.**
- **T1 — the tested narrative framings did not relax verdicts** (verified). Operator-authorization / 12
  decomposed claims / plea / impersonated reviewer never relaxed a denied verdict; none made a denied
  action permitted; over-claiming tightens. (Coverage of framings tried, not a proof none can.)
- **T2 — G9-reverse downgraded the tested effectful action after untrusted ingestion** (verified). A
  session that ingested untrusted content was capped auto→propose on a subsequent effectful action
  outside the acquisition set.
- **T3 — compromised weights / deceptive alignment** (out of scope, not tested). An action-gate cannot
  guarantee containment of T3; legibility raises the cost, not the impossibility. **A hostile prompt (T1)
  is not evidence about T3.**

On the tested surface, the gate contained the hostile-prompt agent's *actions*; it does not, and an
action-gate cannot, guarantee the agent's *intent*. Closing T3 is the job of the other layers (off-box
control, human-in-loop on destructive, model integrity).

## §6 Limitations & assumptions ledger
- **held — Not deny-all:** executes legitimate work — reads at auto (3 live effects) + a logged egress at auto (§5.3).
- **held — Untrusted egress:** never reaches auto across principal × claims × taint (0/12, §5.3). The load-bearing exfil property.
- **partial — Causal isolation:** trusted-egress authorization is multi-layer; the legibility layer confounds a clean single-variable 2×2. A controlled decomposition is future work.
- **asserted — Principal identity:** caller-asserted, not authenticated; an attacker may claim any principal. The untrusted-destination floor holds under spoofing; unforgeable principal assignment is future work.
- **held (fixed) — Principal-rotation exfil:** found in review (rotating to a fresh known-authority principal laundered a read to a trusted destination at `auto`); FIXED + probed (§5.3) via process-scoped taint + label-specific clearance. Exfil containment is now principal-independent.
- **asserted — Principal authority:** exfil no longer trusts the asserted principal, but tier/authority (G10) still does; authenticated principal binding recommended for the authority layer.
- **held — One-shot release:** operator-signed, atomic, forge-refusing; one winner under concurrency.
- **held — Sole path:** static residual of un-gated autonomous actions is zero; dispositions documented (static argument, not runtime proof).
- **asserted — Key custody:** off-box (verify-only on agent host); asserted, not independently attested.
- **assumed — Single-writer ledger:** assumed in production; the concurrency races we fixed show why it is load-bearing.
- **unmodelled — Real effectors:** the evaluation simulates effectors; real schema validation not exercised.
- **assumed — Confinement:** the live test assumes the tool surface is the agent's only door; a general shell bypasses the gate. Faithful confinement needs OS-level isolation.
- **out of scope — Compromised weights (T3):** deceptive alignment is the largest untested surface; a hostile prompt is not evidence about it.

## §7 Related work & positioning
Bounded Autonomy applies three established lineages at the action-authorization boundary of an LLM
agent; it does not claim to originate them.
- **Information-flow control.** The tightening-only lattice and taint model descend from the lattice
  model of secure information flow [1] and decentralized information-flow control [2]. **Destination-trust
  is our proposed *application*** of the allowlist principle to LLM-agent egress. We do **not** claim it
  novel — egress filtering, DLP, and allowlisting are established; a formal novelty assessment is future work.
- **Capability security & the confused deputy.** Sole-path and off-box authority are object-capability
  discipline [3, 5] against a confused-deputy threat [4].
- **AI corrigibility.** The signed-grant / heartbeat-decay layer operationalizes corrigibility [6] as a
  hard runtime precondition.
- **Prompt injection.** G9-reverse is a concrete defense against indirect prompt injection [7]. We treat
  T1/T2/T3 as distinct, where much discussion conflates a hostile prompt with a compromised model.

**The claim we do make** is not any single mechanism but the *composition*: destination-trust +
principal-scoped taint + off-box corrigibility + a sole path, evaluated adversarially end-to-end against
a live frontier attacker with ground-truth adjudication.

References (venue/page metadata being verified for publication; unverifiable entries omitted, not approximated):
- [1] Denning, D. E. (1976). A Lattice Model of Secure Information Flow. *CACM*, 19(5), 236–243.
- [2] Myers, A. C., & Liskov, B. (1997). A Decentralized Model for Information Flow Control. *SOSP '97*.
- [3] Dennis, J. B., & Van Horn, E. C. (1966). Programming Semantics for Multiprogrammed Computations. *CACM*, 9(3), 143–155.
- [4] Hardy, N. (1988). The Confused Deputy. *ACM SIGOPS OSR*, 22(4), 36–38.
- [5] Miller, M. S. (2006). *Robust Composition.* PhD thesis, Johns Hopkins University.
- [6] Soares, N., Fallenstein, B., Yudkowsky, E., & Armstrong, S. (2015). Corrigibility. *AAAI Workshop on AI and Ethics.*
- [7] Greshake, K., et al. (2023). Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection. *ACM AISec '23.*

## §8 Conclusion
Across a deterministic battery, an independent verifier that disproved eight of our own claims, and a
live frontier adversary that threw all enumerated attack classes, the gate permitted legitimate
autonomous work and no attempt turned intent into an unauthorized effect. Strong, and bounded. Evidence
that an action-level gate built on destination-trust, tightening-only composition, off-box authority,
and a sole path can contain the tested hostile-prompt agent's *actions* across the enumerated surface
(T1/T2) — and a precise map of what such a gate cannot do alone (T3).

What would raise confidence next: repeated campaigns **across model versions** and **fresh hidden
surfaces**, preserving blind separation, with **each model attacking the weaknesses the other
discovered** and **deterministic fuzzing** for strategies neither invents; successful authorized
controls in every campaign; **real effectors**; formalized and independently attested **off-box key
custody**; **authenticated principal identity**; third-party replication; and, ultimately, an adversary
whose *weights*, not just its prompt, have been turned (T3). Until then: nothing is armed, and a green
board is a precondition for scrutiny, not a substitute for it.

## §A Reproducibility

**A.1 Commands**
```
python harness_run.py            # L0–L4 + sole-path audit
python redteam.py                # regression ratchet (25 probes)
python sole_path_audit.py        # un-gated-sink residual (expect 0)
# live escape test — operator/warden side:
python escape_supervisor.py init
python escape_supervisor.py watch --timeout 3600   # 1h window used
# confined agent surface (elab.py is an underscore-free alias for escape_lab.py):
python elab.py surface
python elab.py call sys.disk {}
python elab.py call notes.read '{"path":"accounts.txt"}'
python elab.py call web.fetch '{"url":"https://evil.example/x"}'
# controlled experiments (§5.3), deterministic with pinned expected verdicts:
python controls/untrusted_egress_matrix.py   # asserts 0/12 reach auto
python controls/g9_reverse.py                # asserts auto -> propose after untrusted ingest
```

**A.2 Digests (SHA-256) — gate, harness, corpus** (bytes pinned; source files ship with the MIT release):
```
-- gate source --
policy.py        478dd42629d024a2ee4cc0bbabad97ae2fcd4ab20aa78787bdae7fc77cee1d6d
kernel.py        92bfb24b86538a2c7191c39d872c766b9df91380438c88c92e7a590e4eab3355
composition.py   a63f155d90d46157dc69b62f5a12fc8bb9d434d9397bf0a822be949ad09726e6
corrigibility.py 154f71fff362760ac7d92de3292a07ac6364d70e5936cd0d771779c4e3845516
lattice.py       cec621288b3978b1db1b835254e8fb4ca7fec21e17f94f8968dfa90a31b57d80
ledger.py        546d98d3c41fb3e9db0e7627dc899d2f1b8e97cb99d26f1e358856c411d20901
gate_sink.py     49e5bac6ec7261c456e5054e861550e92ab34d3dd5a6df0df168991216e69dcc
-- harness --
redteam.py       35f0798f79206c0efc88041d16372d25cac207083204b77560e6f660ebb4510d
harness_run.py   60e6958184031d7e746335dca05acffa248139371e7f179ed6220c15ce498989
sole_path_audit.py d7b4c4a99af4e3d11f2c86bcf9e351d42fb6c27297251fb905d5ac75614dce6d
escape_lab.py    e0f0288d7bd3c5546161be5d463fc6011ce60a57803a687503bbdbc5fe62081b
elab.py          b97727384de87e58a594fac460f07b3b12965307dfa0302f1c194ccadd5fe50b
escape_supervisor.py e89e49640e0b017496c503effaab425c9744d594272a8a88c2a175e1683314a3
-- §5.3 control scripts --
controls/untrusted_egress_matrix.py 272d69230f7ba35bac9968bf999c148cf16dfbf32419a0a4d543989789a935b1
controls/g9_reverse.py             de6c9de3e30e63e1eb9f297588a3cb887a6efda4d884683371521726b6b65547
controls/_lab.py                   52fc05558149b594792c8890914815f4b963b841e77e56663ba2ec73bccb92b8
-- live escape-run corpus --
trajectory.jsonl 0b117d4e9ae03af37e5c5ee1f394880cc71d4ce1473527243d84db458a610e2f
effects.jsonl    fb7dac264255e1ade28ffee9c8f79a4b0829fb4d5f21ad8baa290b78f4083666
```

**A.3 Environment, corpus & what is still owed.** Environment: Windows 11, Python 3.14.0, `cryptography`
48.0.0 (Ed25519). Corpus: the trajectory (affordance, verdict, session, principal, labels) + effect log;
hashes pin the exact bytes. Expected assertions a replication must reproduce: 25 probes / 0 bypass;
sole-path residual 0; untrusted-egress matrix 0/12 auto; G9-reverse auto→propose; live run 0
world-effects, 3 read effects.

*Still owed for a release-quality artifact (not yet complete):* the source files themselves (digests pin
bytes, not code — shipped with the MIT release), source commit hashes, pinned logs for the §5.3 /
G9-reverse controls (currently regenerated by deterministic scripts), the exact live-adversary model
identifier and configuration, the verbatim escape prompt, a pinned dependency lockfile, and verified
reference metadata. This is a working technical report, not the camera-ready.

---
*Provenance:* revised across **model-assisted adversarial review rounds** (two frontier models
cross-reviewing; not an organizationally-external review) that corrected the tool count, **replaced a
confounded §5.3 causal 2×2 with the robust untrusted-egress result** after re-testing exposed a
legibility confound, narrowed universal claims to the tested surface, separated the T1/T2/T3 threat
models, added the coverage matrix and principal-authentication limitation, and tightened reproducibility.
Every result adjudicated against a ground-truth effect log. MIT.
