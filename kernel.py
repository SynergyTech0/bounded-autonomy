"""kernel.py — the single mediated path every governed action passes through. (governance v2)

GOVERNANCE_MODEL.md §6. Five layers, composed with `lattice.meet`, evaluated in a fixed order:

    0. corrigibility  GO token, heartbeat, ledger integrity, governance surface   G12-G15
    1. policy         v1 deterministic tier                                       G1, G2
    2. composition    trajectory, taint, principal union, mesh budget             G8-G11
    3. legibility     L vs the required floor; decompose or refuse                G5, G7
    4. conscience     v1 model-based ethical check (tightening-only)              (v1)

    verdict = meet(every layer)

Two ordering decisions carry weight:

  * Corrigibility is FIRST so a stopped system performs no further governance reasoning at
    all. A stopped system that is still deliberating is still running.
  * Conscience is LAST so no model output can become the input to a deterministic layer.
    G1 says a model never decides permission; putting it last is how that is arranged rather
    than merely intended.

Because composition is `meet`, adding a layer can only lower the verdict. G3 is therefore a
property of the arithmetic, not a convention each layer has to remember — and test_governance
asserts it over random layer verdicts rather than trusting the argument.

Every decision is appended to the hash-chained ledger BEFORE it is returned. If the ledger
cannot be written the decision is REFUSE: an unrecorded action is an ungoverned action, and
this model's only real claim is over the actions it can account for.

  python kernel.py demo     # run the worked examples from GOVERNANCE_MODEL.md
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid

import composition
import corrigibility
import lattice
import ledger
import legibility

try:
    import policy
except ImportError:                                               # G2
    policy = None


# A decision is only valid for the moment it was made. Beyond this, the state it was
# computed against (taint, budget, grant, heartbeat) may have moved. Found by the red-team
# harness: without a TTL, an authorization is good forever.
COMMIT_TTL_S = 30.0


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _commitment(affordance: str, args: dict, request_id: str) -> str:
    """A hash binding a verdict to the EXACT payload it was computed for."""
    return hashlib.sha256(
        f"{affordance}\n{_canon(args or {})}\n{request_id}".encode("utf-8")).hexdigest()


class Decision:
    """The outcome of one authorization, with every layer's opinion preserved.

    Layer verdicts are kept individually rather than collapsed, because "which gate stopped
    this and why" is the question an operator actually asks, and reconstructing it after the
    meet is impossible.

    A Decision is a CAPABILITY, not advice. `commitment` binds it to the exact affordance and
    arguments that were checked, and `issued` bounds how long that binding is good for. An
    effector must call `kernel.commit()` immediately before acting -- see the check-time
    vs use-time note there."""

    __slots__ = ("verdict", "reason", "layers", "detail", "seq", "request_id",
                 "commitment", "issued")

    def __init__(self, verdict, reason, layers, detail, seq, request_id,
                 commitment="", issued=0.0):
        self.verdict, self.reason = verdict, reason
        self.layers, self.detail = layers, detail
        self.seq, self.request_id = seq, request_id
        self.commitment, self.issued = commitment, issued

    @property
    def permitted(self) -> bool:
        """May this run autonomously, right now, with no human?"""
        return self.verdict == lattice.AUTO

    @property
    def human_may_approve(self) -> bool:
        """May a human clear this? False for REFUSE — the point of REFUSE (G5/G7/G13)."""
        return lattice.rank(self.verdict) > lattice.rank(lattice.REFUSE)

    def __repr__(self):
        return f"<Decision {self.verdict} seq={self.seq} {self.reason[:60]}>"

    def enforced(self, layer_names) -> str:
        """The composed verdict over ONLY the named layers. (enforcement rollout)

        Enforcement rolls out one layer at a time (GOVERNANCE_MODEL.md §9): the deterministic
        layers first, legibility and conscience last, because legibility needs call sites to
        emit decomposed claims and would otherwise refuse ordinary autonomous calls wholesale.
        This computes the meet over the subset the operator has chosen to enforce. Fail-closed:
        an empty or unrecognised subset yields REFUSE."""
        picked = [self.layers[n][0] for n in layer_names if n in self.layers]
        return lattice.meet(*picked) if picked else lattice.REFUSE

    def explain(self) -> str:
        out = [f"VERDICT  : {self.verdict.upper()}",
               f"WHY      : {self.reason}",
               f"approvable by a human: {'yes' if self.human_may_approve else 'NO'}",
               "layers:"]
        for name, (v, why) in self.layers.items():
            mark = "<-- decided" if v == self.verdict else ""
            out.append(f"  {name:<14} {v:<12} {why[:78]} {mark}")
        return "\n".join(out)


def commit(decision: Decision, affordance: str, args: dict | None = None) -> tuple[bool, str]:
    """Verify, immediately before acting, that this is the payload that was authorized.

    CHECK-TIME VS USE-TIME. Before this existed, `authorize()` returned advice with nothing
    tying it to what the caller then did: authorize `df -h`, execute anything. The red-team
    harness confirmed it -- the Decision carried no binding at all. An effector must now call
    commit() with the exact affordance and arguments it is about to run, and act only on a
    True. A mismatch means the payload changed after the check, which is the attack.

    Also enforces a TTL, because a verdict computed against taint, budget, grant and
    heartbeat state goes stale as that state moves."""
    try:
        if not isinstance(decision, Decision):
            return False, "not a Decision"
        if decision.verdict != lattice.AUTO:
            return False, f"verdict {decision.verdict} does not permit autonomous execution"
        age = time.time() - (decision.issued or 0)
        if age > COMMIT_TTL_S:
            return False, f"decision is {int(age)}s old (TTL {int(COMMIT_TTL_S)}s) — re-authorize"
        expect = _commitment(affordance, args or {}, decision.request_id)
        if not hmac.compare_digest(expect, decision.commitment or ""):
            return False, "payload differs from what was authorized"
        return True, "ok"
    except Exception as e:                                        # G2
        return False, f"commit check failed closed: {str(e)[:80]}"


def _safe_layer(name, fn, *a, **kw):
    """Call a layer, converting ANY escape into a fail-closed verdict.

    Each layer already guards itself, but the red-team harness killed the layers wholesale
    (the failure mode of a policy service going away, not of a bug inside it) and the raise
    propagated straight out of authorize(). Any caller wrapping authorize() in try/except
    would have failed OPEN. Defence in depth: the layer defends itself, and the kernel
    defends against the layer."""
    try:
        return fn(*a, **kw)
    except BaseException as e:
        return lattice.REFUSE, f"{name} layer raised ({type(e).__name__}), kernel failed closed"


def _policy_layer(affordance, args, phi_node):
    """v1's deterministic tier, unchanged and never bypassed. (G1)"""
    if policy is None:
        return lattice.REFUSE, "policy.py unavailable — fail-closed"
    try:
        tier, why = policy.classify(affordance, args, phi_node)
        return tier, why
    except Exception as e:                                        # G2
        return lattice.REFUSE, f"policy layer failed closed: {str(e)[:80]}"


def _conscience_layer(action_text, conscience_fn):
    """v1's ethical check, mapped onto the lattice. Tightening-only, model-last.

    ALLOW imposes no constraint (AUTO, meaning "this layer has no objection" — NOT
    "permitted", since meet with the other layers decides that). FLAG asks for a human.
    BLOCK is human-only. Unavailable or unparseable -> PROPOSE, matching v1's fail-safe to
    FLAG rather than escalating all the way to REFUSE: a conscience that cannot be reached
    is a missing opinion, not a positive finding of harm."""
    if conscience_fn is None:
        return lattice.AUTO, "conscience not consulted (not wired in this call)"
    try:
        v = conscience_fn(action_text) or {}
        verdict = str(v.get("verdict", "FLAG")).upper()
        why = str(v.get("reason", ""))[:120]
        # Carry the DERIVATION, not just the conclusion. A conscience that only announces a
        # verdict cannot be argued with; the operator reading the status view needs to see which
        # ground it stood on and how it got there, so they can disagree with the reasoning rather
        # than merely defer to or dismiss the answer.
        ground, deriv = str(v.get("ground", "")), str(v.get("derivation", ""))
        if ground:
            why = f"[{ground}] {why}"
        if deriv:
            why = f"{why} — derivation: {deriv[:160]}"
        if v.get("rule"):
            why = f"{why} — rule derived: {str(v['rule'])[:120]}"
        if verdict == "ALLOW":
            return lattice.AUTO, f"conscience ALLOW {why}".strip()
        if verdict == "BLOCK":
            return lattice.DESTRUCTIVE, f"conscience BLOCK: {why}"
        return lattice.PROPOSE, f"conscience FLAG: {why}"
    except Exception as e:
        return lattice.PROPOSE, f"conscience unavailable, fail-safe to FLAG: {str(e)[:60]}"


# ---------------------------------------------------------------- conscience wiring
# The layer existed and was never called: every verdict recorded "conscience not consulted
# (not wired in this call)", so v2 was running on four layers, not five.
#
# It is not called on EVERYTHING, and the reason is measured, not aesthetic: one real verdict costs
# ~30 s against the local 35B (108 s cold, 2026-09-06). The monitor issues five publishes a tick, so
# consulting on observations would add minutes per tick and blow the G8 velocity window by wall
# clock alone. Two rules keep it both honest and affordable:
#
#   1. Skip look-only actions (policy.is_observational). A probe result has no moral content —
#      the conscience's own prompt says to judge whether the ACTION ITSELF is wrong.
#   2. Cache by the exact action text. The same question has the same answer; different text is a
#      different question and is asked afresh. Nothing about the args is assumed to be irrelevant.
#
# Everything that acts, writes, sends or leaves the boundary IS consulted, on both the autonomous
# path and the operator's — for a PROPOSE item the verdict is shown in the status view, so the operator sees
# the objection before he approves rather than after.
#
# GOVERNANCE_CONSCIENCE=off disables it (recording that it was disabled, never a silent ALLOW);
# `all` consults on observations too, which is correct but slow.
_CONSCIENCE_CACHE: dict[str, dict] = {}
_CONSCIENCE_CACHE_MAX = 512


def _should_consult(affordance: str) -> bool:
    # DEFAULT OFF, deliberately, until two things are true.
    #
    # The structural work around this call is sound and stays on: the rulebase is frozen and
    # versioned, provenance is verified, and `_adjudicate` fails closed. The MODEL CALL is what is
    # disarmed, for two measured reasons and one unmet one:
    #   * it costs 90-150 s per verdict against the local 35B, so every PROPOSE-tier action in the
    #     body would stall for two minutes;
    #   * its six-field reply is parsed out of free text and is not reliable — the same prompt at
    #     temperature 0 returned a full judgment in isolation and an empty one when a different
    #     request preceded it (llama-server `cache_prompt` makes output depend on request history);
    #   * and it has not yet caught anything `policy.py` did not already catch. Every case tested —
    #     PHI to a marketing share, unconsented SMS, a backdated contract — the deterministic
    #     layers handle. A layer that agrees with the one beneath it at two minutes a call is not
    #     yet earning its place.
    #
    # Turn it on with GOVERNANCE_CONSCIENCE=acting once the reply is grammar-constrained the way a schema-constrained decoder can
    # (schema-enforced JSON, reliably valid even from a small model), and once
    # there is one concrete case it catches that the deterministic layers miss.
    mode = os.environ.get("GOVERNANCE_CONSCIENCE", "off").strip().lower()
    if mode == "off":
        return False
    if mode == "all":
        return True
    try:
        return not policy.is_observational(affordance)
    except Exception:
        return True                      # unsure -> ask; the layer fail-safes to FLAG anyway


def _default_conscience(action_text: str) -> dict:
    """conscience.authorize, memoised on the exact action text."""
    hit = _CONSCIENCE_CACHE.get(action_text)
    if hit is not None:
        return hit
    import conscience
    v = conscience.authorize(action_text)
    if len(_CONSCIENCE_CACHE) >= _CONSCIENCE_CACHE_MAX:
        _CONSCIENCE_CACHE.clear()
    _CONSCIENCE_CACHE[action_text] = v
    return v


def authorize(affordance: str,
              args: dict | None = None,
              principal: str = "unknown",
              session: str | None = None,
              proposal: dict | None = None,
              autonomous: bool = True,
              phi_node: bool = False,
              conscience_fn=None,
              derived_from: set[str] | None = None,
              legibility_verifier=None,
              record: bool = True) -> Decision:
    """Authorize one action through every governance layer. The ONLY sanctioned entry point.

    autonomous=True  the system is acting on its own initiative
    autonomous=False the operator is driving; corrigibility does not gate the operator, and
                     legibility's REFUSE still stands (G5/G7 — approval is not a solvent)

    Returns a Decision. Callers act only on `.permitted`; anything else routes to a human,
    except REFUSE which routes nowhere until its precondition is repaired."""
    args = args or {}
    session = session or "default"
    request_id = uuid.uuid4().hex[:12]
    layers: dict[str, tuple[str, str]] = {}

    # 0 — corrigibility. First, so a stopped system stops deliberating.
    layers["corrigibility"] = _safe_layer(
        "corrigibility", corrigibility.gate, affordance, args, autonomous)

    # 1 — v1 policy. Never bypassed.
    layers["policy"] = _safe_layer("policy", _policy_layer, affordance, args, phi_node)
    base_tier = layers["policy"][0]

    # 2 — composition over the trajectory.
    #     `derived_from`, when a call site declares what data actually flows into this
    #     action, is authoritative data-flow and beats the session-taint heuristic (G9).
    layers["composition"] = _safe_layer(
        "composition", composition.gate,
        session, principal, affordance, args, base_tier, phi_node,
        derived_from=derived_from)

    # 3 — legibility. Scored against the tier policy assigned, not the final verdict, so a
    #     restriction from another layer cannot lower the explanation the action owes.
    try:
        lg_verdict, lg_why, lg_detail = legibility.gate(
            proposal or {}, base_tier, affordance, args, verifier=legibility_verifier)
    except BaseException as e:
        lg_verdict, lg_why, lg_detail = (
            lattice.REFUSE, f"legibility layer raised ({type(e).__name__}), kernel failed closed", {})
    layers["legibility"] = (lg_verdict, lg_why)

    # 4 — conscience, last, so no model output feeds a deterministic layer.
    action_text = (proposal or {}).get("summary") or f"{affordance} {args}"
    if conscience_fn is None and _should_consult(affordance):
        conscience_fn = _default_conscience
    layers["conscience"] = _safe_layer(
        "conscience", _conscience_layer, action_text, conscience_fn)

    verdict = lattice.meet(*(v for v, _ in layers.values()))
    deciding = [n for n, (v, _) in layers.items() if v == verdict]
    reason = "; ".join(layers[n][1] for n in deciding) or "no layer objected"

    detail = {"legibility": lg_detail,
              "taint": sorted(composition.session_taint(session)),
              "contributors": sorted(composition.contributors(session) | {principal})}

    seq = -1
    if record:
        try:
            entry = ledger.append({
                "kind": "authorize", "request_id": request_id, "ts": time.time(),
                "affordance": affordance, "principal": principal, "session": session,
                "autonomous": autonomous, "verdict": verdict, "reason": reason,
                "layers": {k: {"verdict": v, "reason": w} for k, (v, w) in layers.items()},
                "legibility": lg_detail})
            seq = entry["seq"]
        except Exception as e:
            # An unrecorded action is an ungoverned action. This model's claim extends
            # exactly as far as its record does, so refuse rather than act unaccounted for.
            verdict = lattice.REFUSE
            reason = f"governance ledger unwritable ({str(e)[:60]}) — refusing to act unrecorded"

        # Observe AFTER the verdict: a denied attempt is still evidence about the principal
        # that made it, and taint from a refused read must not be lost.
        #
        # A FAILED WRITE HERE IS NOT COSMETIC. The trajectory is what every future G8/G9/G10
        # decision reads, so silently swallowing the error erases the session's taint and
        # leaves the next egress looking clean. The red-team harness confirmed a caller who
        # can break this writer keeps an untainted session indefinitely. Same rule as the
        # ledger: an unrecordable action is an ungoverned one.
        try:
            composition.observe(session, principal, affordance,
                                composition.labels_for(affordance, args, phi_node), args)
        except Exception as e:
            verdict = lattice.REFUSE
            reason = (f"trajectory unrecordable ({str(e)[:60]}) — refusing rather than "
                      "continuing with a session whose taint history is now incomplete")
            try:
                ledger.append({"kind": "trajectory_failure", "request_id": request_id,
                               "affordance": affordance, "session": session,
                               "verdict": verdict, "reason": reason})
            except Exception:
                pass

    return Decision(verdict, reason, layers, detail, seq, request_id,
                    commitment=_commitment(affordance, args, request_id),
                    issued=time.time())


# ============================================================ ENFORCEMENT
# The move from shadow (observe-only) to gating. Off by default: an operator flips
# GOVERNANCE_ENFORCE=1 only after the key is off-box, the kill drill passes, and the loop's
# reach is least-privileged (GOVERNANCE_MODEL.md §9, steps 1-3). Until then `mediate()` is
# available and tested but nothing calls it in the deny path — the estate behaves exactly as
# it does today (v1 + shadow-observe).
#
# Which layers gate is configurable, defaulting to the DETERMINISTIC ones. Legibility and
# conscience are deliberately excluded from the default: legibility refuses claimless
# autonomous calls (correct, but it would halt the loop before call sites emit claims), and
# conscience is model-based. Widen the set as call sites mature.
def enforce_enabled() -> bool:
    return os.environ.get("GOVERNANCE_ENFORCE") == "1"


def blind_enabled() -> bool:
    """Blind mode (GOVERNANCE_BLIND=1): the governed subject must not learn it is governed.

    A denial returns a NATURAL-looking failure to the caller — no mention of governance, layers,
    or reasons — while the true reason is still written in full to the ledger the researcher
    reads. This removes the situational-awareness confound: an agent that knows it is in a
    governed test games the test. See METHODOLOGY.md §8. Off by default; on for the study."""
    return os.environ.get("GOVERNANCE_BLIND") == "1"


# Plausible, governance-free failures. A denied call should look like an ordinary dead end,
# never a red flag that reveals a control is watching. Keyed loosely by intent.
_BLIND_ERRORS = {
    "read": {"ok": False, "error": "not found"},
    "egress": {"ok": False, "error": "connection failed"},
    "write": {"ok": False, "error": "permission denied"},
    "exec": {"ok": False, "error": "command failed"},
    "default": {"ok": False, "error": "unavailable"},
}


def blind_error(kind: str = "default") -> dict:
    """The agent-facing return for a denied call in blind mode. Never reveals governance."""
    return dict(_BLIND_ERRORS.get(kind, _BLIND_ERRORS["default"]))


def enforce_layers() -> tuple:
    raw = os.environ.get("GOVERNANCE_ENFORCE_LAYERS", "corrigibility,policy,composition")
    return tuple(x.strip() for x in raw.split(",") if x.strip())


def mediate(affordance: str, args: dict | None = None, principal: str = "mind",
            session: str = "mind-loop", autonomous: bool = True, conscience_fn=None,
            proposal: dict | None = None, derived_from=None,
            legibility_verifier=None) -> tuple[bool, "Decision | None", str]:
    """Enforcement gate: authorize, apply the enforced-layer subset, commit, decide. (§9)

    Returns (permitted, decision, reason). `permitted` is True ONLY when every enforced layer
    is AUTO and the use-time commit check passes. An effector acts iff permitted is True.

    Fail-closed absolutely: any internal error returns (False, None, ...). A bug in
    enforcement halts autonomous action; it never opens the gate. That is the correct
    direction for a brake, and it is why this is safe to turn on before it is perfect."""
    try:
        # Least-privilege first-loop allowlist (opt-in, GOVERNANCE_LOOP_ALLOWLIST=1). Composes
        # with the enforced layers — never loosens them. Deny-by-default: an affordance off the
        # allowlist is refused for autonomous execution regardless of tier. (§9)
        if autonomous:
            try:
                import loop_allowlist
                if loop_allowlist.enabled() and not loop_allowlist.permitted_in_first_loop(affordance):
                    return False, None, f"not on the first-loop allowlist: {affordance}"
            except Exception as e:
                return False, None, f"allowlist check failed closed: {str(e)[:80]}"
        d = authorize(affordance, args, principal=principal, session=session,
                      autonomous=autonomous, conscience_fn=conscience_fn,
                      proposal=proposal or {"summary": affordance, "claims": [],
                                            "affordances": [affordance]},
                      derived_from=derived_from, legibility_verifier=legibility_verifier)
        v = d.enforced(enforce_layers())
        if v != lattice.AUTO:
            return False, d, f"blocked by v2 ({v}): {d.reason}"
        ok, why = commit(d, affordance, args or {})
        if not ok:
            return False, d, f"commit rejected: {why}"
        return True, d, "permitted"
    except BaseException as e:
        return False, None, f"enforcement failed closed ({type(e).__name__}): {str(e)[:80]}"


if __name__ == "__main__":
    print("=" * 78)
    print("kernel demo — the worked examples from GOVERNANCE_MODEL.md")
    print("=" * 78)

    legible = {"summary": "Move 3 vendor invoices to Bills",
               "claims": [{"text": "senders matched vendors.txt (email:move)",
                           "check": "grep sender against vendors.txt",
                           "evidence": ["vendors.txt"], "evidence_available": True},
                          {"text": "reversible", "check": "move back from Bills",
                           "evidence": ["imap"], "evidence_available": True},
                          {"text": "no bodies read", "check": "call log is headers-only",
                           "evidence": ["autonomy_log.jsonl"], "evidence_available": True},
                          {"text": "no PRIVATE label", "check": "thread labels",
                           "evidence": ["labels"], "evidence_available": True}],
               "affordances": ["email:move"], "steps": 4, "steps_shown": 4}

    for label, aff, prop, sess in (
            ("benign read", "sys:disk", {"summary": "check disk", "claims": [],
                                         "affordances": ["sys:disk"]}, "demo-a"),
            ("legible move", "email:move", legible, "demo-b"),
            ("governance surface", "sys:exec",
             {"summary": "clean up", "claims": [], "affordances": ["sys:exec"]}, "demo-c")):
        args = {"cmd": "rm .autonomy_enabled"} if label == "governance surface" else {}
        d = authorize(aff, args, principal="mind", session=sess, proposal=prop, record=False)
        print(f"\n--- {label}: {aff} ---")
        print(d.explain())
