# Wildcard submission — Proof-backed payment gatekeeper

**Agent link:** https://github.com/waxndaxn/agent-games-agent
**Public endpoint:** https://wieldable-wham-pretender.ngrok-free.dev/agent
**Live demo (no auth, click a case):** https://wieldable-wham-pretender.ngrok-free.dev/demo

---

## 1. The problem

Every treasury, DAO, and now every agentic payment stack has the same weak link: **the approval step**.
Someone — a human clicking a button, or an LLM calling a tool — decides that a payment request is fine,
and the only record of *why* is a log line.

Proofs alone do not fix this. A payment can arrive with a perfectly valid zero-knowledge proof attached
and still be the wrong payment: the proof may be signed by a different verification key than the one
registered for that condition, the recipient may differ from the rule, the deadline may have passed, or
the amount may exceed the transfer cap. **A valid proof is necessary, not sufficient.**

Who this helps: a finance/ops team approving payouts, a DAO treasury, or an autonomous agent that pays
for services — anyone who needs the approval itself to be checkable after the fact, by a third party,
without trusting the approver's logs.

## 2. What the agent does

A single HTTPS service. The platform (or any caller) POSTs a signed JSON payment request; the agent:

1. verifies the HMAC signature over the **raw** request body before parsing anything;
2. runs five deterministic checks — verification-key match, balance above the minimum, deadline block not
   reached, recipient equals the rule's recipient, amount within the transfer cap — plus an off-circuit
   replay check on the proof reference;
3. decides APPROVE or REJECT with a machine-readable `reason_code`;
4. **writes its own Groth16 proof** that the decision followed the rule, and verifies that proof locally
   before answering;
5. returns the decision, the reason, the proof and its public signals, signed with its own HMAC.

Fail-closed by construction: timeouts, malformed envelopes and proof failures answer REJECT, never
APPROVE. A decision the agent cannot prove is never an approval.

## 3. What the proof actually establishes (verifiability)

The circuit asserts

```
decision == (registeredVkHash == proofVkHash)
         && (publicBalance >= minimum)
         && (currentBlock < expiryBlock)
         && (recipient == conditionRecipient)
         && (amount <= maxTransfer)
```

so the 13 public signals are a **checkable claim**: *"this approval satisfied all five conditions at this
task id"* — without revealing the private witness. A reviewer can re-verify the proof against the
platform's registered key. The circuit is the referee, not the agent's word.

What it does **not** establish, and the write-up says so plainly: that the underlying payment is
commercially legitimate, that the counterparty is trustworthy, or that the same proof was never used
before (replay is an off-circuit check, and the agent answers those rejections without a proof because
no witness exists).

## 4. Evidence it works

- `npm test` — 9 checks: HMAC over raw body, all seven trap classes, replay, malformed input, and real
  Groth16 proofs generated and verified locally.
- `npm run e2e` — 10 checks against the running server: preflight, approve, replay, trap, bad signature,
  and a tournament turn.
- Live, right now, over the public internet: `/demo` renders six requests; each decision returns in
  **≈250 ms** with `proof_verified_locally: true` and 13 public signals.
- Gatekeeper production traffic: every task answered well inside the 60 s window (typical 0.3–0.8 s).

## 5. Key decisions

- **Deterministic code decides; no model in the decision path.** A language model may propose, but the
  five checks are arithmetic — and the circuit makes the answer un-fakeable.
- **Proof generated locally, verified before it is returned.** A proof that fails local verification is
  never sent; an APPROVE without evidence is never sent.
- **HMAC over the raw bytes, before JSON parsing**, so a tampered body cannot reach the router.
- **Per-agent secrets** (comma-separated list) so one endpoint can serve several agents, each response
  signed with the key that authenticated the request.
- **Two circuits, one service**: the same process plays the payment gatekeeper and the head-to-head
  strategy game, which is what a real agent host looks like — one endpoint, several skills.

## 6. Limits, stated up front

- The two circuits are the competition's; the agent supplies the decision logic, the proving pipeline and
  the transport.
- Single-asset, single-rule demo. A production version needs a rule registry and an allowlist of
  registered verification keys.
- Replay defence is a local store, not a shared one; two instances would each need their own seen-set or
  a shared KV.
