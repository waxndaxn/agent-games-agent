# agent-games-agent

zkVerify **Agent Games** entry — one HTTPS service that plays two tracks:

- **Proof Gatekeeper** — decide APPROVE/REJECT on a proof-backed payment request, then write a Groth16
  proof (platform circuit) that the decision followed the circuit's rule.
- **Steal the VFY** — a committed policy that answers tournament turns, with a Groth16 proof that the
  action is exactly what the committed strategy produces for that game state.

Everything runs locally; the model is not in the loop for any decision. Deterministic code decides, the
circuit proves, and the platform re-verifies against its own verification key.

## Verified protocol facts (not guesses)

Measured against the published artifacts (`/api/circuit-info`, `circuits/*.wasm`, `*.zkey`) by generating
proofs and verifying them locally — see `npm test`.

**Gatekeeper circuit** — 13 public signals, 1 private input (`salt`):

| # | public signal | source |
|---|---|---|
| 0 | commitment | `Poseidon(salt, taskId)` computed **in-circuit** (never computed here) |
| 1–2 | registeredVkHash, proofVkHash | `input.registered_vk`, `input.proof_vk` |
| 3–6 | minimum, publicBalance, expiryBlock, currentBlock | task input |
| 7–8 | recipient, conditionRecipient | task input |
| 9–10 | amount, maxTransfer | task input |
| 11 | decision | 1 = APPROVE, 0 = REJECT |
| 12 | taskId | task id |

The circuit **asserts** `decision == (vkMatch && balance>=minimum && currentBlock<expiryBlock &&
recipientMatch && amount<=maxTransfer)`. Consequences:

- an APPROVE proof only exists when every check passes; a REJECT proof only exists when one fails;
- `currentBlock == expiryBlock` is **expired** (the circuit puts equality on the reject side);
- `PROOF_REUSED` is **off-circuit** (the circuit has no replay memory), so that rejection is returned
  without a proof — a missing proof costs −2, a wrong decision costs more.

**Steal the VFY circuit** — 9 public signals, 17 inputs
(`commitment, strategyParams[0..7], salt, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion`).
`commitment = Poseidon(strategyParams[0..7], salt)` with the salt **last**; `publicSignals[0]` is a
binding value produced in-circuit from `(salt, matchId, turnNumber)`, so it is never computed here.

## The policy (this entry)

```
mode == 1                  -> HOLD
selfBalance < p1           -> FORTIFY        (defensive tail: fortify only when badly weakened)
opponentBalance <= p2      -> HOLD           (nothing worth taking)
otherwise                  -> EXTRACT p0     (p0 = extract amount, 1..10)
```

Committed parameters: `10,30,0,0,0,0,0,0` (extract 10, fortify below 30, extract whenever the opponent
holds anything, active mode). The strategy hash must be registered on the dashboard **before Swiss round 1**;
the platform freezes it for the tournament and rejects turns proven with a different version.

## Quickstart

```bash
npm ci
cp .env.example .env            # fill it in; .env is gitignored
npm test                        # 9 unit tests: HMAC, 7 traps, real proofs verified locally
npm run e2e                     # boots the server, 10 checks: preflight, approve, replay, trap, turn
node scripts/gen-commitment.mjs # prints the Steal the VFY commitment to paste into the dashboard
npm start                       # listens on :8080 /agent
```

`.env`:

```
AGENT_GAMES_HMAC_SECRET=   # dashboard → Rotate Secret (one-time plaintext) — not a placeholder
KURIER_API_KEY=            # zkVerify Kurier mainnet key, for on-chain attestation
STV_SALT=                  # private, stable, never commit
STV_PARAMS=10,30,0,0,0,0,0,0
GATEKEEPER_SALT=1
PORT=8080
AGENT_PATH=/agent
```

## Deploy

Any always-on HTTPS host works; the platform POSTs to the exact path you register (`/agent`, not the root).

```bash
docker build -t agent-games .
docker run -p 8080:8080 --env-file .env agent-games
```

`GET /health` is unsigned and exists for uptime checks. Anything else requires a valid
`x-agent-games-signature` over the raw body, and every response is signed the same way.

## Register (dashboard)

1. **Repository URL** — this repo (public, personal account).
2. **Agent endpoint** — `https://<host>/agent` (full handler path).
3. **Tracks** — Proof Gatekeeper + Steal the VFY.
4. **Rotate Secret** → copy the plaintext into `AGENT_GAMES_HMAC_SECRET`, restart, then run **preflight**.
   A placeholder secret fails preflight with a signature error.
5. **Strategy commitment** — `node scripts/gen-commitment.mjs`, paste the hash under
   Dashboard → My Agents → Edit agent → Steal the VFY.

## Known unknowns (flagged honestly)

- `registered_vk`/`proof_vk` → field element and `task_id` → field element are undocumented conversions.
  Defaults: `BigInt(hex) mod p` and `keccak256(utf8) mod p`, switchable with `VK_HASH_MODE` /
  `TASK_ID_MODE`. If practice mode reports a public-signal mismatch, flip one at a time.
- The turn response carries `policyProof.proof` + `publicSignals` inline (the build guide says to attach
  the proof; the example response only names the hash). Set `STV_PROOF_INLINE=0` if a strict schema
  rejects the extra fields.
- Kurier job polling is capped at `KURIER_POLL_MS` (default 20 s) so the 60 s task deadline is never
  blown by a slow attestation.

## Security posture

- HMAC verified over **raw bytes before JSON parsing**; mismatches answer 401 and never reach the router.
- Fail closed: timeouts, proof failures and malformed envelopes answer REJECT (or HOLD), never APPROVE.
- No secrets in the repo: `.env` gitignored, `.env.example` blank, the STV salt stays private.
- The proof is generated locally and self-verified before it is returned.
