// Steal the VFY: committed policy + Groth16 proof that the action is exactly what the committed
// strategy produces for this turn state.
//
// Circuit (platform-provided, 9 public signals / 17 input signals). Input order recovered from the
// artifacts and verified by generating + locally verifying a proof:
//   commitment, strategyParams[0..7], salt, matchId, turnNumber, selfBalance, opponentBalance,
//   action, amount, circuitVersion
// Public signals: [0] binding Poseidon(salt, matchId, turnNumber) — produced in-circuit, never computed
// by us; [1..8] commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount,
// circuitVersion.
//
// The strategy is fixed at commitment time: the dashboard registers its hash, the platform freezes it
// for the tournament, and any turn whose action is not the policy's output cannot be proven at all.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const { keccak256 } = require("js-sha3");
const { buildPoseidon } = require("circomlibjs");

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = process.env.CIRCUITS_DIR || join(HERE, "..", "circuits");
const WASM = join(CIRCUITS, "vfy-policy.wasm");
const ZKEY = join(CIRCUITS, "vfy-policy_final.zkey");

const DEFAULT_PARAMS = (process.env.STV_PARAMS || "10,30,0,0,0,0,0,0")
  .split(",")
  .map((x) => BigInt(x.trim()));
const SALT = BigInt(process.env.STV_SALT || "12345678901234567890");
export const ACTION = Object.freeze({ HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n });
const ACTION_NAME = ["HOLD", "FORTIFY", "EXTRACT"];

let poseidonPromise = null;
const poseidon = () => (poseidonPromise ||= buildPoseidon());

/** Commitment over the 8 strategy parameters + private salt (salt LAST). Registered on the dashboard. */
export async function commitment(params = DEFAULT_PARAMS, salt = SALT) {
  if (params.length !== 8) throw new Error("strategyParams must be exactly 8 field elements");
  const p = await poseidon();
  const h = p([...params.map((x) => BigInt(x)), BigInt(salt)]);
  return p.F.toString(h);
}

/**
 * The committed policy, evaluated on the turn state. Deterministic by construction.
 *   mode == 1                -> HOLD
 *   selfBalance < minSelf    -> FORTIFY   (defensive tail)
 *   opponentBalance <= minOpp-> HOLD      (nothing worth taking)
 *   otherwise                -> EXTRACT extractAmount
 */
export function decide(state, params = DEFAULT_PARAMS) {
  const [extract, minSelf, minOpp, mode] = params;
  const self_ = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  if (mode === 1n) return { type: "HOLD", amount: 0n };
  if (self_ < minSelf) return { type: "FORTIFY", amount: 0n };
  if (opp <= minOpp) return { type: "HOLD", amount: 0n };
  return { type: "EXTRACT", amount: extract };
}

const toBytes32 = (v) => {
  const x = BigInt(v);
  if (x < 0n) throw new Error("negative value cannot be packed");
  const hex = x.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("value exceeds 32 bytes");
  return Buffer.from(hex, "hex");
};

/** keccak256 of the ABI-packed turn fields, in the platform's documented order. */
export function publicInputsHash({ commitment: c, matchId, turn, selfBalance, opponentBalance, action, amount = 0n }) {
  const packed = Buffer.concat([
    toBytes32(c),
    toBytes32(BigInt("0x" + String(matchId).replace(/-/g, ""))),
    toBytes32(turn),
    toBytes32(selfBalance),
    toBytes32(opponentBalance),
    toBytes32(ACTION[action]),
    toBytes32(amount),
    toBytes32(1n), // circuitVersion "v1"
  ]);
  return "0x" + keccak256(packed);
}

export function circuitInput({ commitment: c, matchId, turn, state, action, amount = 0n }, params = DEFAULT_PARAMS, salt = SALT) {
  if (params.length !== 8) throw new Error("strategyParams must be exactly 8");
  return {
    commitment: String(c),
    strategyParams: params.map((x) => String(x)),
    salt: String(salt),
    matchId: BigInt("0x" + String(matchId).replace(/-/g, "")).toString(),
    turnNumber: String(turn),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: ACTION[action].toString(),
    amount: String(amount),
    circuitVersion: "1",
  };
}

export async function prove(turn, params = DEFAULT_PARAMS, salt = SALT) {
  const c = await commitment(params, salt);
  const decision = decide(turn.state, params);
  const input = circuitInput({ ...turn, commitment: c, action: decision.type, amount: decision.amount }, params, salt);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals, decision, commitment: c };
}

export async function verifyLocally(proof, publicSignals) {
  const vk = JSON.parse(readFileSync(join(CIRCUITS, "vfy-policy_vk.json"), "utf8"));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

/** Shape the turn response exactly as the build guide specifies (amount omitted for HOLD/FORTIFY). */
export async function handleTurn(envelope, opts = {}) {
  const params = opts.params || DEFAULT_PARAMS;
  const salt = opts.salt || SALT;
  const turn = { matchId: envelope.matchId, turn: envelope.turn, state: envelope.state };
  const { proof, publicSignals, decision, commitment: c } = await prove(turn, params, salt);

  const action = { type: decision.type };
  if (decision.type === "EXTRACT") action.amount = Number(decision.amount);
  if (decision.type === "HOLD" || decision.type === "FORTIFY") {
    if ("amount" in action) delete action.amount;
  }

  const policyProof = {
    circuitVersion: "v1",
    publicInputsHash: publicInputsHash({
      commitment: c,
      matchId: envelope.matchId,
      turn: envelope.turn,
      selfBalance: envelope.state.selfBalance,
      opponentBalance: envelope.state.opponentBalance,
      action: decision.type,
      amount: decision.amount,
    }),
  };
  if (process.env.STV_PROOF_INLINE !== "0") {
    policyProof.proof = proof;
    policyProof.publicSignals = publicSignals;
  }

  return {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: opts.idempotencyKey || `${envelope.matchId}-${envelope.turn}`,
  };
}

export const __internals = { ACTION_NAME, DEFAULT_PARAMS, SALT };
