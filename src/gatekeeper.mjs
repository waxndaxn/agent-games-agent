// Proof Gatekeeper: deterministic decision + a Groth16 proof that the decision followed the circuit's rule.
//
// The platform's gatekeeper circuit (13 public signals, 1 private `salt`) asserts
//     decision == (registeredVkHash == proofVkHash)
//              && (publicBalance >= minimum)
//              && (currentBlock < expiryBlock)
//              && (recipient == conditionRecipient)
//              && (amount <= maxTransfer)
// so an APPROVE proof only exists when every check passes, and a REJECT proof only when at least one
// fails. Boundary confirmed against the circuit: currentBlock == expiryBlock counts as EXPIRED.
//
// Public signal order (verified by generating and locally verifying a proof):
//   [0] commitment (in-circuit Poseidon(salt, taskId)) [1] registeredVkHash [2] proofVkHash
//   [3] minimum [4] publicBalance [5] expiryBlock [6] currentBlock [7] recipient
//   [8] conditionRecipient [9] amount [10] maxTransfer [11] decision [12] taskId
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as store from "./store.mjs";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs"); // NB: `import * as snarkjs` hangs on this Node build; require works
const { keccak256 } = require("js-sha3");

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = process.env.CIRCUITS_DIR || join(HERE, "..", "circuits");
const WASM = join(CIRCUITS, "gatekeeper.wasm");
const ZKEY = join(CIRCUITS, "gatekeeper_final.zkey");

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => {
  const r = x % FIELD;
  return r >= 0n ? r : r + FIELD;
};

export const REASONS = Object.freeze({
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
});

const norm = (v) => String(v).toLowerCase().replace(/^0x/, "");
const big = (v, field) => {
  try {
    return BigInt(v);
  } catch {
    throw new Error(`field ${field} is not an integer: ${v}`);
  }
};

/**
 * The checklist, in the order the platform documents. First failure decides `reason_code`.
 * Fails closed: malformed input throws, and the caller answers REJECT.
 */
export function decide(input) {
  const required = [
    "registered_vk", "proof_vk", "minimum", "public_balance", "expiry_block",
    "current_block", "recipient", "condition_recipient", "amount", "max_transfer",
  ];
  for (const k of required) {
    if (input?.[k] === undefined || input[k] === null || input[k] === "") {
      throw new Error(`missing input field: ${k}`);
    }
  }
  if (norm(input.proof_vk) !== norm(input.registered_vk)) return { decision: "REJECT", reason_code: REASONS.VK, decisionBit: 0n };
  if (big(input.public_balance, "public_balance") < big(input.minimum, "minimum")) return { decision: "REJECT", reason_code: REASONS.THRESHOLD, decisionBit: 0n };
  if (input.proof_tx && store.proofSeen(input.proof_tx)) return { decision: "REJECT", reason_code: REASONS.REUSED, decisionBit: 0n };
  if (big(input.current_block, "current_block") >= big(input.expiry_block, "expiry_block")) return { decision: "REJECT", reason_code: REASONS.EXPIRED, decisionBit: 0n };
  if (norm(input.recipient) !== norm(input.condition_recipient)) return { decision: "REJECT", reason_code: REASONS.RECIPIENT, decisionBit: 0n };
  if (big(input.amount, "amount") > big(input.max_transfer, "max_transfer")) return { decision: "REJECT", reason_code: REASONS.AMOUNT, decisionBit: 0n };
  return { decision: "APPROVE", reason_code: REASONS.VALID, decisionBit: 1n };
}

/**
 * The two conversions the platform never published. Both are deterministic and equal-for-equal, which is
 * what matters for the proof; switch modes with env vars if practice mode reports a signal mismatch.
 */
export function vkToField(hex, mode = process.env.VK_HASH_MODE || "bigint") {
  const raw = String(hex).replace(/^0x/, "");
  if (mode === "keccak") return modP(BigInt("0x" + keccak256(Buffer.from(raw, "hex"))));
  return modP(BigInt("0x" + raw));
}

export function taskIdToField(id, mode = process.env.TASK_ID_MODE || "keccak") {
  if (mode === "bigint") {
    const hex = Buffer.from(String(id), "utf8").toString("hex");
    return modP(BigInt("0x" + hex));
  }
  return modP(BigInt("0x" + keccak256(String(id))));
}

export function circuitInput(input, decisionBit, salt = process.env.GATEKEEPER_SALT || "1") {
  return {
    registeredVkHash: vkToField(input.registered_vk).toString(),
    proofVkHash: vkToField(input.proof_vk).toString(),
    minimum: big(input.minimum, "minimum").toString(),
    publicBalance: big(input.public_balance, "public_balance").toString(),
    expiryBlock: big(input.expiry_block, "expiry_block").toString(),
    currentBlock: big(input.current_block, "current_block").toString(),
    recipient: modP(BigInt("0x" + norm(input.recipient))).toString(),
    conditionRecipient: modP(BigInt("0x" + norm(input.condition_recipient))).toString(),
    amount: big(input.amount, "amount").toString(),
    maxTransfer: big(input.max_transfer, "max_transfer").toString(),
    decision: decisionBit.toString(),
    taskId: taskIdToField(input.task_id || input.taskId || "unknown").toString(),
    salt: BigInt(salt).toString(),
  };
}

export async function prove(input, decisionBit) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput(input, decisionBit), WASM, ZKEY);
  return { proof, publicSignals };
}

export async function verifyLocally(proof, publicSignals) {
  const vk = JSON.parse(readFileSync(join(CIRCUITS, "gatekeeper_vk.json"), "utf8"));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

/**
 * Submit to zkVerify through Kurier and wait for a Finalized result.
 * Only Finalized counts as confirmed (build guide §03).
 */
export async function submitToKurier(proof, publicSignals) {
  const key = process.env.KURIER_API_KEY;
  if (!key) throw new Error("KURIER_API_KEY not set");
  const base = process.env.KURIER_URL || "https://api.kurier.xyz/api/v1";
  const vk = process.env.GATEKEEPER_VK_HASH || "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

  const res = await fetch(`${base}/submit-proof/${key}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk },
    }),
  });
  if (!res.ok) throw new Error(`kurier submit ${res.status}: ${(await res.text()).slice(0, 200)}`);
  let job = await res.json();
  const deadline = Date.now() + Number(process.env.KURIER_POLL_MS || 20000);
  while (!["Finalized", "Aggregated"].includes(job.status)) {
    if (["Failed", "Rejected", "Error"].includes(job.status)) throw new Error(`kurier job ${job.status}`);
    if (Date.now() > deadline) throw new Error("kurier poll timeout");
    await new Promise((r) => setTimeout(r, 1500));
    const poll = await fetch(`${base}/job-status/${key}/${job.jobId}`);
    if (!poll.ok) throw new Error(`kurier poll ${poll.status}`);
    job = await poll.json();
  }
  return job;
}

/**
 * Handle one gatekeeper task. Returns the response body (already shaped for the platform).
 * `includeProof=false` is only for local tests and for the fail-closed path where proving failed.
 */
export async function handleTask(task, { includeProof = true, verify = null } = {}) {
  const input = { ...task.input, task_id: task.task_id };

  // Idempotency: the platform retries after network failures. A retried task must get the same answer —
  // deciding again would trip the replay check and turn a valid approval into PROOF_REUSED.
  const cached = store.getTaskResponse(task.task_id);
  if (cached) return { ...cached, replayed: true };

  const decision = decide(input);
  store.markProof(input.proof_tx, { taskId: task.task_id });

  const body = { decision: decision.decision, reason_code: decision.reason_code };
  if (input.proof_tx) body.proof_tx = input.proof_tx;
  if (!includeProof) return body;

  // PROOF_REUSED is an off-circuit check: the circuit only encodes the five on-chain conditions, so a
  // replay rejection has no witness. Answer with the decision alone (a missing proof costs -2; the wrong
  // decision would cost more) instead of failing the task outright.
  try {
    const { proof, publicSignals } = await prove(input, decision.decisionBit);
    if (verify) {
      const ok = await verify(proof, publicSignals);
      if (!ok) throw new Error("self-verify failed: refusing to return an invalid proof");
    }
    body.proof = proof;
    body.public_signals = publicSignals;
  } catch (e) {
    body.proof_error = e.message;
    if (decision.decision === "APPROVE") throw e; // never approve without evidence
  }
  store.markTaskResponse(task.task_id, body);
  return body;
}
