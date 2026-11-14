// Tiny persistent store: used proof references (replay defence) and turn idempotency keys.
// JSON file, atomic-ish write, no dependencies. The process is single-instance by design.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const FILE = process.env.STORE_PATH || "./data/store.json";

function load() {
  try {
    return JSON.parse(readFileSync(FILE, "utf8"));
  } catch {
    return { usedProofs: {}, idempotency: {}, seenTurns: {} };
  }
}

let state = load();

function persist() {
  mkdirSync(dirname(FILE), { recursive: true });
  const tmp = FILE + ".tmp";
  writeFileSync(tmp, JSON.stringify(state));
  renameSync(tmp, FILE);
}

/** Has this proof reference already backed another task? */
export function proofSeen(proofTx) {
  if (!proofTx) return false;
  return Object.prototype.hasOwnProperty.call(state.usedProofs, String(proofTx).toLowerCase());
}

/** Record a proof reference. Called for every task we answer, so a replay is caught next time. */
export function markProof(proofTx, meta = {}) {
  if (!proofTx) return;
  const k = String(proofTx).toLowerCase();
  if (state.usedProofs[k]) return;
  state.usedProofs[k] = { at: new Date().toISOString(), ...meta };
  persist();
}

/** First submission per idempotency key wins; later duplicates are recognised. */
export function idempotencySeen(key) {
  if (!key) return false;
  return Object.prototype.hasOwnProperty.call(state.idempotency, key);
}

export function markIdempotency(key, response) {
  if (!key) return;
  state.idempotency[key] = { at: new Date().toISOString(), response };
  persist();
}

/** Gatekeeper tasks: a retried task_id must return the original response, not a replay rejection. */
export function getTaskResponse(taskId) {
  if (!taskId) return null;
  return state.tasks?.[taskId] ?? null;
}

export function markTaskResponse(taskId, response) {
  if (!taskId) return;
  state.tasks = state.tasks || {};
  state.tasks[taskId] = response;
  persist();
}

export function getTurnResponse(key) {
  return state.idempotency[key]?.response ?? null;
}

export function resetForTests() {
  state = { usedProofs: {}, idempotency: {}, seenTurns: {}, tasks: {} };
  persist();
}
