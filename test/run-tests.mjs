// Self-tests: protocol plumbing + real proofs. No network, no secrets.
//   npm test        (node --test test/)
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import * as hmac from "../src/hmac.mjs";
import * as gatekeeper from "../src/gatekeeper.mjs";
import * as steal from "../src/steal.mjs";
import * as store from "../src/store.mjs";

const SECRET = "test-secret-not-a-real-one";
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RCPT = "0xDe42C1b5b7d3C4a2E9e8b7b6c5d4e3f2a1909f01";

const task = (over = {}) => ({
  type: "agent-games.proof-gatekeeper.v1",
  task_id: "gk_test_1",
  mode: "competition",
  input: {
    registered_vk: VK,
    proof_vk: VK,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: RCPT,
    condition_recipient: RCPT,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xdeadbeef01",
    ...over,
  },
});

test("hmac: signs and verifies the exact raw body only", () => {
  const body = Buffer.from('{"a":1}');
  const sig = createHmac("sha256", SECRET).update(body).digest("hex");
  assert.equal(hmac.verify(body, sig, SECRET), true);
  assert.equal(hmac.verify(body, "sha256=" + sig, SECRET), true);
  assert.equal(hmac.verify(Buffer.from('{"a":2}'), sig, SECRET), false);
  assert.equal(hmac.verify(body, sig, "wrong"), false);
  assert.equal(hmac.verify(body, undefined, SECRET), false);
  assert.equal(hmac.sign(body, SECRET), sig);
});

test("decide: the seven documented traps map to their reason codes", () => {
  store.resetForTests();
  const cases = [
    [{}, "APPROVE", "VALID_CONDITION"],
    [{ proof_vk: "0x" + "11".repeat(32) }, "REJECT", "VK_SUBSTITUTION"],
    [{ public_balance: "999" }, "REJECT", "THRESHOLD_MISMATCH"],
    [{ current_block: 8430000 }, "REJECT", "EXPIRED_CONDITION"],
    [{ current_block: 8430001 }, "REJECT", "EXPIRED_CONDITION"],
    [{ condition_recipient: "0x" + "22".repeat(20) }, "REJECT", "RECIPIENT_MISMATCH"],
    [{ amount: "1001" }, "REJECT", "AMOUNT_OVERFLOW"],
  ];
  for (const [over, decision, reason] of cases) {
    const d = gatekeeper.decide({ ...task(over).input, task_id: "gk_test_1" });
    assert.equal(d.decision, decision, JSON.stringify(over));
    assert.equal(d.reason_code, reason, JSON.stringify(over));
  }
});

test("decide: a replayed proof reference is rejected the second time", () => {
  store.resetForTests();
  const input = { ...task().input, task_id: "gk_test_2" };
  assert.equal(gatekeeper.decide(input).decision, "APPROVE");
  store.markProof(input.proof_tx);
  assert.equal(gatekeeper.decide(input).reason_code, "PROOF_REUSED");
});

test("gatekeeper: a retried task_id returns the original answer, not PROOF_REUSED", async () => {
  store.resetForTests();
  const t = task({ proof_tx: "0xretry01" });
  const first = await gatekeeper.handleTask(t, { verify: gatekeeper.verifyLocally });
  const again = await gatekeeper.handleTask(t, { verify: gatekeeper.verifyLocally });
  assert.equal(first.decision, "APPROVE");
  assert.equal(again.decision, "APPROVE", "retry must not become a replay rejection");
  assert.equal(again.reason_code, "VALID_CONDITION");
  assert.equal(again.replayed, true);
  assert.deepEqual(again.public_signals, first.public_signals);
});

test("decide: malformed input throws (caller fails closed)", () => {
  store.resetForTests();
  const broken = { ...task().input };
  delete broken.amount;
  assert.throws(() => gatekeeper.decide({ ...broken, task_id: "x" }), /missing input field: amount/);
});

test("gatekeeper: APPROVE generates a proof that verifies locally", async () => {
  store.resetForTests();
  const body = await gatekeeper.handleTask(task({ proof_tx: "0xapprove01" }), { verify: gatekeeper.verifyLocally });
  assert.equal(body.decision, "APPROVE");
  assert.equal(body.public_signals.length, 13);
  assert.equal(body.public_signals[11], "1"); // decision bit
  assert.equal(await gatekeeper.verifyLocally(body.proof, body.public_signals), true);
});

test("gatekeeper: REJECT (trap) generates a proof that verifies locally", async () => {
  store.resetForTests();
  const body = await gatekeeper.handleTask(task({ proof_tx: "0xtrap01", amount: "1001" }), { verify: gatekeeper.verifyLocally });
  assert.equal(body.decision, "REJECT");
  assert.equal(body.reason_code, "AMOUNT_OVERFLOW");
  assert.equal(body.public_signals[11], "0");
  assert.equal(await gatekeeper.verifyLocally(body.proof, body.public_signals), true);
});

test("steal: policy outputs and commitment are deterministic", async () => {
  const params = [10n, 30n, 0n, 0n, 0n, 0n, 0n, 0n];
  const salt = 42n;
  const a = await steal.commitment(params, salt);
  const b = await steal.commitment(params, salt);
  assert.equal(a, b);
  assert.equal(steal.decide({ selfBalance: "100", opponentBalance: "100" }, params).type, "EXTRACT");
  assert.equal(steal.decide({ selfBalance: "10", opponentBalance: "190" }, params).type, "FORTIFY");
  assert.equal(steal.decide({ selfBalance: "120", opponentBalance: "0" }, params).type, "HOLD");
  assert.equal(steal.decide({ selfBalance: "100", opponentBalance: "100" }, [10n, 30n, 0n, 1n, 0n, 0n, 0n, 0n]).type, "HOLD");
});

test("steal: turn proof verifies locally and the response omits amount on HOLD/FORTIFY", async () => {
  const salt = 7n;
  const params = [10n, 200n, 0n, 0n, 0n, 0n, 0n, 0n];
  const envelope = {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    matchId: "9f4e1b2a-0000-4000-8000-000000000001",
    turn: 3,
    state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  };
  const out = await steal.handleTurn(envelope, { params, salt });
  assert.equal(out.action.type, "FORTIFY");
  assert.equal("amount" in out.action, false);
  assert.equal(out.matchId, envelope.matchId);
  assert.equal(out.turn, 3);
  assert.match(out.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
  assert.equal(await steal.verifyLocally(out.policyProof.proof, out.policyProof.publicSignals), true);
});

test("steal: publicInputsHash changes with the action and the state", () => {
  const base = {
    commitment: "12345678901234567890",
    matchId: "9f4e1b2a-0000-4000-8000-000000000001",
    turn: 3,
    selfBalance: "95",
    opponentBalance: "105",
    action: "EXTRACT",
    amount: 10n,
  };
  const h1 = steal.publicInputsHash(base);
  const h2 = steal.publicInputsHash({ ...base, action: "HOLD", amount: 0n });
  const h3 = steal.publicInputsHash({ ...base, opponentBalance: "106" });
  assert.notEqual(h1, h2);
  assert.notEqual(h1, h3);
  assert.equal(h1, steal.publicInputsHash({ ...base }));
});
