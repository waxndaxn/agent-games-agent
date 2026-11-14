// End-to-end: boot the real server, POST HMAC-signed envelopes, verify the signed responses.
//   npm run e2e
import { spawn } from "node:child_process";
import { rmSync } from "node:fs";
import { createHmac } from "node:crypto";

const SECRET = "e2e-secret";
const PORT = 8931;
const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RCPT = "0xDe42C1b5b7d3C4a2E9e8b7b6c5d4e3f2a1909f01";
const sign = (buf) => createHmac("sha256", SECRET).update(buf).digest("hex");

// fresh store per run, otherwise previously used proof references come back as PROOF_REUSED
rmSync("./data/e2e-store.json", { force: true });

const child = spawn(process.execPath, ["src/server.mjs"], {
  env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT), LOG_LEVEL: "silent", STORE_PATH: "./data/e2e-store.json" },
  stdio: ["ignore", "inherit", "inherit"],
});
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
await wait(900);

const post = async (body, { badSig = false } = {}) => {
  const raw = Buffer.from(JSON.stringify(body));
  const res = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "0".repeat(64) : sign(raw) },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get("x-agent-games-signature"), body: JSON.parse(text), raw: text };
};

const results = [];
const check = (name, cond, extra = "") => { results.push([name, cond]); console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${extra}`); };

// 1. preflight
const pre = await post({ type: "agent-games.preflight.v1", agent_id: "agt_e2e", issued_at: new Date().toISOString(), nonce: "abc123" });
check("preflight -> {ok:true,protocolVersion:v1}", pre.status === 200 && pre.body.ok === true && pre.body.protocolVersion === "v1", JSON.stringify(pre.body));
check("preflight response is HMAC-signed", pre.sig === sign(Buffer.from(pre.raw)));

// 2. a valid payment task
const task = {
  type: "agent-games.proof-gatekeeper.v1", task_id: "gk_e2e_1", mode: "competition",
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: {
    registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
    expiry_block: 8430000, current_block: 8420000, recipient: RCPT, condition_recipient: RCPT,
    amount: "500", max_transfer: "1000", proof_tx: "0xe2e0001",
  },
};
const t0 = Date.now();
const ok = await post(task);
check("valid task -> APPROVE", ok.body.decision === "APPROVE", `${Date.now() - t0}ms`);
check("APPROVE carries a 13-signal proof", Array.isArray(ok.body.public_signals) && ok.body.public_signals.length === 13);
check("APPROVE response signed", ok.sig === sign(Buffer.from(ok.raw)));

// 3. the same proof reference again -> PROOF_REUSED
const replay = await post({ ...task, task_id: "gk_e2e_2" });
check("replayed proof_tx -> REJECT PROOF_REUSED", replay.body.reason_code === "PROOF_REUSED", JSON.stringify(replay.body.reason_code));

// 4. a trap
const trap = await post({ ...task, task_id: "gk_e2e_3", input: { ...task.input, proof_tx: "0xe2e0002", condition_recipient: "0x" + "22".repeat(20) } });
check("recipient trap -> REJECT RECIPIENT_MISMATCH", trap.body.reason_code === "RECIPIENT_MISMATCH", JSON.stringify(trap.body.reason_code));

// 5. bad signature
const bad = await post({ type: "agent-games.preflight.v1" }, { badSig: true });
check("bad HMAC -> 401", bad.status === 401, String(bad.status));

// 6. Steal the VFY turn
const turn = await post({
  protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
  matchId: "9f4e1b2a-0000-4000-8000-00000000e2e1", turn: 3,
  issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 60000).toISOString(),
  state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: "0x7d" }, resolverVersion: "v1", nonce: "3c2f1a",
});
check("turn -> action echoed with matchId/turn", turn.body.matchId === "9f4e1b2a-0000-4000-8000-00000000e2e1" && turn.body.turn === 3, JSON.stringify(turn.body.action));
check("turn carries policyProof with a hash", /^0x[0-9a-f]{64}$/.test(turn.body.policyProof?.publicInputsHash || ""));

child.kill("SIGKILL");
const failed = results.filter(([, c]) => !c).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
