// Agent Games endpoint: one HTTPS service, two tracks (Proof Gatekeeper, Steal the VFY).
//
// Contract, from https://agentgames.zkverify.io/build:
//   - the platform POSTs a signed JSON envelope to the exact registered path (default /agent)
//   - the HMAC in `x-agent-games-signature` is verified over the RAW body before parsing
//   - every response is signed the same way
//   - 60 s hard deadline; fail closed (REJECT) on any error or uncertainty
//
// Run:  node src/server.mjs        (env: AGENT_GAMES_HMAC_SECRET, PORT, AGENT_PATH, KURIER_API_KEY)
import http from "node:http";
import * as hmac from "./hmac.mjs";
import * as gatekeeper from "./gatekeeper.mjs";
import * as steal from "./steal.mjs";
import * as store from "./store.mjs";

const PORT = Number(process.env.PORT || 8080);
const PATH = process.env.AGENT_PATH || "/agent";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const HARD_DEADLINE_MS = Number(process.env.HARD_DEADLINE_MS || 45000);
const LOG = (process.env.LOG_LEVEL || "info") !== "silent";

function log(...a) {
  if (LOG) console.log(new Date().toISOString(), ...a);
}

function send(res, status, body, { sign = true } = {}) {
  const raw = Buffer.from(JSON.stringify(body));
  const headers = { "content-type": "application/json", "content-length": raw.length };
  if (sign && SECRET) headers["x-agent-games-signature"] = hmac.sign(raw, SECRET);
  res.writeHead(status, headers);
  res.end(raw);
}

function withTimeout(promise, ms) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, rej) => {
      t = setTimeout(() => rej(new Error("hard deadline exceeded")), ms);
    }),
  ]);
}

async function route(envelope) {
  const type = String(envelope?.type || "");

  if (type === "agent-games.preflight.v1") return { body: { ok: true, protocolVersion: "v1" } };

  if (type.includes("proof-gatekeeper")) {
    const body = await gatekeeper.handleTask(envelope, { verify: gatekeeper.verifyLocally });
    return { body };
  }

  if (envelope.eventId === "steal-the-vfy" || type.includes("steal") || envelope.matchId) {
    const key = envelope.idempotencyKey || `${envelope.matchId}-${envelope.turn}`;
    const prior = store.getTurnResponse(key);
    if (prior) return { body: prior, replayed: true };
    const body = await steal.handleTurn(envelope);
    store.markIdempotency(key, body);
    return { body };
  }

  return { status: 400, body: { error: `unsupported envelope type: ${type || "unknown"}` } };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => {
    chunks.push(c);
    if (chunks.reduce((n, b) => n + b.length, 0) > 2_000_000) req.destroy();
  });
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);

    if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true, path: PATH });

    if (req.method !== "POST" || !req.url?.startsWith(PATH)) {
      log("reject", req.method, req.url, "path mismatch");
      return send(res, 404, { error: "not found" });
    }
    if (!SECRET) {
      log("reject: AGENT_GAMES_HMAC_SECRET not set");
      return send(res, 500, { error: "agent misconfigured" }, { sign: false });
    }

    const sig = req.headers["x-agent-games-signature"];
    if (!hmac.verify(raw, sig, SECRET)) {
      log("reject: bad hmac", { bytes: raw.length, sig: String(sig).slice(0, 12) });
      return send(res, 401, { error: "bad signature" }, { sign: false });
    }

    let envelope;
    try {
      envelope = JSON.parse(raw.toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid json" });
    }

    const started = Date.now();
    try {
      const out = await withTimeout(route(envelope), HARD_DEADLINE_MS);
      log("handled", envelope.type || envelope.eventId || "?", envelope.task_id || envelope.matchId || "", `${Date.now() - started}ms`, out.replayed ? "replay" : "");
      return send(res, out.status || 200, out.body);
    } catch (e) {
      // Fail closed: a decision we cannot prove is worse than an honest rejection.
      log("task error -> REJECT", e.message);
      if (String(envelope.type || "").includes("proof-gatekeeper")) {
        return send(res, 200, {
          decision: "REJECT",
          reason_code: "INTERNAL_ERROR",
          ...(envelope?.input?.proof_tx ? { proof_tx: envelope.input.proof_tx } : {}),
        });
      }
      const fallback = {
        matchId: envelope?.matchId ?? null,
        turn: envelope?.turn ?? null,
        action: { type: "HOLD" },
        policyProof: { circuitVersion: "v1" },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: `${envelope?.matchId}-${envelope?.turn}`,
      };
      return send(res, 200, fallback);
    }
  });
});

server.listen(PORT, () => {
  log(`agent listening on :${PORT}${PATH}`);
  if (!SECRET) log("WARNING: AGENT_GAMES_HMAC_SECRET is empty — every task will be rejected");
});

export { server };
