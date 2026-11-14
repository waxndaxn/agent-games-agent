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
// One secret per registered agent; comma-separated. The response is always signed with the secret that
// verified the request, so two agents (Proof Gatekeeper + Steal the VFY) can share one endpoint.
const SECRETS = (process.env.AGENT_GAMES_HMAC_SECRETS || process.env.AGENT_GAMES_HMAC_SECRET || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const HARD_DEADLINE_MS = Number(process.env.HARD_DEADLINE_MS || 45000);
const LOG = (process.env.LOG_LEVEL || "info") !== "silent";

function log(...a) {
  if (LOG) console.log(new Date().toISOString(), ...a);
}

function send(res, status, body, { sign = true, secret = null } = {}) {
  const raw = Buffer.from(JSON.stringify(body));
  const headers = { "content-type": "application/json", "content-length": raw.length };
  const key = secret || SECRETS[0];
  if (sign && key) headers["x-agent-games-signature"] = hmac.sign(raw, key);
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

    // Public demo surface (read-only, no HMAC): lets a reviewer watch one decision get made and proved.
    if (req.method === "GET" && req.url.startsWith("/demo")) {
      try {
        const { demoJson, demoHtml } = await import("./demo.mjs");
        if (req.url.startsWith("/demo/run")) {
          const out = await demoJson(new URL(req.url, "http://x").searchParams.get("case") || "valid");
          return send(res, 200, out, { sign: false });
        }
        const html = await demoHtml();
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-length": Buffer.byteLength(html) });
        return res.end(html);
      } catch (e) {
        log("demo error", e.message);
        return send(res, 500, { error: e.message }, { sign: false });
      }
    }

    if (req.method !== "POST" || !req.url?.startsWith(PATH)) {
      log("reject", req.method, req.url, "path mismatch");
      return send(res, 404, { error: "not found" });
    }
    if (!SECRETS.length) {
      log("reject: no HMAC secret configured");
      return send(res, 500, { error: "agent misconfigured" }, { sign: false });
    }

    const sig = req.headers["x-agent-games-signature"];
    const matched = hmac.verifyAny(raw, sig, SECRETS);
    if (!matched) {
      log("reject: bad hmac", { bytes: raw.length, sig: String(sig).slice(0, 12) });
      return send(res, 401, { error: "bad signature" }, { sign: false });
    }

    let envelope;
    try {
      envelope = JSON.parse(raw.toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid json" }, { secret: matched });
    }

    const started = Date.now();
    try {
      const out = await withTimeout(route(envelope), HARD_DEADLINE_MS);
      log("handled", envelope.type || envelope.eventId || "?", envelope.task_id || envelope.matchId || "", `${Date.now() - started}ms`, out.replayed ? "replay" : "");
      return send(res, out.status || 200, out.body, { secret: matched });
    } catch (e) {
      // Fail closed: a decision we cannot prove is worse than an honest rejection.
      log("task error -> REJECT", e.message);
      if (String(envelope.type || "").includes("proof-gatekeeper")) {
        return send(res, 200, {
          decision: "REJECT",
          reason_code: "INTERNAL_ERROR",
          ...(envelope?.input?.proof_tx ? { proof_tx: envelope.input.proof_tx } : {}),
        }, { secret: matched });
      }
      const fallback = {
        matchId: envelope?.matchId ?? null,
        turn: envelope?.turn ?? null,
        action: { type: "HOLD" },
        policyProof: { circuitVersion: "v1" },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: `${envelope?.matchId}-${envelope?.turn}`,
      };
      return send(res, 200, fallback, { secret: matched });
    }
  });
});

server.listen(PORT, () => {
  log(`agent listening on :${PORT}${PATH}`);
  log(`secrets loaded: ${SECRETS.length}`);
  if (!SECRETS.length) log("WARNING: no HMAC secret configured — every task will be rejected");
});

export { server };
