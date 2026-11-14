// HMAC-SHA256 over the RAW request/response body, per the Agent Games build guide:
// the platform signs every task with `x-agent-games-signature`, and every response must be signed
// the same way. Verification runs on the raw bytes, before JSON parsing.
import { createHmac, timingSafeEqual } from "node:crypto";

const HEX64 = /^[0-9a-fA-F]{64}$/;
const B64 = /^[A-Za-z0-9+/=]{43,44}$/;

/** Normalise whatever the platform put in the header into a 32-byte Buffer. */
export function parseSignature(header) {
  if (!header) return null;
  let v = String(header).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7);
  if (HEX64.test(v)) return Buffer.from(v, "hex");
  if (B64.test(v)) {
    try {
      const b = Buffer.from(v, "base64");
      if (b.length === 32) return b;
    } catch {
      /* fall through */
    }
  }
  return null;
}

export function sign(rawBody, secret) {
  if (!secret) throw new Error("AGENT_GAMES_HMAC_SECRET is not set");
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

/** True only when the header is a valid HMAC of the exact raw body. Fails closed on anything odd. */
export function verify(rawBody, header, secret) {
  if (!secret) return false;
  const given = parseSignature(header);
  if (!given) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  if (given.length !== expected.length) return false;
  return timingSafeEqual(given, expected);
}
