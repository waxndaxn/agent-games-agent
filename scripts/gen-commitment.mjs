// Print the strategy commitment that must be registered on the dashboard
// (Dashboard → My Agents → Edit agent → Steal the VFY) BEFORE Swiss round 1.
//
//   node scripts/gen-commitment.mjs            # uses STV_PARAMS / STV_SALT from env
//   STV_PARAMS=10,30,0,0,0,0,0,0 node scripts/gen-commitment.mjs
//
// Keep STV_SALT private and stable: the commitment hash is public, the salt never leaves the agent,
// and changing either after pairing makes every turn proof invalid.
import { commitment, decide, __internals } from "../src/steal.mjs";

const params = (process.env.STV_PARAMS || "10,30,0,0,0,0,0,0").split(",").map((x) => BigInt(x.trim()));
const salt = process.env.STV_SALT;

if (!salt) {
  console.error("STV_SALT is not set — refusing to print a commitment you cannot reproduce later.");
  process.exit(1);
}

const c = await commitment(params, BigInt(salt));
console.log(JSON.stringify({
  strategyParams: params.map(String),
  commitment: c,
  commitment_hex: "0x" + BigInt(c).toString(16).padStart(64, "0"),
  policy: "mode==1 -> HOLD; selfBalance < p1 -> FORTIFY; opponentBalance <= p2 -> HOLD; else EXTRACT p0",
  params: __internals.DEFAULT_PARAMS.map(String),
  sample_turns: [
    { state: { selfBalance: "100", opponentBalance: "100" }, action: decide({ selfBalance: "100", opponentBalance: "100" }, params) },
    { state: { selfBalance: "10", opponentBalance: "190" }, action: decide({ selfBalance: "10", opponentBalance: "190" }, params) },
    { state: { selfBalance: "120", opponentBalance: "0" }, action: decide({ selfBalance: "120", opponentBalance: "0" }, params) },
  ].map((x) => ({ ...x, action: { ...x.action, amount: String(x.action.amount) } })),
}, null, 1));
process.exit(0);
