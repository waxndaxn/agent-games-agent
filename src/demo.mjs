// Public demo surface: one sample payment request per case, decided by the same code path the platform
// uses, proved with the real circuit, and verified locally before it is shown. Read-only, no secrets.
import * as gatekeeper from "./gatekeeper.mjs";

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RCPT = "0xDe42C1b5b7d3C4a2E9e8b7b6c5d4e3f2a1909f01";

const BASE = {
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
};

const CASES = {
  valid: { label: "Everything checks out", over: {} },
  vk_substitution: { label: "Proof signed by a different verification key", over: { proof_vk: "0x" + "11".repeat(32) } },
  threshold: { label: "Public balance below the required minimum", over: { public_balance: "999" } },
  expired: { label: "Deadline block already reached", over: { current_block: 8430000 } },
  recipient: { label: "Recipient does not match the rule", over: { condition_recipient: "0x" + "22".repeat(20) } },
  amount: { label: "Amount above the transfer cap", over: { amount: "1001" } },
};

export async function demoJson(name = "valid") {
  const spec = CASES[name] || CASES.valid;
  const input = { ...BASE, ...spec.over, proof_tx: "0xdemo_" + name, task_id: "gk_demo_" + name };
  const t0 = Date.now();
  const decision = gatekeeper.decide(input);
  let proofOk = null;
  let publicSignals = null;
  let error = null;
  try {
    const { proof, publicSignals: ps } = await gatekeeper.prove(input, decision.decisionBit);
    publicSignals = ps;
    proofOk = await gatekeeper.verifyLocally(proof, ps);
  } catch (e) {
    error = e.message;
  }
  return {
    case: name,
    label: spec.label,
    request: {
      registered_vk: input.registered_vk.slice(0, 12) + "…",
      proof_vk: input.proof_vk.slice(0, 12) + "…",
      minimum: input.minimum,
      public_balance: input.public_balance,
      amount: input.amount,
      max_transfer: input.max_transfer,
      current_block: input.current_block,
      expiry_block: input.expiry_block,
      recipient: input.recipient.slice(0, 12) + "…",
      condition_recipient: input.condition_recipient.slice(0, 12) + "…",
    },
    decision: decision.decision,
    reason_code: decision.reason_code,
    decision_bit: decision.decisionBit.toString(),
    proof_verified_locally: proofOk,
    public_signals: publicSignals,
    proof_error: error,
    elapsed_ms: Date.now() - t0,
    note:
      "The circuit asserts decision == AND(vk match, balance>=minimum, currentBlock<expiryBlock, recipient match, amount<=maxTransfer), " +
      "so an APPROVE proof can only exist when every check passes, and a REJECT proof only when one fails.",
  };
}

export async function demoHtml() {
  const rows = Object.entries(CASES)
    .map(([k, v]) => `<button data-case="${k}">${v.label}</button>`)
    .join("");
  return `<!doctype html><meta charset="utf-8"><title>Payment gatekeeper — live demo</title>
<style>
 :root{color-scheme:dark}
 body{font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:#0b0d10;color:#e6edf3;margin:0;padding:32px;max-width:900px}
 h1{font-size:20px;margin:0 0 4px} p.sub{color:#8b949e;margin:0 0 20px}
 button{background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:8px 12px;margin:0 8px 8px 0;cursor:pointer;font:inherit}
 button:hover{border-color:#58a6ff} pre{background:#11151a;border:1px solid #21262d;border-radius:8px;padding:14px;overflow:auto}
 .ok{color:#3fb950} .bad{color:#f85149} code{color:#79c0ff}
</style>
<h1>Proof-backed payment gatekeeper</h1>
<p class="sub">Click a request. The agent decides, writes a Groth16 proof of the decision, and verifies it locally before answering.</p>
<div>${rows}</div>
<pre id="out">pick a case…</pre>
<script>
const out = document.getElementById("out");
document.querySelectorAll("button").forEach(b => b.onclick = async () => {
  out.textContent = "deciding and proving…";
  const r = await fetch("/demo/run?case=" + b.dataset.case).then(r => r.json());
  out.innerHTML = [
    "case:            " + r.case + "  (" + r.label + ")",
    "decision:        " + r.decision + "  [" + r.reason_code + "]",
    "decision bit:    " + r.decision_bit,
    "proof verifies:  " + (r.proof_verified_locally ? '<span class=ok>true</span>' : '<span class=bad>false</span>'),
    "public signals:  " + (r.public_signals ? r.public_signals.length : 0),
    "elapsed:         " + r.elapsed_ms + " ms",
    "",
    r.note
  ].join("\\n");
});
</script>`;
}
