// Load generator for the intake: sends OTLP JSON batches of GenAI-style spans and,
// like the Collector's retry_on_failure, retries each batch until it gets a 200.
// Every span has a unique trace id, so the database count can be reconciled exactly.
//
//   node fixtures/load/load.mjs --url http://127.0.0.1:8788 --token <otlp token> \
//        --batches 2000 --spans 50 --concurrency 8 [--run-id r1]
//
// Prints one JSON line: spans sent, retries, elapsed seconds, spans per second accepted.

import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";

const { values } = parseArgs({
  options: {
    url: { type: "string", default: "http://127.0.0.1:8788" },
    token: { type: "string" },
    batches: { type: "string", default: "1000" },
    spans: { type: "string", default: "50" },
    concurrency: { type: "string", default: "8" },
    "run-id": { type: "string", default: randomBytes(4).toString("hex") },
  },
});
const batches = Number(values.batches), perBatch = Number(values.spans), conc = Number(values.concurrency);
const runId = values["run-id"];
const models = ["gpt-4o-mini", "claude-sonnet-4-5", "gemini-2.5-flash"];
const agents = ["refund-bot", "support-agent", "kyc-checker", "invoice-matcher", "ticket-summariser"];

function batchBody(b) {
  const now = BigInt(Date.now()) * 1_000_000n;
  const spans = [];
  for (let i = 0; i < perBatch; i++) {
    spans.push({
      traceId: randomBytes(16).toString("hex"), spanId: randomBytes(8).toString("hex"),
      name: `chat ${models[i % 3]}`, kind: 3,
      startTimeUnixNano: String(now), endTimeUnixNano: String(now + 700_000_000n),
      attributes: [
        { key: "gen_ai.operation.name", value: { stringValue: "chat" } },
        { key: "gen_ai.request.model", value: { stringValue: models[i % 3] } },
        { key: "gen_ai.usage.input_tokens", value: { intValue: String(100 + i) } },
        { key: "gen_ai.usage.output_tokens", value: { intValue: "40" } },
        { key: "zenai4.load.run", value: { stringValue: runId } },
      ],
      status: { code: i % 20 === 0 ? 2 : 1 },
    });
  }
  return JSON.stringify({ resourceSpans: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: agents[b % agents.length] } }] }, scopeSpans: [{ scope: { name: "load" }, spans }] }] });
}

let next = 0, retries = 0, sent = 0;
const t0 = Date.now();
async function worker() {
  for (;;) {
    const b = next++;
    if (b >= batches) return;
    const body = batchBody(b);
    for (;;) {
      try {
        const r = await fetch(`${values.url}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${values.token}` }, body });
        if (r.status === 200) { await r.arrayBuffer(); break; }
        await r.arrayBuffer();
      } catch { /* intake down: retry */ }
      retries++;
      await new Promise((res) => setTimeout(res, 250));
    }
    sent += perBatch;
  }
}
await Promise.all(Array.from({ length: conc }, worker));
const secs = (Date.now() - t0) / 1000;
console.log(JSON.stringify({ runId, spansSent: sent, batches, retries, seconds: secs, spansPerSecondAccepted: Math.round(sent / secs) }));
