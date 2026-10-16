// Phase 1.1 tests: telemetry intake, redaction, storage guarantees and
// reconciliation against the registry.
// Run: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { buildControlPlane, DEFAULT_PROFILES } from "../control/control-plane.js";
import { createSecureGateway } from "../gateway/secure-server.js";
import type { RegistrationRequest } from "../control/registration.js";
import type { TelemetryConfig } from "./config.js";
import { luhnValid, redactString } from "./redact.js";
import { mapSpan, parseOtlpTraces } from "./mapping.js";
import { modelPermitted } from "./reconcile.js";

const DAY = 86_400_000;
const CHECKLIST = { identity_verified: true, least_privilege_reviewed: true, data_classification_confirmed: true, logging_enabled: true, kill_switch_tested: true };

const regBody = (over: Partial<RegistrationRequest> = {}): RegistrationRequest => ({
  name: "DocReader", purpose: "Summarises internal docs", ownerEmail: "alice@example.com", subOwnerEmail: "bob@example.com",
  accessProfileId: "internal-readonly", businessUnit: "Ops", platform: "custom", modelProvider: "anthropic", modelVersion: "claude-haiku-4-5",
  autonomyDefault: "A1", mode: "enforcement", tools: [{ toolName: "read_docs", reversible: true, dataClasses: ["internal"] }], budgetPolicy: {}, ...over,
});

function clock(start = Date.now()) {
  let t = start;
  return { now: () => new Date(t), advance: (ms: number) => { t += ms; } };
}

async function mkEnv(opts: { now?: () => Date; telemetry?: Partial<TelemetryConfig> } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "zenai4-p11-"));
  const cp = buildControlPlane({ dbPath: join(dir, "cp.db"), now: opts.now, readTelemetryEnv: false, telemetry: { gapGraceMs: 0, ...opts.telemetry } });
  for (const p of DEFAULT_PROFILES) cp.profiles.upsert(p);
  const people: Array<[string, any[]]> = [
    ["alice@example.com", ["agent_owner"]], ["bob@example.com", ["agent_owner"]], ["carol@example.com", ["security_reviewer"]],
    ["dave@example.com", ["admin"]], ["erin@example.com", ["auditor"]], ["olga@example.com", ["agent_owner"]],
  ];
  for (const [email, roles] of people) cp.directory.upsert({ email, displayName: email.split("@")[0], active: true, roles });
  const app = createSecureGateway(cp, { trustProxy: true });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const tok: Record<string, string> = {};
  for (const [email] of people) tok[email.split("@")[0]] = cp.credentials.issueUserToken(email).token;
  const api = async (method: string, path: string, token?: string, body?: unknown, extra: Record<string, string> = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { "content-type": extra["content-type"] ?? "application/json", "x-forwarded-for": extra.ip ?? "10.0.0.1", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json: any;
    try { json = JSON.parse(text); } catch { json = undefined; }
    return { status: res.status, json, text };
  };
  return {
    cp, api, tok,
    source: (capture: "none" | "metadata" | "redacted" = "metadata", name = "otel-vm1") => cp.telemetry.createSource(name, "otlp", capture, "carol@example.com"),
    register: (over: Partial<RegistrationRequest> = {}) => {
      const r = cp.registration.submit(regBody(over), "alice@example.com");
      assert.ok(r.ok, JSON.stringify(!r.ok && r.violations));
      return r;
    },
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      cp.close();
    },
  };
}

const dump = (cp: ReturnType<typeof buildControlPlane>) => {
  const out: string[] = [];
  for (const { name } of cp.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>) {
    out.push(JSON.stringify(cp.db.prepare(`SELECT * FROM "${name}"`).all()));
  }
  return out.join("\n") + "\n" + cp.audit.exportJsonl({ limit: 1_000_000 });
};
const count = (cp: ReturnType<typeof buildControlPlane>, table: string) => (cp.db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as any).n as number;

const step = (seq: number, over: Record<string, unknown> = {}) => ({ session_id: "sess-1", seq, ts: new Date().toISOString(), ...over });

// ------------------------------------------------------------ authentication

test("intake: unauthenticated batch gets 401 and nothing is stored", async () => {
  const env = await mkEnv();
  try {
    const before = count(env.cp, "intake_batches");
    for (const path of ["/v1/intake/steps", "/v1/intake/otlp"]) {
      for (const ctype of ["application/json", "text/csv", "application/yaml"]) {
        const r = await env.api("POST", path, undefined, JSON.stringify({ steps: [step(0, { prompt: "hello" })] }), { "content-type": ctype });
        assert.equal(r.status, 401);
        assert.deepEqual(r.json, { error: "unauthorized" });
      }
    }
    assert.equal(count(env.cp, "intake_batches"), before);
    assert.equal(count(env.cp, "telemetry_steps"), 0);
    assert.equal(count(env.cp, "telemetry_sessions"), 0);
    // A human token is authenticated but may not send telemetry.
    const h = await env.api("POST", "/v1/intake/steps", env.tok.alice, { steps: [step(0)] });
    assert.equal(h.status, 403);
    assert.equal(count(env.cp, "telemetry_steps"), 0);
  } finally { await env.close(); }
});

test("intake: unknown or bad credentials feed discovery without storing the secret", async () => {
  const env = await mkEnv();
  try {
    const { source } = env.source();
    const badSource = `zsrc.${source.id}.${"S".repeat(43)}`;
    const unknownSource = `zsrc.nosuchsrc1.${"U".repeat(43)}`;
    const unknownAgent = `gai.a.zzzzzzzzzzzz.${"A".repeat(43)}`;
    const providerKey = `sk-ant-api03-${"K".repeat(40)}`;
    for (const t of [badSource, unknownSource, unknownAgent, providerKey]) {
      const r = await env.api("POST", "/v1/intake/steps", t, { steps: [step(0)] }, { ip: "10.9.9.9" });
      assert.equal(r.status, 401);
      assert.deepEqual(r.json, { error: "unauthorized" });
    }
    assert.equal(count(env.cp, "telemetry_steps"), 0);
    const gw = env.cp.discovery.list({ source: "gateway" });
    const schemes = gw.map((d) => d.attributes.credentialScheme).sort();
    assert.deepEqual(schemes, ["provider-key", "zenai4-agent", "zenai4-source", "zenai4-source"]);
    const all = dump(env.cp);
    for (const secret of ["S".repeat(43), "U".repeat(43), "A".repeat(43), "K".repeat(40)]) assert.ok(!all.includes(secret), "a presented secret was stored");
    // A source token is refused on non-intake routes.
    const { token } = env.source("metadata", "other");
    const r = await env.api("GET", "/v1/agents", token);
    assert.equal(r.status, 401);
  } finally { await env.close(); }
});

test("intake: source tokens are stored only as hashes and revocation is immediate", async () => {
  const env = await mkEnv();
  try {
    const { source, token } = env.source();
    assert.ok(!dump(env.cp).includes(token.split(".")[2]));
    assert.equal(env.cp.telemetry.sourceTokenHashes().length, 1);
    assert.equal((await env.api("POST", "/v1/intake/steps", token, { steps: [step(0)] })).status, 200);
    env.cp.telemetry.revokeSource(source.id, "carol@example.com", "rotated");
    assert.equal((await env.api("POST", "/v1/intake/steps", token, { steps: [step(1)] })).status, 401);
    assert.throws(() => env.cp.db.prepare(`DELETE FROM intake_sources`).run(), /cannot be deleted/);
  } finally { await env.close(); }
});

// ------------------------------------------------------------ registry linkage

test("intake: unregistered agent telemetry is stored as unregistered and becomes a telemetry discovery row", async () => {
  const env = await mkEnv();
  try {
    const { source, token } = env.source();
    const body = { steps: [step(0, { agent_key: "shadow-bot", tool_name: "send_email", model: "gpt-5" }), step(1, { agent_key: "shadow-bot", model: "gpt-5" })] };
    const r = await env.api("POST", "/v1/intake/steps", token, body);
    assert.equal(r.status, 200);
    assert.equal(r.json.accepted, 2);
    const rows = env.cp.db.prepare(`SELECT agent_id, observed_agent_key FROM telemetry_steps`).all() as any[];
    assert.ok(rows.every((x) => x.agent_id === null && x.observed_agent_key === "shadow-bot"));
    const s1 = env.cp.reconcile.run();
    assert.equal(s1.newDiscoveries, 1);
    // Second batch + second run: same row, count accumulates, no new discovery.
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(2, { agent_key: "shadow-bot", tool_name: "read_crm" })] });
    const s2 = env.cp.reconcile.run();
    assert.equal(s2.newDiscoveries, 0);
    const d = env.cp.discovery.list({ source: "telemetry" });
    assert.equal(d.length, 1);
    assert.equal(d[0].count, 3);
    assert.equal(d[0].kind, "observed_agent");
    assert.equal(d[0].attributes.sourceId, source.id);
    assert.deepEqual((d[0].attributes.tools as string[]).sort(), ["read_crm", "send_email"]);
    // It is in the triage queue and can be claimed like any other discovery.
    assert.equal(env.cp.discovery.list({ queue: "triage" }).filter((x) => x.source === "telemetry").length, 1);
    const claim = env.cp.discovery.claim(d[0].id, "olga@example.com");
    assert.ok(claim.ok);
    assert.equal(env.cp.audit.query({ action: "discovery.sighted" }).filter((e) => e.details.source === "telemetry").length, 1);
  } finally { await env.close(); }
});

test("intake: a registered agent key (id or manifest id) is linked; an agent credential cannot report as another agent", async () => {
  const env = await mkEnv();
  try {
    const a = env.register();
    const b = env.register({ name: "Other" });
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { agent_key: a.agent.id })] });
    assert.equal((env.cp.db.prepare(`SELECT agent_id, agent_state FROM telemetry_steps`).get() as any).agent_id, a.agent.id);
    // Agent credential: identity from the credential.
    const ok = await env.api("POST", "/v1/intake/steps", a.credential!.token, { steps: [step(0, { session_id: "own" })] });
    assert.equal(ok.status, 200);
    const spoof = await env.api("POST", "/v1/intake/steps", a.credential!.token, { steps: [step(1, { session_id: "own", agent_key: b.agent.id })] });
    assert.equal(spoof.status, 422);
    assert.equal(spoof.json.rejected, 1);
    assert.equal(env.cp.audit.query({ action: "identity.mismatch" }).length, 1);
    assert.equal((env.cp.db.prepare(`SELECT count(*) AS n FROM telemetry_steps WHERE agent_id = ?`).get(b.agent.id) as any).n, 0);
  } finally { await env.close(); }
});

// ------------------------------------------------------------ redaction and capture modes

const SECRETS = {
  anthropic: `sk-ant-api03-${"Q".repeat(40)}`,
  zenai4: `gai.a.keyid123.${"Z".repeat(43)}`,
  bearer: `Bearer ${"b".repeat(40)}`,
  password: "hunter2-correct-horse",
};
const PII = {
  email: "jane.doe@customer.example",
  phoneIntl: "+65 9123 4567",
  phoneUs: "(415) 555-0134",
  card: "4111 1111 1111 1111",
  nric: "S1234567D",
  ssn: "123-45-6789",
};

test("redaction: secrets and PII never reach the database or the audit export", async () => {
  const env = await mkEnv();
  try {
    const { token } = env.source("redacted");
    const prompt = `Email ${PII.email} or call ${PII.phoneIntl} / ${PII.phoneUs}. Card ${PII.card}, NRIC ${PII.nric}, SSN ${PII.ssn}. Key ${SECRETS.anthropic} and ${SECRETS.zenai4}. Header ${SECRETS.bearer}`;
    const body = { steps: [step(0, {
      agent_key: `bot ${PII.email}`, tool_name: "crm_lookup", prompt,
      input: { customer: PII.email, password: SECRETS.password, nested: { card: PII.card } },
      output: [`ok ${PII.nric}`],
      policy: { id: "pii-guard", decision: "deny", rule: "no_card_numbers" },
    })] };
    const r = await env.api("POST", "/v1/intake/steps", token, body);
    assert.equal(r.status, 200, r.text);
    const all = dump(env.cp);
    for (const v of [...Object.values(SECRETS), ...Object.values(PII), "Q".repeat(40), "Z".repeat(43)]) {
      assert.ok(!all.includes(v), `raw value stored: ${v}`);
    }
    const row = env.cp.db.prepare(`SELECT prompt_redacted, input_redacted, redaction_counts FROM telemetry_steps`).get() as any;
    assert.match(row.prompt_redacted, /\[email\].*\[phone\].*\[card\].*\[national-id\]/s);
    assert.match(row.input_redacted, /"password":"\[redacted\]"/);
    const counts = JSON.parse(row.redaction_counts);
    assert.ok(counts.email >= 2 && counts.card >= 2 && counts.secret >= 2 && counts.sensitive_key >= 1, row.redaction_counts);
    // The blocked action on the violation is redacted too.
    const v = env.cp.telemetry.listViolations();
    assert.equal(v.length, 1);
    assert.ok(!v[0].blockedAction!.includes(PII.email));
  } finally { await env.close(); }
});

test("redaction: unit cases for Luhn, phones and IDs; non-card digit runs survive", () => {
  assert.equal(luhnValid("4111111111111111"), true);
  assert.equal(luhnValid("4111111111111112"), false);
  const out = redactString("order 4111111111111112 card 5500-0000-0000-0004 ref 2026101612", ["card", "phone", "email", "national_id"]);
  assert.match(out, /order 4111111111111112/);
  assert.match(out, /card \[card\]/);
  assert.match(out, /ref 2026101612/);
  assert.equal(redactString("x T0123456J y", ["national_id"]), "x [national-id] y");
  assert.equal(redactString("call 8123 4567", ["phone"]), "call [phone]");
  assert.equal(redactString("a@b.co", []), "a@b.co", "PII kinds are configurable");
});

test("redaction: payloads are truncated after redaction", async () => {
  const env = await mkEnv({ telemetry: { maxPayloadChars: 100 } });
  try {
    const { token } = env.source("redacted");
    const long = "x".repeat(95) + ` ${SECRETS.anthropic}`;
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { prompt: long })] });
    const row = env.cp.db.prepare(`SELECT prompt_redacted, payload_meta FROM telemetry_steps`).get() as any;
    assert.ok(row.prompt_redacted.startsWith("x".repeat(95)));
    assert.match(row.prompt_redacted, /\[truncated \d+ chars\]$/);
    assert.ok(!row.prompt_redacted.includes("sk-ant"));
    assert.equal(JSON.parse(row.payload_meta).promptTruncated, true);
  } finally { await env.close(); }
});

test("capture modes: none stores no payload information, metadata stores sizes only", async () => {
  const env = await mkEnv();
  try {
    const none = env.source("none", "none");
    const meta = env.source("metadata", "meta");
    const s = step(0, { prompt: "secret plan for Q4", input: { a: 1 }, output: "done", reasoning: "thinking hard" });
    await env.api("POST", "/v1/intake/steps", none.token, { steps: [s] });
    await env.api("POST", "/v1/intake/steps", meta.token, { steps: [s] });
    const rows = env.cp.db.prepare(`SELECT source_id, capture_mode, prompt_redacted, input_redacted, output_redacted, reasoning_redacted, payload_meta FROM telemetry_steps ORDER BY source_id = ?`).all(meta.source.id) as any[];
    const [n, m] = rows;
    assert.equal(n.capture_mode, "none");
    assert.deepEqual(JSON.parse(n.payload_meta), {});
    assert.equal(m.capture_mode, "metadata");
    for (const r of rows) for (const c of ["prompt_redacted", "input_redacted", "output_redacted", "reasoning_redacted"]) assert.equal(r[c], null);
    const pm = JSON.parse(m.payload_meta);
    assert.equal(pm.promptChars, "secret plan for Q4".length);
    assert.equal(pm.reasoning, "dropped");
    assert.ok(!dump(env.cp).includes("secret plan for Q4"));
    // Agent credentials use the configured default (metadata).
    const a = env.register();
    await env.api("POST", "/v1/intake/steps", a.credential!.token, { steps: [step(0, { session_id: "x", prompt: "agent prompt text" })] });
    assert.equal((env.cp.db.prepare(`SELECT capture_mode FROM telemetry_steps WHERE agent_id = ?`).get(a.agent.id) as any).capture_mode, "metadata");
    assert.ok(!dump(env.cp).includes("agent prompt text"));
  } finally { await env.close(); }
});

test("capture: reasoning text is dropped by default and redacted when switched on", async () => {
  const off = await mkEnv();
  const on = await mkEnv({ telemetry: { captureReasoning: true } });
  try {
    const reasoning = `I should email ${PII.email} the plan`;
    for (const env of [off, on]) {
      const { token } = env.source("redacted");
      await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { prompt: "p", reasoning })] });
    }
    const a = off.cp.db.prepare(`SELECT reasoning_redacted, payload_meta FROM telemetry_steps`).get() as any;
    assert.equal(a.reasoning_redacted, null);
    assert.equal(JSON.parse(a.payload_meta).reasoning, "dropped");
    assert.ok(!dump(off.cp).includes("the plan"));
    const b = on.cp.db.prepare(`SELECT reasoning_redacted FROM telemetry_steps`).get() as any;
    assert.equal(b.reasoning_redacted, "I should email [email] the plan");
  } finally { await off.close(); await on.close(); }
});

// ------------------------------------------------------------ sequence, dedupe, gaps

test("steps: duplicates by (session, seq) are dropped and gaps raise a telemetry_gap alert", async () => {
  const env = await mkEnv();
  try {
    const { token } = env.source();
    const r1 = await env.api("POST", "/v1/intake/steps", token, { steps: [step(0), step(1), step(2)] });
    assert.equal(r1.json.accepted, 3);
    const r2 = await env.api("POST", "/v1/intake/steps", token, { steps: [step(2), step(5), step(6)] });
    assert.equal(r2.json.accepted, 2);
    assert.equal(r2.json.duplicates, 1);
    assert.equal(count(env.cp, "telemetry_steps"), 5);
    const sum = env.cp.reconcile.run();
    assert.equal(sum.gapsFound, 1);
    const [gap] = env.cp.telemetry.listAlerts({ kind: "telemetry_gap" });
    assert.deepEqual(gap.details.missing, [3, 4]);
    assert.equal(gap.details.missingCount, 2);
    // Already checked: a second run does not re-alert.
    assert.equal(env.cp.reconcile.run().gapsFound, 0);
    // Another source's session with the same id is a different session.
    const other = env.source("metadata", "other");
    assert.equal((await env.api("POST", "/v1/intake/steps", other.token, { steps: [step(0)] })).json.accepted, 1);
    const batches = env.cp.telemetry.listBatches();
    assert.equal(batches.length, 3);
    assert.ok(batches.every((b) => typeof b.auditSeq === "number"));
    assert.equal(env.cp.audit.query({ action: "intake.batch" }).length, 3);
  } finally { await env.close(); }
});

// ------------------------------------------------------------ append-only evidence

test("violations: hash chain verifies and tampering is detected", async () => {
  const env = await mkEnv();
  try {
    for (let i = 0; i < 4; i++) env.cp.telemetry.appendViolation({ agentId: "a1", policyId: "p", policyVersion: 1, rule: "r", decision: "deny", source: "intake", blockedAction: `tool_call t${i}` });
    assert.equal(env.cp.telemetry.verifyViolationChain(), -1);
    // Tamper with the triggers out of the way, as an attacker with file access would.
    env.cp.db.exec(`DROP TRIGGER policy_violations_no_update`);
    env.cp.db.prepare(`UPDATE policy_violations SET decision = 'allow' WHERE seq = 2`).run();
    assert.equal(env.cp.telemetry.verifyViolationChain(), 2);
    env.cp.db.prepare(`UPDATE policy_violations SET decision = 'deny' WHERE seq = 2`).run();
    assert.equal(env.cp.telemetry.verifyViolationChain(), -1);
    env.cp.db.exec(`DROP TRIGGER policy_violations_no_delete`);
    env.cp.db.prepare(`DELETE FROM policy_violations WHERE seq = 3`).run();
    assert.equal(env.cp.telemetry.verifyViolationChain(), 4);
  } finally { await env.close(); }
});

test("evidence: steps and violations cannot be updated or deleted through the store or the database", async () => {
  const env = await mkEnv();
  try {
    const { token } = env.source("redacted");
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { tool_name: "t", prompt: "p", policy: { id: "p1", decision: "deny" } })] });
    const store = env.cp.telemetry as unknown as Record<string, unknown>;
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(env.cp.telemetry));
    assert.ok(!proto.some((m) => /^(update|delete|remove|edit)(Step|Violation)/i.test(m)), `store exposes a mutator: ${proto.join(",")}`);
    assert.equal(typeof store.purgePayloadsBefore, "function");
    const db = env.cp.db;
    assert.throws(() => db.prepare(`UPDATE telemetry_steps SET tool_name = 'other'`).run(), /append-only/);
    assert.throws(() => db.prepare(`UPDATE telemetry_steps SET agent_id = 'x'`).run(), /append-only/);
    assert.throws(() => db.prepare(`UPDATE telemetry_steps SET prompt_redacted = 'rewritten', payload_purged_at = 'now'`).run(), /append-only/);
    assert.throws(() => db.prepare(`DELETE FROM telemetry_steps`).run(), /append-only/);
    assert.throws(() => db.prepare(`UPDATE policy_violations SET rule = 'x'`).run(), /append-only/);
    assert.throws(() => db.prepare(`DELETE FROM policy_violations`).run(), /append-only/);
    assert.throws(() => db.prepare(`UPDATE intake_batches SET accepted = 0`).run(), /append-only/);
    assert.throws(() => db.prepare(`DELETE FROM intake_batches`).run(), /append-only/);
    env.cp.telemetry.raiseAlert({ kind: "drift", severity: "low", dedupeKey: "k", details: {} });
    assert.throws(() => db.prepare(`DELETE FROM telemetry_alerts`).run(), /cannot be deleted/);
    assert.throws(() => db.prepare(`DELETE FROM telemetry_sessions`).run(), /cannot be deleted/);
    assert.equal(count(env.cp, "telemetry_steps"), 1);
    assert.equal(count(env.cp, "policy_violations"), 1);
  } finally { await env.close(); }
});

test("retention: the sweep nulls old payloads only, keeping metadata, violations and the audit chain", async () => {
  const c = clock();
  const env = await mkEnv({ now: c.now, telemetry: { payloadRetentionDays: 30 } });
  try {
    const { token } = env.source("redacted");
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { tool_name: "t", model: "m", prompt: "old prompt", output: "old out", usage: { input_tokens: 5 }, policy: { id: "p", decision: "deny" } })] });
    c.advance(31 * DAY);
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(1, { prompt: "new prompt" })] });
    const auditBefore = count(env.cp, "audit_events");
    const r = env.cp.reconcile.retentionSweep();
    assert.equal(r.purged, 1);
    const rows = env.cp.db.prepare(`SELECT seq, tool_name, model, input_tokens, prompt_redacted, output_redacted, payload_purged_at FROM telemetry_steps ORDER BY seq`).all() as any[];
    assert.equal(rows[0].prompt_redacted, null);
    assert.equal(rows[0].output_redacted, null);
    assert.ok(rows[0].payload_purged_at);
    assert.equal(rows[0].tool_name, "t");
    assert.equal(rows[0].model, "m");
    assert.equal(rows[0].input_tokens, 5);
    assert.equal(rows[1].prompt_redacted, "new prompt");
    assert.equal(count(env.cp, "policy_violations"), 1);
    assert.equal(env.cp.telemetry.verifyViolationChain(), -1);
    assert.equal(count(env.cp, "audit_events"), auditBefore + 1);
    assert.equal(env.cp.audit.verifyChain(), -1);
    assert.equal(env.cp.reconcile.retentionSweep().purged, 0, "idempotent");
  } finally { await env.close(); }
});

// ------------------------------------------------------------ reconciliation

test("drift: alert_only raises a drift alert and leaves the agent active", async () => {
  const env = await mkEnv();
  try {
    const a = env.register();
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [
      step(0, { agent_key: a.agent.id, tool_name: "read_docs", model: "claude-haiku-4-5-20261001" }),
      step(1, { agent_key: a.agent.id, tool_name: "delete_records", model: "gpt-5" }),
    ] });
    const sum = env.cp.reconcile.run();
    assert.equal(sum.reReviews, 0);
    const [d] = env.cp.telemetry.listAlerts({ kind: "drift" });
    assert.deepEqual(Object.keys(d.details.tools as object), ["delete_records"]);
    assert.deepEqual(Object.keys(d.details.models as object), ["gpt-5"]);
    assert.equal(d.details.observedTier, "medium");
    assert.equal(env.cp.registry.get(a.agent.id)!.lifecycleState, "active");
    assert.equal(env.cp.credentials.verify(a.credential!.token).ok, true);
    assert.equal(env.cp.audit.query({ action: "telemetry.alert" }).length, 1);
    // A re-run with no new steps does not duplicate the alert.
    env.cp.reconcile.run();
    assert.equal(env.cp.telemetry.listAlerts({ kind: "drift" }).length, 1);
  } finally { await env.close(); }
});

test("drift: enforce_review sends a high-risk drifted agent to pending_approval and revokes credentials", async () => {
  const env = await mkEnv({ telemetry: { driftMode: "enforce_review" } });
  try {
    env.cp.profiles.upsert({ ...DEFAULT_PROFILES[0], id: "money", allowedDataClasses: ["internal", "financial"], maxAutonomy: "A3", requiresSecurityReview: false });
    const a = env.register({ accessProfileId: "money", tools: [{ toolName: "read_ledger", reversible: true, dataClasses: ["financial"] }] });
    assert.equal(a.agent.riskTier, "medium");
    // A medium agent touching money that is seen using an unknown (assumed irreversible) tool -> high.
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { agent_key: a.agent.id, tool_name: "wire_transfer" })] });
    const sum = env.cp.reconcile.run();
    assert.equal(sum.reReviews, 1);
    const agent = env.cp.registry.get(a.agent.id)!;
    assert.equal(agent.lifecycleState, "pending_approval");
    assert.equal(agent.riskTier, "high");
    assert.equal(agent.riskOverride?.by, "system:telemetry-reconcile");
    assert.match(agent.securityReview?.notes ?? "", /wire_transfer/);
    assert.equal(env.cp.credentials.verify(a.credential!.token).ok, false);
    assert.equal(env.cp.audit.query({ action: "credential.revoke" }).at(-1)!.details.reason, "observed_drift_pending_review");
    // A low-risk drift in enforce_review still only alerts.
    const b = env.register({ name: "Low" });
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { session_id: "s2", agent_key: b.agent.id, model: "gpt-5" })] });
    env.cp.reconcile.run();
    assert.equal(env.cp.registry.get(b.agent.id)!.lifecycleState, "active");
  } finally { await env.close(); }
});

test("bypass: activity from a suspended or expired agent raises a high-severity alert", async () => {
  const c = clock();
  const env = await mkEnv({ now: c.now });
  try {
    const sus = env.register({ name: "Suspended" });
    env.cp.registration.suspend(sus.agent.id, "carol@example.com", "investigation");
    const exp = env.register({ name: "Expiring", expiresAt: new Date(c.now().getTime() + 2 * DAY).toISOString() });
    c.advance(3 * DAY);
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [
      step(0, { agent_key: sus.agent.id, tool_name: "read_docs" }),
      step(1, { agent_key: exp.agent.id, tool_name: "read_docs" }),
    ] });
    env.cp.reconcile.run();
    const alerts = env.cp.telemetry.listAlerts({ kind: "bypass" });
    assert.equal(alerts.length, 2);
    assert.ok(alerts.every((x) => x.severity === "high"));
    assert.deepEqual(alerts.map((x) => x.details.state).sort(), ["expired", "suspended"]);
    // The expired agent's own credential is refused at intake (Phase 1 expiry rule).
    assert.equal((await env.api("POST", "/v1/intake/steps", exp.credential!.token, { steps: [step(0, { session_id: "own" })] })).status, 401);
  } finally { await env.close(); }
});

test("dormant: active agents with no activity for N days are listed and alerted", async () => {
  const c = clock();
  const env = await mkEnv({ now: c.now, telemetry: { dormantDays: 30 } });
  try {
    const idle = env.register({ name: "Idle" });
    const busy = env.register({ name: "Busy" });
    c.advance(31 * DAY);
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { agent_key: busy.agent.id, ts: c.now().toISOString() })] });
    // Active agents expire at 90 days; still active here. User tokens (8h) have expired: reissue.
    for (const u of ["carol", "olga", "alice"]) env.tok[u] = env.cp.credentials.issueUserToken(`${u}@example.com`).token;
    const list = env.cp.reconcile.dormantAgents().map((d) => d.agent.id);
    assert.deepEqual(list, [idle.agent.id]);
    env.cp.reconcile.run();
    assert.equal(env.cp.telemetry.listAlerts({ kind: "dormant" }).length, 1);
    const r = await env.api("GET", "/v1/telemetry/dormant", env.tok.carol);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.agents.map((x: any) => x.id), [idle.agent.id]);
    // Owners see their own; olga owns nothing.
    assert.deepEqual((await env.api("GET", "/v1/telemetry/dormant", env.tok.olga)).json.agents, []);
    // Recertification response carries the dormant flag.
    const rc = await env.api("POST", `/v1/agents/${idle.agent.id}/recertify`, env.tok.alice);
    assert.equal(rc.status, 200);
    assert.equal(rc.json.activity.dormant, true);
    assert.equal(rc.json.activity.steps, 0);
  } finally { await env.close(); }
});

test("activity: summary of tools, models, counts, violations and last seen for recertification", async () => {
  const env = await mkEnv();
  try {
    const a = env.register();
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [
      step(0, { agent_key: a.agent.id, tool_name: "read_docs", model: "claude-haiku-4-5", usage: { input_tokens: 100, output_tokens: 20 } }),
      step(1, { agent_key: a.agent.id, tool_name: "read_docs", model: "claude-haiku-4-5", usage: { input_tokens: 50, output_tokens: 10 } }),
      step(2, { agent_key: a.agent.id, tool_name: "export_csv", status: "error", error_class: "tool_failure", policy: { id: "exports", version: 3, decision: "deny", rule: "no_bulk_export" } }),
    ] });
    const r = await env.api("GET", `/v1/agents/${a.agent.id}/activity?days=90`, env.tok.alice);
    assert.equal(r.status, 200);
    const s = r.json.activity;
    assert.equal(s.steps, 3);
    assert.equal(s.sessions, 1);
    assert.equal(s.errors, 1);
    assert.deepEqual(s.tokens, { input: 150, output: 30 });
    assert.deepEqual(s.tools, [{ name: "read_docs", calls: 2, registered: true }, { name: "export_csv", calls: 1, registered: false }]);
    assert.deepEqual(s.models, [{ name: "claude-haiku-4-5", calls: 2, permitted: true }]);
    assert.equal(s.violations.inWindow, 1);
    assert.equal(s.violations.recent[0].policyId, "exports");
    assert.deepEqual(s.driftTools, ["export_csv"]);
    assert.ok(s.lastSeen);
    assert.equal(s.dormant, false);
    // Not the owner -> 404 (no existence oracle); auditors may look.
    assert.equal((await env.api("GET", `/v1/agents/${a.agent.id}/activity`, env.tok.olga)).status, 404);
    assert.equal((await env.api("GET", `/v1/agents/${a.agent.id}/activity`, env.tok.erin)).status, 200);
    // The agent record carries the 30-day violation count.
    const rec = await env.api("GET", `/v1/agents/${a.agent.id}`, env.tok.alice);
    assert.equal(rec.json.telemetry.violationsLast30d, 1);
  } finally { await env.close(); }
});

test("violations: threshold raises the effective tier via a system override owners cannot lower", async () => {
  const env = await mkEnv({ telemetry: { violationThreshold: 3, violationRaiseTier: "high" } });
  try {
    const a = env.register();
    assert.equal(a.agent.riskTier, "low");
    const { token } = env.source();
    const deny = (i: number) => step(i, { agent_key: a.agent.id, tool_name: "read_docs", policy: { id: "p", decision: "deny" } });
    await env.api("POST", "/v1/intake/steps", token, { steps: [deny(0), deny(1), deny(2)] });
    const sum = env.cp.reconcile.run();
    assert.equal(sum.tierRaises, 1);
    const agent = env.cp.registry.get(a.agent.id)!;
    assert.equal(agent.riskTier, "high");
    assert.equal(agent.riskOverride?.direction, "raise");
    assert.equal(agent.riskOverride?.by, "system:telemetry-reconcile");
    // alert_only: the agent stays active.
    assert.equal(agent.lifecycleState, "active");
    const lower = env.cp.registration.setRiskTier(a.agent.id, "low", "alice@example.com", "fine");
    assert.equal(lower.ok, false);
    assert.match((lower as any).violations[0], /only a security reviewer may lower/);
    const sec = env.cp.registration.setRiskTier(a.agent.id, "low", "carol@example.com", "reviewed: false positives");
    assert.equal(sec.ok, true);
    assert.equal(env.cp.telemetry.listAlerts({ kind: "violation_threshold" }).length, 1);
  } finally { await env.close(); }
});

test("gateway: denied governed calls are recorded as hash-chained violations", async () => {
  const env = await mkEnv();
  try {
    const a = env.register({ tools: [{ toolName: "issue_refund", reversible: false, dataClasses: ["internal"] }] });
    env.cp.savePolicy({ id: "refunds", version: 1, toolName: "issue_refund", defaultDecision: "allow",
      rules: [{ kind: "parameter_threshold", field: "amount", greaterThan: 10, thenDecision: "deny", reason: "refund cap" }] }, "dave@example.com");
    const r = await env.api("POST", "/v1/call", a.credential!.token, { toolName: "issue_refund", principal: "user:1", parameters: { amount: 500, note: `for ${PII.email}` } });
    assert.equal(r.status, 200);
    assert.equal(r.json.decision, "deny");
    const v = env.cp.telemetry.listViolations({ agentId: a.agent.id });
    assert.equal(v.length, 1);
    assert.equal(v[0].source, "gateway");
    assert.equal(v[0].policyId, "refunds");
    assert.equal(v[0].policyVersion, 1);
    assert.match(v[0].blockedAction!, /^tool_call issue_refund: .*"amount":500/);
    assert.ok(!v[0].blockedAction!.includes(PII.email));
    assert.equal(env.cp.telemetry.verifyViolationChain(), -1);
  } finally { await env.close(); }
});

// ------------------------------------------------------------ OTLP mapping

const kv = (key: string, v: string | number) => ({ key, value: typeof v === "number" ? (Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v }) : { stringValue: v } });
const otlp = (spans: any[], resource: any[] = [kv("service.name", "support-bot")]) => ({ resourceSpans: [{ resource: { attributes: resource }, scopeSpans: [{ scope: { name: "test" }, spans }] }] });
const t0 = BigInt(Date.UTC(2026, 9, 16, 10, 0, 0)) * 1_000_000n;

test("otlp: maps current (>=1.37), 1.27-1.36 and legacy GenAI attribute generations", () => {
  const newest = mapSpan({
    traceId: "t1", spanId: "s1", startTimeUnixNano: String(t0), endTimeUnixNano: String(t0 + 1_500_000_000n),
    attributes: [kv("gen_ai.provider.name", "openai"), kv("gen_ai.operation.name", "chat"), kv("gen_ai.request.model", "gpt-5"),
      kv("gen_ai.usage.input_tokens", 12), kv("gen_ai.usage.output_tokens", 7), kv("gen_ai.conversation.id", "conv-9"), kv("gen_ai.agent.id", "agent-x"),
      kv("gen_ai.input.messages", JSON.stringify([{ role: "user", parts: [{ type: "text", content: "hi" }] }])),
      kv("gen_ai.output.messages", JSON.stringify([{ role: "assistant", parts: [{ type: "reasoning", content: "secret thoughts" }, { type: "text", content: "hello" }] }]))],
  }, {})!;
  assert.equal(newest.provider, "openai");
  assert.equal(newest.model, "gpt-5");
  assert.equal(newest.stepType, "model_call");
  assert.equal(newest.inputTokens, 12);
  assert.equal(newest.totalTokens, 19);
  assert.equal(newest.latencyMs, 1500);
  assert.equal(newest.sessionKey, "conv-9");
  assert.equal(newest.agentKey, "agent-x");
  assert.deepEqual(newest.reasoning, ["secret thoughts"]);
  assert.ok(!JSON.stringify(newest.output).includes("secret thoughts"));
  assert.ok(newest.conventions!.includes("genai>=1.37"));

  const mid = mapSpan({
    traceId: "t2", spanId: "s2", startTimeUnixNano: String(t0),
    attributes: [kv("gen_ai.system", "anthropic"), kv("gen_ai.operation.name", "execute_tool"), kv("gen_ai.tool.name", "search_kb"), kv("gen_ai.request.model", "claude-sonnet-5")],
  }, { "service.name": "kb-agent" })!;
  assert.equal(mid.provider, "anthropic");
  assert.equal(mid.stepType, "tool_call");
  assert.equal(mid.toolName, "search_kb");
  assert.equal(mid.agentKey, "kb-agent");
  assert.equal(mid.sessionKey, "trace:t2");
  assert.ok(mid.conventions!.includes("genai-1.27-1.36"));

  const legacy = mapSpan({
    traceId: "t3", spanId: "s3", startTimeUnixNano: String(t0), status: { code: 2, message: "429 Too Many Requests" },
    attributes: [kv("llm.vendor", "OpenAI"), kv("llm.request.type", "chat"), kv("llm.request.model", "gpt-4o"), kv("gen_ai.usage.prompt_tokens", 30),
      kv("gen_ai.usage.completion_tokens", 4), kv("gen_ai.prompt.0.role", "user"), kv("gen_ai.prompt.0.content", "legacy prompt")],
  }, {})!;
  assert.equal(legacy.provider, "OpenAI");
  assert.equal(legacy.model, "gpt-4o");
  assert.equal(legacy.inputTokens, 30);
  assert.equal(legacy.outputTokens, 4);
  assert.equal(legacy.status, "error");
  assert.equal(legacy.errorClass, "rate_limit");
  assert.match(JSON.stringify(legacy.prompt), /legacy prompt/);
  assert.ok(legacy.conventions!.includes("genai-legacy"));

  const openinference = mapSpan({ traceId: "t4", spanId: "s4", attributes: [kv("openinference.span.kind", "TOOL"), kv("tool.name", "lookup"), kv("input.value", "{\"q\":1}")] }, {})!;
  assert.equal(openinference.stepType, "tool_call");
  assert.equal(openinference.toolName, "lookup");
  assert.deepEqual(openinference.input, "{\"q\":1}");

  assert.equal(mapSpan({ spanId: "s5", attributes: [kv("http.method", "GET")] }, {}), undefined, "non-GenAI spans are ignored");
});

test("otlp: endpoint stores mapped spans, dedupes re-sent spans and counts ignored spans", async () => {
  const env = await mkEnv();
  try {
    const a = env.register();
    const { token } = env.source("redacted");
    const body = otlp([
      { traceId: "aa", spanId: "01", startTimeUnixNano: String(t0), attributes: [kv("gen_ai.system", "anthropic"), kv("gen_ai.request.model", "claude-haiku-4-5"), kv("gen_ai.agent.id", a.agent.id), kv("gen_ai.prompt", `mail ${PII.email}`)] },
      { traceId: "aa", spanId: "02", startTimeUnixNano: String(t0), attributes: [kv("http.route", "/x")] },
    ]);
    const r = await env.api("POST", "/v1/intake/otlp", token, body);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json.partialSuccess, {});
    const again = await env.api("POST", "/v1/intake/otlp", token, body);
    assert.equal(again.status, 200);
    assert.equal(count(env.cp, "telemetry_steps"), 1);
    const row = env.cp.db.prepare(`SELECT agent_id, model, provider, prompt_redacted FROM telemetry_steps`).get() as any;
    assert.equal(row.agent_id, a.agent.id);
    assert.equal(row.provider, "anthropic");
    assert.equal(row.prompt_redacted, "mail [email]");
    const [b1, b2] = env.cp.telemetry.listBatches().reverse();
    assert.equal(b1.ignored, 1);
    assert.equal(b2.duplicates, 1);
    // Protobuf is not accepted (yet): clear 415, batch recorded as rejected.
    const pb = await env.api("POST", "/v1/intake/otlp", token, "\x0a\x00", { "content-type": "application/x-protobuf" });
    assert.equal(pb.status, 415);
  } finally { await env.close(); }
});

test("otlp: parseOtlpTraces rejects a body without resourceSpans", () => {
  assert.equal(parseOtlpTraces({ foo: 1 }).ok, false);
  const p = parseOtlpTraces(otlp([{ attributes: [kv("gen_ai.system", "x")] }]));
  assert.ok(p.ok && p.batch.rejected.length === 1, "span without spanId is rejected");
});

// ------------------------------------------------------------ limits and error hygiene

test("limits: oversized batches are rejected (bytes and item count) and recorded", async () => {
  const env = await mkEnv({ telemetry: { maxBatchBytes: 4096, maxBatchSteps: 5 } });
  try {
    const { token } = env.source();
    const many = await env.api("POST", "/v1/intake/steps", token, { steps: Array.from({ length: 6 }, (_, i) => step(i)) });
    assert.equal(many.status, 413);
    assert.deepEqual(many.json, { error: "batch_too_large", maxItems: 5 });
    const big = await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { prompt: "x".repeat(10_000) })] });
    assert.equal(big.status, 413);
    assert.equal(big.json.error, "batch_too_large");
    assert.equal(count(env.cp, "telemetry_steps"), 0);
    const batches = env.cp.telemetry.listBatches();
    assert.equal(batches.length, 2);
    assert.ok(batches.every((b) => b.status === "rejected" && b.accepted === 0));
    assert.equal(env.cp.audit.query({ action: "intake.batch", outcome: "denied" }).length, 2);
  } finally { await env.close(); }
});

test("errors: responses never contain internals (stack, SQL, exception text)", async () => {
  const env = await mkEnv();
  try {
    const { token } = env.source();
    const bad = await env.api("POST", "/v1/intake/steps", token, "{not json", { "content-type": "application/json" });
    assert.equal(bad.status, 400);
    const invalid = await env.api("POST", "/v1/intake/steps", token, { steps: [{ session_id: "s", seq: -1, ts: "nope" }] });
    assert.equal(invalid.status, 422);
    // Force an internal failure: break the store underneath the gateway.
    env.cp.db.exec(`ALTER TABLE telemetry_steps RENAME TO telemetry_steps_gone`);
    const origError = console.error;
    console.error = () => {};
    let boom;
    try { boom = await env.api("POST", "/v1/intake/steps", token, { steps: [step(0)] }); } finally { console.error = origError; }
    assert.equal(boom.status, 500);
    assert.deepEqual(Object.keys(boom.json).sort(), ["error", "requestId"]);
    assert.equal(boom.json.error, "internal_error");
    for (const r of [bad, invalid, boom]) {
      assert.ok(!/at .*\.js:\d+|SqliteError|no such table|SELECT|INSERT|TypeError|SyntaxError|stack/i.test(r.text), `leaked internals: ${r.text}`);
    }
    assert.equal(env.cp.audit.query({ action: "request.error" }).length, 1);
  } finally { await env.close(); }
});

// ------------------------------------------------------------ alert routes

test("alerts: list and acknowledge (security/admin only, reason required, audited)", async () => {
  const env = await mkEnv();
  try {
    const a = env.register();
    env.cp.registration.suspend(a.agent.id, "carol@example.com", "x");
    const { token } = env.source();
    await env.api("POST", "/v1/intake/steps", token, { steps: [step(0, { agent_key: a.agent.id })] });
    env.cp.reconcile.run();
    const list = await env.api("GET", "/v1/telemetry/alerts?status=open", env.tok.carol);
    assert.equal(list.json.alerts.length, 1);
    const id = list.json.alerts[0].id;
    assert.equal((await env.api("POST", `/v1/telemetry/alerts/${id}/ack`, env.tok.alice, { reason: "mine" })).status, 403);
    assert.equal((await env.api("POST", `/v1/telemetry/alerts/${id}/ack`, env.tok.carol, {})).status, 422);
    const ok = await env.api("POST", `/v1/telemetry/alerts/${id}/ack`, env.tok.carol, { reason: "known test traffic" });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.alert.status, "acknowledged");
    assert.equal(ok.json.alert.ackBy, "carol@example.com");
    assert.equal((await env.api("POST", `/v1/telemetry/alerts/${id}/ack`, env.tok.carol, { reason: "again" })).status, 422);
    assert.equal((await env.api("POST", `/v1/telemetry/alerts/nope/ack`, env.tok.carol, { reason: "x" })).status, 404);
    const acks = env.cp.audit.query({ action: "telemetry.alert.ack" });
    assert.deepEqual(acks.map((e) => e.outcome), ["denied", "success", "denied", "denied"]);
    // Owners see alerts for their own agents only.
    assert.equal((await env.api("GET", "/v1/telemetry/alerts", env.tok.alice)).json.alerts.length, 1);
    assert.equal((await env.api("GET", "/v1/telemetry/alerts", env.tok.olga)).json.alerts.length, 0);
  } finally { await env.close(); }
});

test("model matching: version suffixes match, different models do not", () => {
  assert.equal(modelPermitted("claude-sonnet-5-20261001", ["claude-sonnet-5"]), true);
  assert.equal(modelPermitted("claude-sonnet-5@20261001", ["claude-sonnet-5"]), true);
  assert.equal(modelPermitted("claude-sonnet-5-mini", ["claude-sonnet-5"]), false);
  assert.equal(modelPermitted("gpt-5", ["claude-sonnet-5"]), false);
});

test("scheduler: reconciliation and retention are registered jobs", async () => {
  const env = await mkEnv();
  try {
    const ids = env.cp.scheduler.jobIds();
    assert.ok(ids.includes("telemetry-reconcile") && ids.includes("telemetry-retention") && ids.includes("expiry-sweep"));
    const st = env.cp.scheduler.status().find((j) => j.jobId === "telemetry-reconcile")!;
    assert.equal(st.intervalMs, 60 * 60 * 1000);
    const run = await env.cp.scheduler.runOnce("telemetry-reconcile");
    assert.equal(run.status, "ok");
  } finally { await env.close(); }
});
