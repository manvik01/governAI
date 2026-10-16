// Integration test for the capture path: migrations -> source token -> OTLP
// (JSON and protobuf) and LiteLLM intake -> disk queue -> loader -> Postgres.
//
// Needs a Postgres it may create databases on: ZENAI4_TEST_DATABASE_URL, e.g.
//   postgres://postgres@localhost:5432/postgres
// Skipped when that is not set, so `npm test` still runs without a database.

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import pg from "pg";
import { createPool } from "../db/pool.js";
import { migrate, migrationStatus } from "../db/migrate.js";
import { verifyAuditChain } from "../db/audit-chain.js";
import { addSource, disableSource, SourceAuth } from "./sources.js";
import { DiskQueue } from "./queue.js";
import { Loader } from "./loader.js";
import { createIntakeApp } from "./server.js";
import { decodeProtobuf } from "./otlp.js";
import protobuf from "protobufjs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ADMIN_URL = process.env.ZENAI4_TEST_DATABASE_URL;
const dbName = `zenai4_test_${process.pid}`;

const now = BigInt(Date.now()) * 1_000_000n;
function otlpJson(traceId: string, extraAttrs: Array<{ key: string; value: object }> = []) {
  return {
    resourceSpans: [{
      resource: { attributes: [{ key: "service.name", value: { stringValue: "refund-bot" } }] },
      scopeSpans: [{
        scope: { name: "pydantic-ai", version: "1.0" },
        spans: [{
          traceId, spanId: "1111111111111111", name: "chat gpt-4o", kind: 3,
          startTimeUnixNano: String(now), endTimeUnixNano: String(now + 900_000_000n),
          attributes: [
            { key: "gen_ai.operation.name", value: { stringValue: "chat" } },
            { key: "gen_ai.request.model", value: { stringValue: "gpt-4o" } },
            { key: "gen_ai.usage.input_tokens", value: { intValue: "120" } },
            { key: "gen_ai.usage.output_tokens", value: { intValue: "30" } },
            ...extraAttrs,
          ],
          events: [{ name: "gen_ai.user.message", timeUnixNano: String(now), attributes: [{ key: "content", value: { stringValue: "refund order 99 for ana@acme.com" } }] }],
          status: { code: 1 },
        }],
      }],
    }],
  };
}

describe("intake capture path", { skip: !ADMIN_URL && "set ZENAI4_TEST_DATABASE_URL to run" }, () => {
  let admin: pg.Pool;
  let pool: pg.Pool;
  let server: Server;
  let base: string;
  let queue: DiskQueue;
  let loader: Loader;
  let otlpToken: string;
  let litellmToken: string;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = new URL(ADMIN_URL!);
    url.pathname = `/${dbName}`;
    pool = createPool(url.toString(), 4);
    queue = new DiskQueue(mkdtempSync(join(tmpdir(), "zenai4-q-")));
    loader = new Loader(pool, queue);
    const app = createIntakeApp(pool, queue, new SourceAuth(pool, 0), loader, { minFreeBytes: 1 });
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    server?.close();
    await pool?.end();
    await admin?.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin?.end();
  });

  it("applies every migration once, then reports up to date", async () => {
    const applied = await migrate(pool);
    assert.ok(applied.length >= 5);
    assert.deepEqual(await migrate(pool), []);
    const { supabase, items } = await migrationStatus(pool);
    assert.equal(supabase, false);
    assert.ok(items.every((i) => i.applied && !i.changed));
  });

  it("issues source tokens and refuses bad ones with one 401", async () => {
    otlpToken = await addSource(pool, "collector-1", "otlp", "test");
    litellmToken = await addSource(pool, "litellm-1", "litellm", "test");
    for (const auth of [undefined, "Bearer nope", `Bearer ${otlpToken}x`]) {
      const r = await fetch(`${base}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) }, body: "{}" });
      assert.equal(r.status, 401);
      assert.deepEqual(await r.json(), { error: "unauthorized" });
    }
    const wrongKind = await fetch(`${base}/v1/intake/litellm`, { method: "POST", headers: { authorization: `Bearer ${otlpToken}` }, body: "{}" });
    assert.equal(wrongKind.status, 403);
  });

  it("accepts OTLP JSON, loads it, and drops prompt content and personal data", async () => {
    const body = JSON.stringify(otlpJson("a".repeat(32), [
      { key: "gen_ai.input.messages", value: { stringValue: "[{\"role\":\"user\",\"content\":\"secret plan\"}]" } },
      { key: "enduser.id", value: { stringValue: "ana@acme.com" } },
      { key: "http.request.header.authorization", value: { stringValue: "Bearer sk-live-abcdefghijklmnop1234" } },
      { key: "note", value: { stringValue: "card 4111 1111 1111 1111, nric S1234567D, key sk-abcdefghijklmnopqrstu" } },
      { key: "pydantic_ai.all_messages", value: { stringValue: "[{\"role\":\"user\",\"parts\":[]}]" } },
      { key: "final_result", value: { stringValue: "secret plan approved" } },
      { key: "custom.history", value: { stringValue: "[{\"role\": \"assistant\", \"content\": \"secret plan\"}]" } },
      { key: "order.id", value: { stringValue: "1734567890123" } },
    ]));
    const r = await fetch(`${base}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otlpToken}` }, body });
    assert.equal(r.status, 200);
    assert.equal(queue.depth(), 1);
    assert.equal(await loader.runOnce(), 1);
    assert.equal(queue.depth(), 0);
    const rows = await pool.query(`SELECT record FROM events.raw_span`);
    assert.equal(rows.rowCount, 1);
    const rec = rows.rows[0].record;
    assert.equal(rec.kind, "span");
    assert.equal(rec.resource["service.name"], "refund-bot");
    assert.equal(rec.attributes["gen_ai.usage.input_tokens"], 120);
    assert.equal(rec.attributes["gen_ai.input.messages"], undefined);
    assert.match(rec.attributes["enduser.id"], /^user:[0-9a-f]{16}$/);
    assert.equal(rec.attributes["http.request.header.authorization"], "[redacted]");
    assert.equal(rec.attributes.note, "card [card], nric [nric], key [secret]");
    assert.deepEqual(rec.events[0].attributes, {});
    assert.equal(rec.attributes["pydantic_ai.all_messages"], undefined);
    assert.equal(rec.attributes.final_result, undefined);
    assert.equal(rec.attributes["custom.history"], undefined);
    assert.equal(rec.attributes["order.id"], "1734567890123"); // not Luhn-valid: not mistaken for a card
    const all = JSON.stringify((await pool.query(`SELECT record FROM events.raw_span`)).rows);
    for (const leaked of ["ana@acme.com", "secret plan", "4111", "S1234567D", "sk-"]) assert.ok(!all.includes(leaked), `leaked ${leaked}`);
  });

  it("treats an identical resend as one batch", async () => {
    const body = JSON.stringify(otlpJson("b".repeat(32)));
    for (let i = 0; i < 3; i++) {
      const r = await fetch(`${base}/v1/intake/otlp/traces`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otlpToken}` }, body });
      assert.equal(r.status, 200);
    }
    await loader.runOnce();
    const n = await pool.query(`SELECT count(*)::int AS n FROM events.raw_span WHERE record->>'traceId' = $1`, ["b".repeat(32)]);
    assert.equal(n.rows[0].n, 1);
    assert.equal(loader.stats.duplicates, 2);
  });

  it("accepts OTLP protobuf, the encoding Python and Go SDKs send", async () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const root = new protobuf.Root();
    const dir = resolve(here, "../../proto");
    root.resolvePath = (_o, t) => resolve(dir, t);
    root.loadSync("opentelemetry/proto/collector/trace/v1/trace_service.proto");
    const T = root.lookupType("opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest");
    const json = otlpJson("c".repeat(32));
    const s = json.resourceSpans[0].scopeSpans[0].spans[0] as any;
    s.traceId = Buffer.from("c".repeat(32), "hex");
    s.spanId = Buffer.from("2".repeat(16), "hex");
    const msg = T.fromObject(json);
    const buf = Buffer.from(T.encode(msg).finish());
    assert.equal(decodeProtobuf("traces", buf).resourceSpans.length, 1);
    const r = await fetch(`${base}/v1/traces`, { method: "POST", headers: { "content-type": "application/x-protobuf", authorization: `Bearer ${otlpToken}` }, body: buf });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("content-type"), "application/x-protobuf");
    await loader.runOnce();
    const row = await pool.query(`SELECT record FROM events.raw_span WHERE record->>'traceId' = $1`, ["c".repeat(32)]);
    assert.equal(row.rowCount, 1);
    assert.equal(row.rows[0].record.spanId, "2".repeat(16));
    assert.equal(row.rows[0].record.attributes["gen_ai.request.model"], "gpt-4o");
  });

  it("accepts OTLP logs", async () => {
    const body = JSON.stringify({ resourceLogs: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: "support-agent" } }] }, scopeLogs: [{ scope: { name: "app" }, logRecords: [{ timeUnixNano: String(now), severityText: "ERROR", body: { stringValue: "tool crm.lookup timed out for bob@acme.com" }, attributes: [{ key: "tool", value: { stringValue: "crm.lookup" } }] }] }] }] });
    const r = await fetch(`${base}/v1/logs`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otlpToken}` }, body });
    assert.equal(r.status, 200);
    await loader.runOnce();
    const row = await pool.query(`SELECT record FROM events.raw_span WHERE record->>'kind' = 'log'`);
    assert.equal(row.rows[0].record.body, "tool crm.lookup timed out for [email]");
  });

  it("accepts LiteLLM payloads and spend history, without messages", async () => {
    const payload = { id: "chatcmpl-1", call_type: "acompletion", model: "gpt-4o-mini", status: "success", response_cost: 0.0012, prompt_tokens: 40, completion_tokens: 8, total_tokens: 48, startTime: 1760000000, endTime: 1760000001, messages: [{ role: "user", content: "hi" }], response: { choices: [] }, metadata: { user_api_key_user_id: "ana@acme.com", user_api_key_alias: "refund-bot" } };
    const r = await fetch(`${base}/v1/intake/litellm`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${litellmToken}` }, body: JSON.stringify(payload) });
    assert.equal(r.status, 200);
    await loader.runOnce();
    const row = await pool.query(`SELECT record FROM events.raw_span WHERE record->>'kind' = 'litellm'`);
    const p = row.rows[0].record.payload;
    assert.equal(p.messages, undefined);
    assert.equal(p.response, undefined);
    assert.equal(p.total_tokens, 48);
    assert.match(p.metadata.user_api_key_user_id, /^user:/);
    assert.equal(p.metadata.user_api_key_alias, "refund-bot");
  });

  it("keeps every batch in the audit chain, and the chain verifies", async () => {
    const batches = await pool.query(`SELECT count(*)::int AS n FROM intake.batch b JOIN control.audit_event a ON a.seq = b.audit_seq WHERE a.action = 'intake.batch'`);
    const all = await pool.query(`SELECT count(*)::int AS n FROM intake.batch`);
    assert.equal(batches.rows[0].n, all.rows[0].n);
    assert.equal(await verifyAuditChain(pool), -1);
    await assert.rejects(pool.query(`UPDATE control.audit_event SET actor = 'x' WHERE seq = 1`), /append-only/);
  });

  it("keeps accepting while the database is down, then catches up", async () => {
    const before = (await pool.query(`SELECT count(*)::int AS n FROM events.raw_span`)).rows[0].n;
    // A loader pointed at a dead database: batches stay on disk, nothing is lost.
    const dead = createPool("postgres://nobody@127.0.0.1:1/none", 1);
    const stalled = new Loader(dead, queue);
    const body = JSON.stringify(otlpJson("d".repeat(32)));
    const r = await fetch(`${base}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otlpToken}` }, body });
    assert.equal(r.status, 200);
    assert.equal(await stalled.runOnce(), 0);
    assert.ok(stalled.stats.lastError);
    assert.equal(queue.depth(), 1);
    await dead.end();
    assert.equal(await loader.runOnce(), 1);
    const afterN = (await pool.query(`SELECT count(*)::int AS n FROM events.raw_span`)).rows[0].n;
    assert.equal(afterN, before + 1);
  });

  it("stops accepting a disabled source", async () => {
    await disableSource(pool, "collector-1", "test");
    const r = await fetch(`${base}/v1/traces`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${otlpToken}` }, body: "{}" });
    assert.equal(r.status, 401);
  });

  it("reports readiness and metrics", async () => {
    const ready = await fetch(`${base}/readyz`);
    assert.equal(ready.status, 200);
    const m = await (await fetch(`${base}/metrics`)).text();
    assert.match(m, /zenai4_loader_records_loaded_total \d+/);
    writeFileSync(join(queue.dir, ".partial.json.tmp"), "{"); // an interrupted write is never loaded
    assert.equal(queue.depth(), 0);
  });
});
