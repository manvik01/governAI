// Phase 1 tests: registration as code, discovery and the triage queue, risk
// tier overrides, lifecycle transitions, expiry and recertification.
// Run: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import Database from "better-sqlite3";
import { buildControlPlane, DEFAULT_PROFILES } from "./control-plane.js";
import { createSecureGateway } from "../gateway/secure-server.js";
import type { RegistrationRequest } from "./registration.js";
import { parseManifest } from "./manifest.js";
import { calculateRiskTier, canTransition } from "../registry/registry.js";

const DAY = 86_400_000;
const CHECKLIST = {
  identity_verified: true, least_privilege_reviewed: true, data_classification_confirmed: true, logging_enabled: true, kill_switch_tested: true,
};

const regBody = (over: Partial<RegistrationRequest> = {}): RegistrationRequest => ({
  name: "DocReader",
  purpose: "Summarises internal docs",
  ownerEmail: "alice@example.com",
  subOwnerEmail: "bob@example.com",
  accessProfileId: "internal-readonly",
  businessUnit: "Ops",
  platform: "custom",
  modelProvider: "anthropic",
  modelVersion: "claude-haiku-4-5",
  autonomyDefault: "A1",
  mode: "enforcement",
  tools: [{ toolName: "read_docs", reversible: true, dataClasses: ["internal"] }],
  budgetPolicy: {},
  ...over,
});

const manifest = (over: { tools?: string; autonomy?: string; model?: string; profile?: string; id?: string; name?: string; extra?: string } = {}) => `
apiVersion: zenai4/v1
kind: Agent
metadata:
  id: ${over.id ?? "ops.doc-reader"}
  name: ${over.name ?? "DocReader"}
spec:
  purpose: Summarises internal docs
  owner: alice@example.com
  subOwner: bob@example.com
  businessUnit: Ops
  platform: custom
  model:
    provider: anthropic
    version: ${over.model ?? "claude-haiku-4-5"}
  accessProfile: ${over.profile ?? "internal-readonly"}
  autonomy: ${over.autonomy ?? "A1"}
  mode: enforcement
  tools:
${over.tools ?? "    - { name: read_docs, reversible: true, dataClasses: [internal] }"}
  budget: { agentLimitMicro: 5000000 }
${over.extra ?? ""}`;

/** A clock tests can move forward. */
function clock(start = Date.now()) {
  let t = start;
  return { now: () => new Date(t), advance: (ms: number) => { t += ms; } };
}

async function mkEnv(opts: { now?: () => Date } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "zenai4-p1-"));
  const dbPath = join(dir, "cp.db");
  const cp = buildControlPlane({ dbPath, now: opts.now });
  for (const p of DEFAULT_PROFILES) cp.profiles.upsert(p);
  cp.profiles.upsert({ ...DEFAULT_PROFILES[0], id: "broad", name: "Broad", allowedTools: ["*"], allowedDataClasses: ["internal", "financial", "customer_pii"], allowedModels: ["claude-haiku-4-5", "claude-sonnet-5"], maxAutonomy: "A4", requiresSecurityReview: false });
  const people: Array<[string, any[]]> = [
    ["alice@example.com", ["agent_owner"]],
    ["bob@example.com", ["agent_owner"]],
    ["carol@example.com", ["security_reviewer"]],
    ["dave@example.com", ["admin"]],
    ["erin@example.com", ["auditor"]],
    ["ci@example.com", ["ci_registrar"]],
    ["olga@example.com", ["agent_owner"]],
  ];
  for (const [email, roles] of people) cp.directory.upsert({ email, displayName: email.split("@")[0], active: true, roles });
  const app = createSecureGateway(cp, { trustProxy: true });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const tok: Record<string, string> = {};
  for (const [email] of people) tok[email.split("@")[0]] = cp.credentials.issueUserToken(email).token;
  const api = async (method: string, path: string, token?: string, body?: unknown, extra: Record<string, string> = {}) => {
    const isText = typeof body === "string";
    const res = await fetch(base + path, {
      method,
      headers: { "content-type": isText ? (extra["content-type"] ?? "application/yaml") : "application/json", "x-forwarded-for": extra.ip ?? "10.0.0.1", ...(extra.ua ? { "user-agent": extra.ua } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : isText ? body : JSON.stringify(body),
    });
    let json: any;
    try { json = await res.json(); } catch { json = undefined; }
    return { status: res.status, json };
  };
  return {
    dir, dbPath, cp, api, tok,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      cp.close();
    },
  };
}

const dbDump = (cp: ReturnType<typeof buildControlPlane>) => {
  const out: string[] = [];
  for (const { name } of cp.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>) {
    out.push(JSON.stringify(cp.db.prepare(`SELECT * FROM "${name}"`).all()));
  }
  return out.join("\n");
};

// ------------------------------------------------------------ manual registration

test("manual registration over HTTP accepts every field including an explicit expiry date, and refuses one beyond 90 days", async () => {
  const env = await mkEnv();
  const expires = new Date(Date.now() + 30 * DAY).toISOString();
  const ok = await env.api("POST", "/v1/agents", env.tok.alice, regBody({ expiresAt: expires }));
  assert.equal(ok.status, 201, JSON.stringify(ok.json));
  assert.equal(ok.json.expiresAt, expires);
  const a = env.cp.registry.get(ok.json.agentId)!;
  for (const k of ["name", "purpose", "ownerEmail", "businessUnit", "platform", "modelProvider", "modelVersion", "autonomyDefault"] as const) assert.ok(a[k], k);
  assert.deepEqual(env.cp.registry.grantsFor(a.id).map((g) => [g.toolName, g.dataClasses]), [["read_docs", ["internal"]]]);

  const tooLong = await env.api("POST", "/v1/agents", env.tok.alice, regBody({ expiresAt: new Date(Date.now() + 200 * DAY).toISOString() }));
  assert.equal(tooLong.status, 422);
  assert.match(tooLong.json.violations.join(" "), /more than 90 days/);
  const past = await env.api("POST", "/v1/agents", env.tok.alice, regBody({ expiresAt: "2020-01-01" }));
  assert.match(past.json.violations.join(" "), /in the future/);
  await env.close();
});

// ------------------------------------------------------------ registration as code

test("manifest schema is strict: unknown keys and bad values are refused with paths", () => {
  const bad = parseManifest(manifest({ extra: "  owners: [x@example.com]" }));
  assert.equal(bad.ok, false);
  assert.match((bad as any).errors.join(" "), /spec/);
  const badAuto = parseManifest(manifest({ autonomy: "A9" }));
  assert.equal(badAuto.ok, false);
  assert.match((badAuto as any).errors.join(" "), /spec\.autonomy/);
  assert.equal(parseManifest("::: not yaml :::\n\t- [").ok, false);
  const good = parseManifest(manifest());
  assert.ok(good.ok);
  // Hash is stable across key order / formatting
  const reordered = parseManifest(manifest().replace("  businessUnit: Ops\n  platform: custom\n", "  platform: custom\n  businessUnit: Ops\n"));
  assert.ok(reordered.ok && good.ok && reordered.hash === good.hash);
});

test("apply is idempotent: create, no-op on identical, update on change - keyed by metadata.id, not name", async () => {
  const env = await mkEnv();
  const c = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest());
  assert.equal(c.status, 201, JSON.stringify(c.json));
  assert.equal(c.json.action, "created");
  assert.equal(c.json.lifecycleState, "active");
  assert.equal(JSON.stringify(c.json).includes("gai.a."), false, "apply never returns an agent credential");

  const same = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest());
  assert.equal(same.status, 200);
  assert.equal(same.json.action, "unchanged");
  assert.equal(same.json.agentId, c.json.agentId);

  const renamed = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ name: "DocReader v2" }));
  assert.equal(renamed.json.action, "updated");
  assert.equal(renamed.json.agentId, c.json.agentId);
  assert.deepEqual(renamed.json.widened, []);
  assert.equal(env.cp.registry.get(c.json.agentId)!.name, "DocReader v2");
  assert.equal(env.cp.registry.list().length, 1, "still one agent");

  // JSON body works too
  const parsed = parseManifest(manifest({ id: "ops.other" }));
  assert.ok(parsed.ok);
  const asJson = await env.api("POST", "/v1/agents/apply", env.tok.alice, parsed.ok ? parsed.manifest : {});
  assert.equal(asJson.json.action, "created");

  // every apply is audited, including the no-op
  const applied = env.cp.audit.query({ action: "agent.apply", outcome: "success" }).map((e) => e.details.result);
  assert.deepEqual(applied, ["created", "unchanged", "updated", "created"]);
  // A person with no right to act for the owner is refused
  const erin = await env.api("POST", "/v1/agents/apply", env.tok.erin, manifest({ id: "ops.x" }));
  assert.equal(erin.status, 403);
  await env.close();
});

test("apply that widens access goes back through the profile check and re-review when the tier becomes high", async () => {
  const env = await mkEnv();
  const m0 = manifest({ profile: "broad", id: "fin.refunds" });
  const c = await env.api("POST", "/v1/agents/apply", env.tok.ci, m0);
  assert.equal(c.json.lifecycleState, "active");
  // The owner fetches a credential out of band (apply never issues one).
  const rot = await env.api("POST", `/v1/agents/${c.json.agentId}/credentials/rotate`, env.tok.alice);
  const agentTok = rot.json.credential.token;
  assert.equal((await env.api("POST", "/v1/call", agentTok, { toolName: "read_docs", principal: "p", parameters: {} })).status, 200);

  // Widening outside the profile ceiling is refused, nothing changes.
  const outside = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ id: "fin.refunds", profile: "internal-readonly", tools: "    - { name: issue_refund, reversible: false, dataClasses: [financial] }" }));
  assert.equal(outside.status, 422);
  assert.match(outside.json.violations.join(" "), /data class "financial"/);

  // A low -> medium widening (new reversible tool on PII) stays active.
  const med = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ id: "fin.refunds", profile: "broad", tools: "    - { name: read_docs, reversible: true, dataClasses: [internal] }\n    - { name: lookup_customer, reversible: true, dataClasses: [customer_pii] }" }));
  assert.equal(med.json.action, "updated");
  assert.equal(med.json.riskTier, "medium");
  assert.equal(med.json.reReview, false);
  assert.equal(med.json.lifecycleState, "active");

  // An irreversible money tool -> high: back to pending_approval, credentials revoked.
  const high = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ id: "fin.refunds", profile: "broad", tools: "    - { name: read_docs, reversible: true, dataClasses: [internal] }\n    - { name: lookup_customer, reversible: true, dataClasses: [customer_pii] }\n    - { name: issue_refund, reversible: false, dataClasses: [financial] }" }));
  assert.equal(high.json.action, "updated");
  assert.equal(high.json.riskTier, "high");
  assert.equal(high.json.reReview, true);
  assert.equal(high.json.lifecycleState, "pending_approval");
  assert.ok(high.json.widened.some((w: string) => /new tool "issue_refund"/.test(w)));
  assert.equal((await env.api("POST", "/v1/call", agentTok, { toolName: "read_docs", principal: "p", parameters: {} })).status, 401, "credential revoked pending review");

  // Security approves -> active with a new credential.
  const rev = await env.api("POST", `/v1/agents/${c.json.agentId}/review`, env.tok.carol, { decision: "approve", checklist: CHECKLIST });
  assert.equal(rev.status, 200, JSON.stringify(rev.json));
  assert.equal((await env.api("POST", "/v1/call", rev.json.credential.token, { toolName: "read_docs", principal: "p", parameters: {} })).status, 200);

  // Higher autonomy and a new model are widening too.
  const auto = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ id: "fin.refunds", profile: "broad", autonomy: "A3", model: "claude-sonnet-5", tools: "    - { name: read_docs, reversible: true, dataClasses: [internal] }\n    - { name: lookup_customer, reversible: true, dataClasses: [customer_pii] }\n    - { name: issue_refund, reversible: false, dataClasses: [financial] }" }));
  assert.ok(auto.json.widened.some((w: string) => /autonomy A1 -> A3/.test(w)));
  assert.ok(auto.json.widened.some((w: string) => /new model "claude-sonnet-5"/.test(w)));
  assert.equal(auto.json.riskTier, "critical");
  assert.equal(auto.json.lifecycleState, "pending_approval");
  assert.ok(env.cp.audit.query({ action: "agent.update" }).every((e) => e.stream === "user"));
  await env.close();
});

test("a manifest missing required fields creates a draft; a later complete manifest submits it", async () => {
  const env = await mkEnv();
  const partial = `apiVersion: zenai4/v1\nkind: Agent\nmetadata: { id: ops.partial, name: Partial }\nspec:\n  owner: alice@example.com\n`;
  const d = await env.api("POST", "/v1/agents/apply", env.tok.ci, partial);
  assert.equal(d.status, 201, JSON.stringify(d.json));
  assert.equal(d.json.action, "drafted");
  assert.equal(d.json.lifecycleState, "draft");
  assert.ok(d.json.missing.includes("purpose"));
  assert.equal(env.cp.registry.isActive(d.json.agentId), false);
  const full = await env.api("POST", "/v1/agents/apply", env.tok.ci, manifest({ id: "ops.partial", name: "Partial" }));
  assert.equal(full.json.action, "updated");
  assert.equal(full.json.agentId, d.json.agentId);
  assert.equal(full.json.lifecycleState, "active");
  await env.close();
});

// ------------------------------------------------------------ gateway discovery

test("calls with an unknown credential produce one deduplicated discovery row with no secret material", async () => {
  const env = await mkEnv();
  const fake = "gai.a.unknownKey1.thisIsNotARealSecretButLongEnough_123";
  for (let i = 0; i < 3; i++) {
    const r = await env.api("POST", "/v1/call", fake, { toolName: "x", principal: "p" }, { ip: "10.9.9.9", ua: "python-requests/2.32" });
    assert.equal(r.status, 401);
  }
  // A raw provider key presented to the gateway: recorded as provider-key, never stored.
  const providerKey = "sk-ant-api03-" + "Q".repeat(40);
  await env.api("POST", "/v1/call", providerKey, { toolName: "x", principal: "p" }, { ip: "10.9.9.10" });

  const rows = env.cp.discovery.list({ source: "gateway" });
  assert.equal(rows.length, 2);
  const unknown = rows.find((r) => r.attributes.credentialScheme === "zenai4-agent")!;
  assert.equal(unknown.count, 3, "repeated sightings dedupe into one row");
  assert.equal(unknown.status, "new");
  assert.equal(unknown.attributes.keyIdPrefix, "unknow");
  assert.equal(unknown.attributes.sourceIp, "10.9.9.9");
  assert.equal(rows.find((r) => r.attributes.credentialScheme === "provider-key")!.attributes.provider, "anthropic");

  const dump = dbDump(env.cp) + env.cp.audit.exportJsonl({ limit: 100000 });
  assert.equal(dump.includes("thisIsNotARealSecretButLongEnough_123"), false, "presented secret never stored");
  assert.equal(dump.includes(providerKey), false, "presented provider key never stored");
  assert.equal(env.cp.audit.query({ action: "discovery.sighted" }).length, 2, "first sighting audited once per row");

  // Human tokens that fail are NOT agent discoveries
  await env.api("GET", "/v1/agents", "gai.u.nosuchkey.abcdefghijklmnopqrstuvwxyz");
  assert.equal(env.cp.discovery.list({ source: "gateway" }).length, 2);
  await env.close();
});

test("egress CSV import finds direct provider traffic, skips the rest, and accumulates counts on re-import", async () => {
  const env = await mkEnv();
  const csv = [
    "source_host,destination_domain,count,first_seen,last_seen",
    "build-07.corp,api.openai.com,120,2026-10-01T00:00:00Z,2026-10-10T00:00:00Z",
    "build-07.corp,api.openai.com,5,2026-09-20T00:00:00Z,2026-10-12T00:00:00Z",
    "laptop-ana,api.anthropic.com,7,2026-10-03,2026-10-04",
    "laptop-ana,www.google.com,999,2026-10-03,2026-10-04",
    "\"svc,quoted\",myres.openai.azure.com,3,2026-10-05,2026-10-05",
    "bad-row,api.openai.com,notanumber,2026-10-05,2026-10-05",
  ].join("\n");
  assert.equal((await env.api("POST", "/v1/discovery/import-egress", env.tok.alice, csv, { "content-type": "text/csv" })).status, 403);
  const r = await env.api("POST", "/v1/discovery/import-egress", env.tok.carol, csv, { "content-type": "text/csv" });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.matched, 4);
  assert.equal(r.json.skipped, 1);
  assert.equal(r.json.created, 3);
  assert.equal(r.json.errors.length, 1);
  const build = env.cp.discovery.list({ source: "egress_import" }).find((d) => d.attributes.sourceHost === "build-07.corp")!;
  assert.equal(build.count, 125);
  assert.equal(build.firstSeen, "2026-09-20T00:00:00.000Z");
  assert.equal(build.lastSeen, "2026-10-12T00:00:00.000Z");
  assert.ok(env.cp.discovery.list().some((d) => d.attributes.provider === "azure-openai" && d.attributes.sourceHost === "svc,quoted"));
  await env.api("POST", "/v1/discovery/import-egress", env.tok.carol, { csv });
  assert.equal(env.cp.discovery.list({ source: "egress_import" }).find((d) => d.id === build.id)!.count, 250);
  assert.equal(env.cp.audit.query({ action: "discovery.import_egress", outcome: "success" }).length, 2);
  await env.close();
});

// ------------------------------------------------------------ triage queue

test("claim creates a draft owned by the caller; submitting it registers the discovery", async () => {
  const env = await mkEnv();
  const { item } = env.cp.discovery.record({ source: "egress_import", kind: "direct_provider_traffic", identity: ["host-1", "openai"], displayName: "host-1 -> openai", attributes: { provider: "openai" } });
  assert.deepEqual(env.cp.discovery.list({ queue: "triage" }).map((d) => d.id), [item.id]);

  // A security reviewer (not an agent_owner) cannot claim
  assert.equal((await env.api("POST", `/v1/discovery/${item.id}/claim`, env.tok.carol)).status, 403);
  const claim = await env.api("POST", `/v1/discovery/${item.id}/claim`, env.tok.alice);
  assert.equal(claim.status, 201, JSON.stringify(claim.json));
  assert.equal(claim.json.lifecycleState, "draft");
  assert.equal(claim.json.owner, "alice@example.com");
  assert.equal(claim.json.discovery.status, "claimed");
  const draft = env.cp.registry.get(claim.json.agentId)!;
  assert.equal(draft.discoveryId, item.id);
  assert.equal(draft.modelProvider, "openai", "prefilled from discovery");
  assert.equal(env.cp.discovery.list({ queue: "triage" }).length, 0, "claimed items leave the triage queue");
  // claiming twice is an illegal transition
  const again = await env.api("POST", `/v1/discovery/${item.id}/claim`, env.tok.bob);
  assert.equal(again.status, 422);
  assert.match(again.json.violations.join(" "), /illegal discovery transition: claimed -> claimed/);

  // An incomplete draft cannot be submitted
  const early = await env.api("POST", `/v1/agents/${draft.id}/submit`, env.tok.alice);
  assert.equal(early.status, 422);
  assert.match(early.json.violations.join(" "), /draft is incomplete: missing .*purpose/);

  // Owner completes the draft and submits it
  const patch = await env.api("PATCH", `/v1/agents/${draft.id}`, env.tok.alice, {
    name: "Host-1 summariser", purpose: "Summarises tickets", subOwnerEmail: "bob@example.com", accessProfileId: "internal-readonly",
    businessUnit: "Ops", modelProvider: "anthropic", modelVersion: "claude-haiku-4-5", autonomyDefault: "A1", mode: "enforcement",
    tools: [{ toolName: "read_docs", reversible: true, dataClasses: ["internal"] }], budgetPolicy: {},
  });
  assert.equal(patch.status, 200, JSON.stringify(patch.json));
  assert.equal(patch.json.lifecycleState, "draft");
  const sub = await env.api("POST", `/v1/agents/${draft.id}/submit`, env.tok.alice);
  assert.equal(sub.status, 200, JSON.stringify(sub.json));
  assert.equal(sub.json.lifecycleState, "active");
  assert.ok(sub.json.credential.token);
  assert.equal(env.cp.discovery.get(item.id)!.status, "registered");
  const transitions = env.cp.audit.query({ targetId: item.id }).map((e) => `${e.action}:${e.outcome}`);
  assert.deepEqual(transitions, ["discovery.sighted:success", "discovery.claim:success", "discovery.claim:denied", "discovery.registered:success"]);
  // The security reviewer's attempt was refused at the route (role check) and logged there
  assert.ok(env.cp.audit.query({ action: "access.denied", actorId: "carol@example.com" }).some((e) => String(e.details.path).endsWith("/claim")));
  await env.close();
});

test("only security can assign an owner, ignore or disable; disable suspends a linked agent and revokes its credentials", async () => {
  const env = await mkEnv();
  const mk = (n: string) => env.cp.discovery.record({ source: "okta", kind: "service_app", identity: ["acme.okta.com", n], displayName: `app ${n}` }).item;
  const a = mk("a"), b = mk("b"), c = mk("c");

  for (const tok of [env.tok.alice, env.tok.erin]) {
    assert.equal((await env.api("POST", `/v1/discovery/${a.id}/assign-owner`, tok, { ownerEmail: "olga@example.com" })).status, 403);
    assert.equal((await env.api("POST", `/v1/discovery/${a.id}/disable`, tok, { reason: "x" })).status, 403);
    assert.equal((await env.api("POST", `/v1/discovery/${a.id}/ignore`, tok, { reason: "x" })).status, 403);
  }
  // Service-level checks too (not just route roles)
  assert.equal(env.cp.discovery.assignOwner(a.id, "olga@example.com", "alice@example.com").ok, false);
  assert.equal(env.cp.discovery.disable(a.id, "alice@example.com", "x").ok, false);

  const bad = await env.api("POST", `/v1/discovery/${a.id}/assign-owner`, env.tok.carol, { ownerEmail: "erin@example.com" });
  assert.equal(bad.status, 422);
  assert.match(bad.json.violations.join(" "), /agent_owner role/);
  const asg = await env.api("POST", `/v1/discovery/${a.id}/assign-owner`, env.tok.carol, { ownerEmail: "olga@example.com" });
  assert.equal(asg.status, 200, JSON.stringify(asg.json));
  assert.equal(asg.json.owner, "olga@example.com");
  assert.equal(asg.json.lifecycleState, "draft");

  assert.equal((await env.api("POST", `/v1/discovery/${b.id}/ignore`, env.tok.carol, {})).status, 422, "ignore needs a reason");
  const ign = await env.api("POST", `/v1/discovery/${b.id}/ignore`, env.tok.carol, { reason: "test tenant app" });
  assert.equal(ign.json.discovery.status, "ignored");

  // c: linked to a live, registered agent (e.g. its key was seen failing). Disable stops it.
  const reg = env.cp.registration.submit(regBody(), "alice@example.com");
  assert.ok(reg.ok && reg.credential);
  const live = env.cp.discovery.record({ source: "gateway", kind: "failed_credential", identity: ["10.1.1.1", "ua", "zenai4-agent", "abc"], displayName: "x", agentId: reg.agent.id }).item;
  const dis = await env.api("POST", `/v1/discovery/${live.id}/disable`, env.tok.carol, { reason: "incident 42" });
  assert.equal(dis.status, 200, JSON.stringify(dis.json));
  assert.equal(dis.json.agentState, "suspended");
  assert.equal(env.cp.credentials.verify(reg.credential!.token).ok, false, "credentials revoked");
  assert.equal((await env.api("POST", `/v1/discovery/${live.id}/disable`, env.tok.carol, {})).status, 422, "disabled is terminal");

  // disabling the claimed draft from a retires the draft
  const disA = await env.api("POST", `/v1/discovery/${a.id}/disable`, env.tok.dave, { reason: "not wanted" });
  assert.equal(disA.json.agentState, "retired");
  assert.match(disA.json.manualActionRequired, /read-only/);
  assert.equal(c.status, "new");
  const denied = env.cp.audit.query({ outcome: "denied", limit: 5000 })
    .filter((e) => e.action.startsWith("discovery.") || (e.action === "access.denied" && String(e.details.path).startsWith("/v1/discovery/")));
  assert.equal(denied.length, 6 + 2 + 3, "every refused triage action is audited (6 route refusals, 2 service refusals, 3 rule refusals)");
  assert.equal((await env.api("GET", "/v1/discovery?queue=triage", env.tok.carol)).json.items.length, 1);
  await env.close();
});

// ------------------------------------------------------------ risk tier

test("risk tier: computed automatically; owners can raise, only security can lower (with a reason below the floor)", async () => {
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: true, dataClasses: ["internal"] }], "A1"), "low");
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: true, dataClasses: ["customer_pii"] }], "A1"), "medium");
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: false, dataClasses: ["customer_pii"] }], "A1"), "high");
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: false, dataClasses: ["financial"] }], "A2"), "high");
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: false, dataClasses: [] }], "A4"), "critical");
  assert.equal(calculateRiskTier([{ toolName: "t", reversible: true, dataClasses: [] }], "A3"), "medium");

  const env = await mkEnv();
  const s = env.cp.registration.submit(regBody(), "alice@example.com");
  assert.ok(s.ok);
  const id = s.agent.id;
  assert.equal(s.agent.riskTier, "low");

  // non-owner, non-security cannot raise
  assert.equal((await env.api("POST", `/v1/agents/${id}/risk-tier`, env.tok.erin, { tier: "medium" })).status, 403);
  // owner raises to medium: recorded, effective = medium, computed stays low
  const up = await env.api("POST", `/v1/agents/${id}/risk-tier`, env.tok.alice, { tier: "medium", reason: "talks to customers soon" });
  assert.equal(up.status, 200, JSON.stringify(up.json));
  assert.equal(up.json.riskTier, "medium");
  assert.equal(up.json.computedRiskTier, "low");
  assert.equal(up.json.override.by, "alice@example.com");
  assert.equal(up.json.override.direction, "raise");
  // owner cannot lower
  const down = await env.api("POST", `/v1/agents/${id}/risk-tier`, env.tok.alice, { tier: "low" });
  assert.equal(down.status, 403);
  assert.match(down.json.violations.join(" "), /only a security reviewer may lower/);
  // admin (not security) cannot lower either
  assert.equal((await env.api("POST", `/v1/agents/${id}/risk-tier`, env.tok.dave, { tier: "low" })).status, 403);
  // security lowers back to the computed floor: no reason needed
  const sec = await env.api("POST", `/v1/agents/${id}/risk-tier`, env.tok.carol, { tier: "low" });
  assert.equal(sec.status, 200);
  assert.equal(sec.json.riskTier, "low");

  // Below the computed floor needs a reason
  const hi = env.cp.registration.submit(regBody({ name: "Refunds", accessProfileId: "broad", tools: [{ toolName: "issue_refund", reversible: false, dataClasses: ["financial"] }] }), "alice@example.com");
  assert.ok(hi.ok);
  assert.equal(hi.agent.riskTier, "high");
  const noReason = env.cp.registration.setRiskTier(hi.agent.id, "medium", "carol@example.com", undefined);
  assert.equal(noReason.ok, false);
  assert.match((noReason as any).violations.join(" "), /below the computed tier \(high\) requires a reason/);
  const withReason = env.cp.registration.setRiskTier(hi.agent.id, "medium", "carol@example.com", "refunds capped at $5 by policy");
  assert.ok(withReason.ok);
  assert.equal(withReason.ok && withReason.agent.riskTier, "medium");
  assert.equal(withReason.ok && withReason.agent.computedRiskTier, "high");
  assert.equal(withReason.ok && withReason.agent.riskOverride?.reason, "refunds capped at $5 by policy");

  // Raising a never-reviewed active agent into high sends it to review
  const raise = env.cp.registration.setRiskTier(id, "high", "alice@example.com", "now issues refunds");
  assert.ok(raise.ok);
  assert.equal(raise.ok && raise.agent.lifecycleState, "pending_approval");
  assert.ok(env.cp.audit.query({ action: "agent.risk_tier.set", outcome: "denied" }).length >= 4);
  await env.close();
});

// ------------------------------------------------------------ lifecycle

test("lifecycle: illegal transitions are refused and audited; retired is terminal and revokes credentials", async () => {
  assert.equal(canTransition("retired", "active"), false);
  assert.equal(canTransition("draft", "active"), true);
  const env = await mkEnv();
  const s = env.cp.registration.submit(regBody(), "alice@example.com");
  assert.ok(s.ok && s.credential);
  const id = s.agent.id;

  const toDraft = await env.api("POST", `/v1/agents/${id}/transition`, env.tok.alice, { to: "draft" });
  assert.equal(toDraft.status, 422);
  assert.match(toDraft.json.violations.join(" "), /illegal lifecycle transition: active -> draft/);
  const toRejected = await env.api("POST", `/v1/agents/${id}/transition`, env.tok.alice, { to: "rejected" });
  assert.equal(toRejected.status, 422);

  const sus = await env.api("POST", `/v1/agents/${id}/transition`, env.tok.alice, { to: "suspended", reason: "maintenance" });
  assert.equal(sus.json.lifecycleState, "suspended");
  const back = await env.api("POST", `/v1/agents/${id}/transition`, env.tok.alice, { to: "active" });
  assert.equal(back.status, 422, "a suspended agent is not simply switched back on");

  const ret = await env.api("POST", `/v1/agents/${id}/retire`, env.tok.bob, { reason: "replaced" });
  assert.equal(ret.status, 200);
  assert.equal(ret.json.lifecycleState, "retired");
  assert.equal(env.cp.credentials.verify(s.credential!.token).ok, false);
  for (const to of ["active", "suspended", "draft", "pending_approval"]) {
    const r = await env.api("POST", `/v1/agents/${id}/transition`, env.tok.dave, { to });
    assert.equal(r.status, 422, to);
    assert.match(r.json.violations.join(" "), /illegal lifecycle transition: retired ->/);
  }
  assert.equal((await env.api("PATCH", `/v1/agents/${id}`, env.tok.alice, { purpose: "revive" })).status, 422);
  assert.equal((await env.api("POST", `/v1/agents/${id}/recertify`, env.tok.alice)).status, 422);
  const refusals = env.cp.audit.query({ action: "agent.transition", outcome: "denied" });
  assert.ok(refusals.length >= 7);
  assert.ok(env.cp.audit.query({ action: "credential.revoke" }).some((e) => e.details.reason === "agent_retired"));
  // an outsider cannot retire
  const other = env.cp.registration.submit(regBody({ name: "Other" }), "alice@example.com");
  assert.ok(other.ok);
  assert.equal((await env.api("POST", `/v1/agents/${other.agent.id}/retire`, env.tok.erin, {})).status, 403);
  await env.close();
});

// ------------------------------------------------------------ expiry

test("expiry: the gateway refuses an expired agent before the sweep; the sweep suspends and revokes; recertify extends", async () => {
  const t = clock();
  const env = await mkEnv({ now: t.now });
  const s = env.cp.registration.submit(regBody(), "alice@example.com");
  assert.ok(s.ok && s.credential);
  const id = s.agent.id;
  const call = () => env.api("POST", "/v1/call", s.credential!.token, { toolName: "read_docs", principal: "p", parameters: {} });
  assert.equal((await call()).status, 200);
  assert.equal(Math.round((new Date(s.agent.expiresAt).getTime() - t.now().getTime()) / DAY), 90, "default 90 days");

  // An agent registered with a short explicit expiry: its credential (90d) outlives
  // the registration, so only the agent-expiry check can stop it.
  const short = env.cp.registration.submit(regBody({ name: "Short", expiresAt: new Date(t.now().getTime() + 10 * DAY).toISOString() }), "alice@example.com");
  assert.ok(short.ok && short.credential);
  const callShort = () => env.api("POST", "/v1/call", short.credential!.token, { toolName: "read_docs", principal: "p", parameters: {} });
  assert.equal((await callShort()).status, 200);
  t.advance(11 * DAY);
  assert.equal(env.cp.credentials.verify(short.credential!.token).ok, true, "credential itself is still valid");
  assert.equal(env.cp.registry.get(short.agent.id)!.lifecycleState, "active", "sweep has not run yet");
  assert.equal((await callShort()).status, 401, "gateway refuses an expired agent before the sweep");
  assert.ok(env.cp.audit.query({ action: "auth.failed" }).some((e) => e.details.reason === "agent_expired"));
  assert.equal(env.cp.registry.isActive(short.agent.id), false, "policy engine / model gateway see it as inactive too");
  const swept = env.cp.registration.expirySweep();
  assert.deepEqual(swept.map((a) => a.id), [short.agent.id]);
  assert.equal(env.cp.credentials.verify(short.credential!.token).ok, false, "sweep revoked its credential");
  t.advance(-11 * DAY);

  // 80 days on: it shows up in the "expiring within 14 days" list
  t.advance(80 * DAY);
  const relogin = () => { for (const u of ["alice", "bob", "carol"]) env.tok[u] = env.cp.credentials.issueUserToken(`${u}@example.com`).token; };
  relogin();
  const exp = await env.api("GET", "/v1/agents/expiring?days=14", env.tok.alice);
  assert.deepEqual(exp.json.agents.map((a: any) => a.id), [id]);
  assert.deepEqual(env.cp.registration.expiringWithin(5).map((a) => a.id), []);

  // Recertify by a non-owner is refused; by the sub-owner it extends to now + 90d
  assert.equal((await env.api("POST", `/v1/agents/${id}/recertify`, env.tok.carol)).status, 403);
  const rc = await env.api("POST", `/v1/agents/${id}/recertify`, env.tok.bob);
  assert.equal(rc.status, 200, JSON.stringify(rc.json));
  assert.equal(new Date(rc.json.expiresAt).getTime(), t.now().getTime() + 90 * DAY);
  assert.equal(rc.json.credential, undefined, "active agent keeps its credential");
  t.advance(20 * DAY); // day 100: past the original expiry, within the new one
  assert.equal((await call()).status, 200, "recertified agent (and its credential) still works");

  // Let it lapse: day 100 + 91
  t.advance(91 * DAY);
  relogin();
  assert.equal(env.cp.registry.get(id)!.lifecycleState, "active", "sweep has not run yet");
  assert.equal((await call()).status, 401, "expired agent refused");

  const run = await env.cp.scheduler.runOnce("expiry-sweep");
  assert.equal(run.status, "ok");
  assert.equal(run.items, 1);
  const after = env.cp.registry.get(id)!;
  assert.equal(after.lifecycleState, "suspended");
  assert.equal(after.suspendedReason, "expired");
  assert.ok(env.cp.audit.query({ action: "credential.revoke" }).some((e) => e.details.reason === "agent_expired"));
  assert.equal((await env.cp.scheduler.runOnce("expiry-sweep")).items, 0, "sweep is idempotent");

  // Recertifying an expiry-suspended agent (within grace) reactivates it with a fresh credential
  const back = await env.api("POST", `/v1/agents/${id}/recertify`, env.tok.alice);
  assert.equal(back.status, 200, JSON.stringify(back.json));
  assert.equal(back.json.lifecycleState, "active");
  assert.ok(back.json.credential.token);
  assert.equal((await call()).status, 401, "old credential stays dead");
  assert.equal((await env.api("POST", "/v1/call", back.json.credential.token, { toolName: "read_docs", principal: "p", parameters: {} })).status, 200);

  // An agent suspended for an incident cannot be "recertified" back on
  env.cp.registration.suspend(id, "carol@example.com", "incident");
  const no = await env.api("POST", `/v1/agents/${id}/recertify`, env.tok.alice);
  assert.equal(no.status, 422);
  assert.match(no.json.violations.join(" "), /only active or expiry-suspended/);
  assert.ok(env.cp.audit.query({ action: "agent.recertify", outcome: "success" }).length === 2);
  assert.equal(env.cp.audit.verifyChain(), -1);
  await env.close();
});

test("the scheduler runs one job at a time, records run status and scrubs errors", async () => {
  const env = await mkEnv();
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  env.cp.scheduler.add({ id: "slow", run: async () => { await gate; return { items: 2 }; } });
  env.cp.scheduler.add({ id: "boom", run: async () => { throw new Error("upstream said: Bearer abcdefghijklmnopqrstuvwxyz0123 is bad"); } });
  const first = env.cp.scheduler.runOnce("slow");
  const second = await env.cp.scheduler.runOnce("slow");
  assert.equal(second.status, "skipped");
  release();
  assert.equal((await first).status, "ok");
  const boom = await env.cp.scheduler.runOnce("boom");
  assert.equal(boom.status, "error");
  assert.equal(boom.error!.includes("abcdefghijklmnopqrstuvwxyz0123"), false);
  const st = await env.api("GET", "/v1/discovery/connectors", env.tok.carol);
  const slow = st.json.jobs.find((j: any) => j.jobId === "slow");
  assert.equal(slow.lastRun.status, "ok");
  assert.equal(slow.lastRun.items, 2);
  assert.equal(slow.intervalMs, 6 * 3_600_000);
  assert.equal(st.json.jobs.find((j: any) => j.jobId === "boom").lastRun.status, "error");
  assert.equal((await env.api("GET", "/v1/discovery/connectors", env.tok.alice)).status, 403);
  assert.ok(env.cp.audit.query({ action: "discovery.run" }).length >= 3);
  await env.close();
});

test("restart keeps discovery rows, overrides and expiry (state is in the database)", async () => {
  const env = await mkEnv();
  const s = env.cp.registration.submit(regBody(), "alice@example.com");
  assert.ok(s.ok);
  env.cp.registration.setRiskTier(s.agent.id, "medium", "alice@example.com", "precaution");
  env.cp.discovery.record({ source: "github", kind: "mcp_server", identity: ["o/r", "mcp.json", "x"], displayName: "x" });
  const dbPath = env.dbPath;
  await env.close();
  const cp2 = buildControlPlane({ dbPath });
  assert.equal(cp2.registry.get(s.agent.id)!.riskTier, "medium");
  assert.equal(cp2.registry.get(s.agent.id)!.riskOverride?.reason, "precaution");
  assert.equal(cp2.discovery.list().length, 1);
  const raw = new Database(dbPath, { readonly: true });
  assert.ok((raw.prepare(`SELECT count(*) AS n FROM discovered_agents`).get() as any).n === 1);
  raw.close();
  cp2.close();
});
