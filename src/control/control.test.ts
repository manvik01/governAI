// Tests for agent onboarding, the authenticated gateway, security monitoring
// and the audit/user logs. Run: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { buildControlPlane, DEFAULT_PROFILES } from "./control-plane.js";
import { createSecureGateway, type SecureGatewayOptions } from "../gateway/secure-server.js";
import type { RegistrationRequest } from "./registration.js";

// ------------------------------------------------------------------ fixtures

const regBody = (over: Partial<RegistrationRequest> = {}): RegistrationRequest => ({
  name: "RefundBot",
  purpose: "Issues customer refunds",
  ownerEmail: "alice@example.com",
  subOwnerEmail: "bob@example.com",
  accessProfileId: "customer-facing",
  businessUnit: "Customer Success",
  platform: "custom",
  modelProvider: "anthropic",
  modelVersion: "claude-sonnet-5",
  autonomyDefault: "A2",
  mode: "enforcement",
  tools: [
    { toolName: "issue_refund", reversible: false, dataClasses: ["financial", "customer_pii"] },
    { toolName: "llm_invoke", reversible: true, dataClasses: [] },
  ],
  budgetPolicy: {},
  ...over,
});

const CHECKLIST = {
  identity_verified: true,
  least_privilege_reviewed: true,
  data_classification_confirmed: true,
  logging_enabled: true,
  kill_switch_tested: true,
};

async function mkEnv(opts: { gateway?: SecureGatewayOptions; monitor?: Parameters<typeof buildControlPlane>[0]["monitor"] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "governai-control-"));
  const dbPath = join(dir, "cp.db");
  const siemPath = join(dir, "siem.jsonl");
  const cp = buildControlPlane({ dbPath, siemPath, monitor: opts.monitor });
  for (const p of DEFAULT_PROFILES) cp.profiles.upsert(p);
  const people: Array<[string, any[]]> = [
    ["alice@example.com", ["agent_owner"]],
    ["bob@example.com", ["agent_owner"]],
    ["carol@example.com", ["security_reviewer"]],
    ["dave@example.com", ["admin"]],
    ["erin@example.com", ["auditor"]],
    ["grace@example.com", ["security_reviewer", "agent_owner"]],
  ];
  for (const [email, roles] of people) cp.directory.upsert({ email, displayName: email.split("@")[0], active: true, roles });
  cp.directory.upsert({ email: "frank@example.com", displayName: "frank", active: false, roles: ["agent_owner"] }); // a leaver
  cp.policyEngine.setPolicy({
    id: "pol-refund", version: 1, toolName: "issue_refund", defaultDecision: "allow",
    rules: [{ kind: "parameter_threshold", field: "amount", greaterThan: 200, thenDecision: "deny", reason: "over limit" }],
  });

  const app = createSecureGateway(cp, { trustProxy: true, ...opts.gateway });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const tok: Record<string, string> = {};
  for (const [email] of people) tok[email.split("@")[0]] = cp.credentials.issueUserToken(email).token;

  const api = async (method: string, path: string, token?: string, body?: unknown, ip = "10.0.0.1") => {
    const res = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json", "x-forwarded-for": ip, ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    let json: any;
    try {
      json = await res.json();
    } catch {
      json = undefined;
    }
    return { status: res.status, json };
  };

  /** Registers an agent through the full human workflow and returns its credential token. */
  const onboard = async (over: Partial<RegistrationRequest> = {}) => {
    const sub = await api("POST", "/v1/agents", tok.alice, regBody(over));
    assert.equal(sub.status, 201, JSON.stringify(sub.json));
    if (!sub.json.needsReview) return { agentId: sub.json.agentId as string, token: sub.json.credential.token as string };
    const rev = await api("POST", `/v1/agents/${sub.json.agentId}/review`, tok.carol, { decision: "approve", checklist: CHECKLIST });
    assert.equal(rev.status, 200, JSON.stringify(rev.json));
    return { agentId: sub.json.agentId as string, token: rev.json.credential.token as string };
  };

  return {
    dir, dbPath, siemPath, cp, api, tok, base, onboard,
    async close() {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      cp.close();
    },
  };
}

const actions = (cp: ReturnType<typeof buildControlPlane>) => new Set(cp.audit.query({ limit: 5000 }).map((e) => e.action));

// ------------------------------------------------------------ registration

test("registration refuses unverified identities, missing sub-owner and out-of-profile access - and logs every refusal", async () => {
  const env = await mkEnv();
  const attempts: Array<[Partial<RegistrationRequest>, string, RegExp]> = [
    [{ ownerEmail: "mallory@evil.test" }, "alice@example.com", /owner .* not an active user/],
    [{ ownerEmail: "frank@example.com" }, "alice@example.com", /owner .* not an active user/], // leaver
    [{ ownerEmail: "carol@example.com" }, "carol@example.com", /does not hold the agent_owner role/],
    [{ subOwnerEmail: "" }, "alice@example.com", /sub-owner is required/],
    [{ subOwnerEmail: "alice@example.com" }, "alice@example.com", /different people/],
    [{ accessProfileId: "nope" }, "alice@example.com", /does not exist/],
    [{ tools: [{ toolName: "delete_database", reversible: false, dataClasses: ["internal"] }] }, "alice@example.com", /tool "delete_database" is not permitted/],
    [{ tools: [{ toolName: "issue_refund", reversible: true, dataClasses: ["health_records"] }] }, "alice@example.com", /data class "health_records"/],
    [{ autonomyDefault: "A4" }, "alice@example.com", /autonomy A4 exceeds/],
    [{ modelVersion: "gpt-unvetted", permittedModels: ["gpt-unvetted"] }, "alice@example.com", /model "gpt-unvetted"/],
    [{}, "erin@example.com", /only the owner, the sub-owner or an admin/],
    [{ purpose: "  " }, "alice@example.com", /purpose is required/],
  ];
  for (const [over, by, expected] of attempts) {
    const out = env.cp.registration.submit(regBody(over), by);
    assert.equal(out.ok, false, `expected refusal for ${JSON.stringify(over)}`);
    assert.match((out as any).violations.join(" | "), expected);
  }
  assert.equal(env.cp.registry.list().length, 0, "nothing was registered");
  const denied = env.cp.audit.query({ action: "agent.register", outcome: "denied" });
  assert.equal(denied.length, attempts.length, "every refused attempt is in the user log");
  assert.ok(denied.every((e) => e.stream === "user" && e.actorType === "user"));
  await env.close();
});

test("review: a reviewer is required, checklist must be complete, and owners cannot review their own agent", async () => {
  const env = await mkEnv();
  const sub = await env.api("POST", "/v1/agents", env.tok.alice, regBody());
  assert.equal(sub.status, 201);
  assert.equal(sub.json.lifecycleState, "pending_approval");
  assert.equal(sub.json.credential, undefined, "no credential before review");
  const id = sub.json.agentId;

  // not a reviewer / admin is not a reviewer
  assert.equal((await env.api("POST", `/v1/agents/${id}/review`, env.tok.alice, { decision: "approve", checklist: CHECKLIST })).status, 403);
  assert.equal((await env.api("POST", `/v1/agents/${id}/review`, env.tok.dave, { decision: "approve", checklist: CHECKLIST })).status, 403);
  // incomplete checklist
  const partial = await env.api("POST", `/v1/agents/${id}/review`, env.tok.carol, { decision: "approve", checklist: { ...CHECKLIST, kill_switch_tested: false } });
  assert.equal(partial.status, 422);
  assert.match(partial.json.violations.join(), /checklist incomplete: kill_switch_tested/);
  assert.equal(env.cp.registry.get(id)!.lifecycleState, "pending_approval");

  // separation of duties: grace is a reviewer AND the sub-owner of this other agent
  const other = await env.api("POST", "/v1/agents", env.tok.alice, regBody({ name: "Other", subOwnerEmail: "grace@example.com" }));
  const self = await env.api("POST", `/v1/agents/${other.json.agentId}/review`, env.tok.grace, { decision: "approve", checklist: CHECKLIST });
  assert.equal(self.status, 422);
  assert.match(self.json.violations.join(), /separation of duties/);

  // proper review activates and issues a credential exactly once
  const ok = await env.api("POST", `/v1/agents/${id}/review`, env.tok.carol, { decision: "approve", checklist: CHECKLIST, notes: "looks fine" });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.lifecycleState, "active");
  assert.match(ok.json.credential.token, /^gai\.a\./);
  const again = await env.api("POST", `/v1/agents/${id}/review`, env.tok.carol, { decision: "approve", checklist: CHECKLIST });
  assert.equal(again.status, 422, "cannot approve twice");

  // rejection path
  const rej = await env.api("POST", `/v1/agents/${other.json.agentId}/review`, env.tok.carol, { decision: "reject", notes: "too broad" });
  assert.equal(rej.status, 200);
  assert.equal(env.cp.registry.get(other.json.agentId)!.lifecycleState, "rejected");
  await env.close();
});

test("a low-risk profile that needs no review activates immediately with a credential", async () => {
  const env = await mkEnv();
  const out = await env.api("POST", "/v1/agents", env.tok.alice, regBody({
    name: "DocReader", accessProfileId: "internal-readonly", autonomyDefault: "A1", modelVersion: "claude-haiku-4-5",
    tools: [{ toolName: "read_docs", reversible: true, dataClasses: ["internal"] }],
  }));
  assert.equal(out.status, 201);
  assert.equal(out.json.lifecycleState, "active");
  assert.equal(out.json.needsReview, false);
  assert.ok(out.json.credential.token);
  await env.close();
});

// ------------------------------------------------------- credentials & secrets

test("secrets are stored only as hashes and never reach the audit log or SIEM stream", async () => {
  const env = await mkEnv();
  const { token } = await env.onboard();
  const secret = token.split(".")[3];
  await env.api("POST", "/v1/call", token, { toolName: "issue_refund", principal: "alice@example.com", parameters: { amount: 10 } });
  await env.api("POST", "/v1/call", "gai.a.bogus." + secret, { toolName: "x", principal: "p" }); // failure path too

  assert.ok(!env.cp.credentials.storedHashes().includes(secret), "plaintext secret is not stored");
  assert.ok(env.cp.credentials.storedHashes().every((h) => /^[0-9a-f]{64}$/.test(h)));
  const everything = env.cp.audit.exportJsonl({ limit: 5000 }) + readFileSync(env.siemPath, "utf8");
  assert.ok(!everything.includes(secret), "no secret in audit export or SIEM file");
  assert.ok(!everything.includes(token));
  // defence in depth: sensitive detail keys are redacted at write time
  const e = env.cp.audit.append({ stream: "audit", actorType: "system", actorId: "t", action: "t.redact", outcome: "success", details: { token: "abc", nested: { apiKey: "k", ok: 1 } } });
  assert.deepEqual(e.details, { token: "[redacted]", nested: { apiKey: "[redacted]", ok: 1 } });
  await env.close();
});

test("state survives a restart: agents, credentials and the audit chain are persistent", async () => {
  const env = await mkEnv();
  const { agentId, token } = await env.onboard();
  const before = env.cp.audit.query({ limit: 5000 }).length;
  const { dbPath } = env;
  env.cp.close();

  const cp2 = buildControlPlane({ dbPath });
  assert.equal(cp2.registry.get(agentId)!.lifecycleState, "active");
  assert.equal(cp2.registry.grantsFor(agentId).length, 2);
  const v = cp2.credentials.verify(token);
  assert.ok(v.ok && v.subject === agentId);
  assert.equal(cp2.audit.query({ limit: 5000 }).length, before);
  assert.equal(cp2.audit.verifyChain(), -1);
  cp2.close();
  await env.close(); // stops the HTTP server (closing the already-closed db handles is a no-op)
});

// ----------------------------------------------------------------- gateway auth

test("gateway: no credential, bad credential, wrong credential kind are all refused with an identical 401/403", async () => {
  const env = await mkEnv();
  const { agentId, token } = await env.onboard();
  const none = await env.api("POST", "/v1/call", undefined, { toolName: "issue_refund", principal: "p" });
  const garbage = await env.api("POST", "/v1/call", "not-a-token", { toolName: "issue_refund", principal: "p" });
  const wrongSecret = await env.api("POST", "/v1/call", token.slice(0, -3) + "xxx", { toolName: "issue_refund", principal: "p" });
  assert.deepEqual([none.status, garbage.status, wrongSecret.status], [401, 401, 401]);
  assert.deepEqual(none.json, garbage.json, "no oracle: every failure looks the same");
  assert.deepEqual(garbage.json, wrongSecret.json);

  // a human token cannot use the agent call path
  assert.equal((await env.api("POST", "/v1/call", env.tok.alice, { toolName: "issue_refund", principal: "p" })).status, 403);

  // the precise reason is only in the audit log
  const reasons = env.cp.audit.query({ action: "auth.failed" }).map((e) => e.details.reason);
  assert.deepEqual(reasons, ["missing_credentials", "malformed", "bad_secret"]);

  // a valid call works, and policy still applies behind authentication
  const ok = await env.api("POST", "/v1/call", token, { toolName: "issue_refund", principal: "alice@example.com", parameters: { amount: 50 } });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.allowed, true);
  const over = await env.api("POST", "/v1/call", token, { toolName: "issue_refund", principal: "alice@example.com", parameters: { amount: 500 } });
  assert.equal(over.json.decision, "deny");
  const logged = env.cp.audit.query({ action: "gateway.call", actorId: agentId });
  assert.deepEqual(logged.map((e) => e.outcome), ["success", "denied"]);
  assert.ok(logged[0].details.ledgerEventId, "audit entry links to the governance ledger event");
  await env.close();
});

test("gateway: an agent cannot act as another agent; the attempt is refused and alerted", async () => {
  const env = await mkEnv();
  const a = await env.onboard();
  const b = await env.onboard({ name: "Second" });
  const res = await env.api("POST", "/v1/call", a.token, { agentId: b.agentId, toolName: "issue_refund", principal: "p", parameters: { amount: 1 } });
  assert.equal(res.status, 403);
  assert.ok(env.cp.audit.query({ action: "identity.mismatch" }).length === 1);
  assert.ok(env.cp.monitor.listAlerts().some((al) => al.rule === "identity_spoofing" && al.subject === a.agentId));
  await env.close();
});

test("suspension revokes credentials at the edge; rotation invalidates the old credential", async () => {
  const env = await mkEnv();
  const a = await env.onboard();
  const call = (t: string) => env.api("POST", "/v1/call", t, { toolName: "issue_refund", principal: "p", parameters: { amount: 1 } });

  // rotation: only owner/sub-owner/admin
  assert.equal((await env.api("POST", `/v1/agents/${a.agentId}/credentials/rotate`, env.tok.erin)).status, 403);
  const rot = await env.api("POST", `/v1/agents/${a.agentId}/credentials/rotate`, env.tok.bob);
  assert.equal(rot.status, 200);
  assert.equal((await call(a.token)).status, 401, "old credential is dead");
  assert.equal((await call(rot.json.credential.token)).status, 200, "new credential works");

  // suspension by an owner (permitted) - credentials die immediately, not just policy
  assert.equal((await env.api("POST", `/v1/agents/${a.agentId}/suspend`, env.tok.erin, { reason: "x" })).status, 403);
  assert.equal((await env.api("POST", `/v1/agents/${a.agentId}/suspend`, env.tok.alice, { reason: "incident" })).status, 200);
  assert.equal((await call(rot.json.credential.token)).status, 401);
  assert.equal(env.cp.registry.isActive(a.agentId), false);
  assert.ok(env.cp.audit.query({ action: "auth.failed" }).some((e) => e.details.reason === "revoked"));
  assert.ok(env.cp.monitor.listAlerts().some((al) => al.rule === "dead_credential_used"));
  await env.close();
});

test("a deactivated person loses access even with a valid, unexpired token", async () => {
  const env = await mkEnv();
  assert.equal((await env.api("GET", "/v1/agents", env.tok.alice)).status, 200);
  env.cp.directory.deactivate("alice@example.com");
  assert.equal((await env.api("GET", "/v1/agents", env.tok.alice)).status, 401);
  assert.ok(env.cp.audit.query({ action: "auth.failed" }).some((e) => e.details.reason === "user_inactive"));
  await env.close();
});

test("role checks on human routes; owners only see their own agents", async () => {
  const env = await mkEnv();
  await env.onboard();
  assert.equal((await env.api("GET", "/v1/audit", env.tok.alice)).status, 403);
  assert.equal((await env.api("GET", "/v1/security/alerts", env.tok.alice)).status, 403);
  assert.equal((await env.api("GET", "/v1/audit", env.tok.erin)).status, 200);
  assert.equal((await env.api("GET", "/v1/agents", env.tok.erin)).json.agents.length, 1, "auditor sees all");
  assert.equal((await env.api("GET", "/v1/agents", env.tok.grace)).json.agents.length, 1, "reviewer sees all");
  const noAgents = env.cp.directory.upsert({ email: "ivan@example.com", displayName: "ivan", active: true, roles: ["agent_owner"] });
  void noAgents;
  const ivan = env.cp.credentials.issueUserToken("ivan@example.com").token;
  assert.equal((await env.api("GET", "/v1/agents", ivan)).json.agents.length, 0, "owner sees only their own");
  assert.ok(env.cp.audit.query({ action: "access.denied" }).length >= 2);
  await env.close();
});

// ------------------------------------------------------------------- audit logs

test("every action produces a log entry, in the right stream, and reading the audit log is itself logged", async () => {
  const env = await mkEnv();
  const a = await env.onboard();
  await env.api("POST", "/v1/call", a.token, { toolName: "issue_refund", principal: "p", parameters: { amount: 10 } });
  await env.api("POST", `/v1/agents/${a.agentId}/credentials/rotate`, env.tok.alice);
  await env.api("POST", `/v1/agents/${a.agentId}/suspend`, env.tok.dave, { reason: "test" });
  await env.api("GET", "/v1/audit?stream=user", env.tok.erin);
  await env.api("POST", "/v1/call", "bad.token", { toolName: "x", principal: "p" });

  const seen = actions(env.cp);
  for (const expected of ["agent.registered", "agent.review", "agent.approved", "credential.issue", "auth.success", "auth.failed", "gateway.call", "credential.rotate", "agent.suspended", "credential.revoke", "audit.query"]) {
    assert.ok(seen.has(expected), `missing audit action: ${expected} (have ${[...seen].join(", ")})`);
  }
  // user stream = humans only; audit stream = system/agent/anonymous
  const user = env.cp.audit.query({ stream: "user", limit: 5000 });
  const sys = env.cp.audit.query({ stream: "audit", limit: 5000 });
  assert.ok(user.length > 0 && sys.length > 0);
  assert.ok(user.every((e) => e.actorType === "user"), "user stream holds only human actions");
  assert.ok(sys.every((e) => e.actorType !== "user"));
  const q = env.cp.audit.query({ action: "audit.query" })[0];
  assert.equal(q.actorId, "erin@example.com");
  assert.equal(q.stream, "user");
  // every event carries the request id and source address from the gateway
  const http = env.cp.audit.query({ action: "gateway.call" })[0];
  assert.ok(http.requestId && http.sourceIp === "10.0.0.1");
  // SIEM stream mirrors the log line-for-line
  const lines = readFileSync(env.siemPath, "utf8").trim().split("\n");
  assert.equal(lines.length, env.cp.audit.query({ limit: 100000 }).length);
  await env.close();
});

test("the audit log is tamper-evident: edits and deletions are detected and located", async () => {
  const env = await mkEnv();
  await env.onboard();
  assert.equal((await env.api("GET", "/v1/audit/verify", env.tok.erin)).json.intact, true);

  const target = env.cp.audit.query({ action: "agent.review" })[0];
  env.cp.db.prepare(`UPDATE audit_events SET outcome = 'success', details = '{}' WHERE seq = ?`).run(target.seq - 1);
  const edited = await env.api("GET", "/v1/audit/verify", env.tok.erin);
  assert.equal(edited.json.intact, false);
  assert.equal(edited.json.firstBrokenSeq, target.seq - 1);
  await env.close();

  const env2 = await mkEnv();
  await env2.onboard();
  const mid = env2.cp.audit.query({ limit: 100 })[2];
  env2.cp.db.prepare(`DELETE FROM audit_events WHERE seq = ?`).run(mid.seq);
  const deleted = await env2.api("GET", "/v1/audit/verify", env2.tok.erin);
  assert.equal(deleted.json.intact, false);
  assert.equal(deleted.json.firstBrokenSeq, mid.seq + 1, "break is reported at the row after the gap");
  await env2.close();
});

// ------------------------------------------------------- infiltration monitoring

test("monitor: auth-failure burst, new-source credential use and policy probing raise alerts that reach audit, API and SIEM", async () => {
  const env = await mkEnv();
  const a = await env.onboard();

  // credential stuffing from one source; alert is raised once (cooldown), not per attempt
  for (let i = 0; i < 12; i++) await env.api("POST", "/v1/call", `gai.a.guess${i}.secret`, { toolName: "x", principal: "p" }, "203.0.113.9");
  // a stolen-looking credential used from a second network address
  await env.api("POST", "/v1/call", a.token, { toolName: "issue_refund", principal: "p", parameters: { amount: 1 } }, "10.0.0.1");
  await env.api("POST", "/v1/call", a.token, { toolName: "issue_refund", principal: "p", parameters: { amount: 1 } }, "198.51.100.77");
  // an agent repeatedly testing the policy boundary
  for (let i = 0; i < 6; i++) await env.api("POST", "/v1/call", a.token, { toolName: "issue_refund", principal: "p", parameters: { amount: 999 } }, "10.0.0.1");

  const alerts = (await env.api("GET", "/v1/security/alerts", env.tok.erin)).json.alerts as any[];
  const byRule = (r: string) => alerts.filter((x) => x.rule === r);
  assert.equal(byRule("auth_failure_burst").length, 1, "de-duplicated by cooldown");
  assert.equal(byRule("auth_failure_burst")[0].subject, "203.0.113.9");
  assert.equal(byRule("auth_failure_burst")[0].severity, "high");
  assert.equal(byRule("credential_new_source").length, 1);
  assert.equal(byRule("credential_new_source")[0].details.sourceIp, "198.51.100.77");
  assert.equal(byRule("policy_probing").length, 1);
  assert.equal(byRule("policy_probing")[0].subject, a.agentId);

  assert.ok(env.cp.audit.query({ action: "security.alert" }).length >= 3, "alerts are in the tamper-evident log");
  assert.ok(readFileSync(env.siemPath, "utf8").includes('"action":"security.alert"'), "alerts are forwarded to the SIEM stream");
  assert.equal(env.cp.audit.verifyChain(), -1);
  await env.close();
});

test("rate limiting and oversized/malformed bodies are refused, logged and alerted", async () => {
  const env = await mkEnv({ gateway: { rateLimitPerMin: 3, maxBodyBytes: 512 } });
  const a = await env.onboard();
  const statuses: number[] = [];
  for (let i = 0; i < 6; i++) statuses.push((await env.api("POST", "/v1/call", a.token, { toolName: "issue_refund", principal: "p", parameters: { amount: 1 } })).status);
  assert.ok(statuses.includes(429), `expected a 429 in ${statuses}`);
  assert.ok(env.cp.audit.query({ action: "rate_limit.exceeded" }).length >= 1);

  const big = await env.api("POST", "/v1/agents", env.tok.dave, "x".repeat(2000));
  assert.equal(big.status, 413);
  const bad = await env.api("POST", "/v1/agents", env.tok.dave, "{ not json", "10.7.7.7");
  assert.equal(bad.status, 400);
  assert.ok(env.cp.audit.query({ action: "request.malformed" }).length >= 2);
  await env.close();
});

test("health endpoints need no credential and expose no data", async () => {
  const env = await mkEnv();
  assert.deepEqual((await env.api("GET", "/healthz")).json, { status: "ok" });
  assert.deepEqual((await env.api("GET", "/readyz")).json, { ready: true });
  assert.equal((await env.api("GET", "/v1/agents")).status, 401);
  assert.equal((await env.api("GET", "/nope", env.tok.alice)).status, 404);
  await env.close();
});
