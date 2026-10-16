// Discovery connector tests: every connector parses fixture responses served
// through an injected fetch (no live calls), is read-only, and never lets
// secret material reach the database, the audit log or run errors.
// Run: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildControlPlane } from "../control/control-plane.js";
import {
  CopilotStudioConnector, EntraIdConnector, GeminiEnterpriseConnector, GitHubConnector, OktaConnector, connectorsFromEnv, mcpServersIn,
  type DiscoveryConnector,
} from "./connectors.js";
import { readOnlyFetch, ReadOnlyViolation, type FetchLike, type FetchResponse } from "./http.js";
import { findKeys, fingerprintSecret, scrubSecrets } from "../control/secret-patterns.js";

// Fake secrets: shaped like real ones so the patterns match, but not real.
const SECRETS = {
  entraClientSecret: "entra~CLIENT~secret~value~0000000000",
  oktaToken: "00oktaApiTokenValue1111111111111111111111",
  ghToken: "ghp_fakeGithubTokenValue22222222222222222",
  geminiToken: "ya29.fakeGoogleAccessToken3333333333333333",
  graphAccess: "eyJfake.graph.access.token.444444444444",
  dataverseAccess: "eyJfake.dataverse.access.token.55555555",
  anthropicKey: "sk-ant-api03-" + "A1b2C3d4E5".repeat(9) + "-xyzAA",
  openaiKey: "sk-proj-" + "Zz9Yy8Xx7W".repeat(6),
  googleKey: "AIza" + "SyD3fakeKeyForTests_0123456789abcde",
};

type Route = { method?: string; match: RegExp | string; status?: number; json?: unknown; text?: string; headers?: Record<string, string> };

/** Fixture fetch: answers from routes, records every call. */
function fixtureFetch(routes: Route[]) {
  const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];
  const f: FetchLike = async (url, init = {}) => {
    const method = (init.method ?? "GET").toUpperCase();
    calls.push({ url, method, headers: init.headers ?? {}, body: init.body });
    const r = routes.find((x) => (x.method ?? "GET") === method && (typeof x.match === "string" ? url === x.match : x.match.test(url)));
    const status = r ? (r.status ?? 200) : 404;
    const res: FetchResponse = {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (n: string) => r?.headers?.[n.toLowerCase()] ?? null },
      json: async () => (r?.json !== undefined ? structuredClone(r.json) : JSON.parse(r?.text ?? "{}")),
      text: async () => r?.text ?? JSON.stringify(r?.json ?? { error: "not found" }),
    };
    return res;
  };
  return { f, calls };
}

function mkCp() {
  const dir = mkdtempSync(join(tmpdir(), "zenai4-conn-"));
  return buildControlPlane({ dbPath: join(dir, "c.db") });
}

/** Runs a connector through the real scheduler + discovery store, then proves
 * no secret string is anywhere in the database or the audit log. */
async function runAndAssertNoSecrets(c: DiscoveryConnector, extraSecrets: string[] = []) {
  const cp = mkCp();
  cp.scheduler.addConnector(c, cp.discovery);
  const run = await cp.scheduler.runOnce(`connector:${c.id}`);
  const tables = (cp.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as Array<{ name: string }>).map((t) => t.name);
  const dump = tables.map((t) => JSON.stringify(cp.db.prepare(`SELECT * FROM "${t}"`).all())).join("\n") + cp.audit.exportJsonl({ limit: 100000 });
  for (const s of [...Object.values(SECRETS), ...extraSecrets]) {
    assert.equal(dump.includes(s), false, `secret material "${s.slice(0, 10)}..." must not be stored`);
  }
  const items = cp.discovery.list({ limit: 1000 });
  return { cp, run, items };
}

const ENV = {
  ZENAI4_ENTRA_TENANT_ID: "tenant-123",
  ZENAI4_ENTRA_CLIENT_ID: "client-abc",
  ZENAI4_ENTRA_CLIENT_SECRET: SECRETS.entraClientSecret,
  ZENAI4_OKTA_DOMAIN: "acme.okta.com",
  ZENAI4_OKTA_API_TOKEN: SECRETS.oktaToken,
  ZENAI4_DATAVERSE_URL: "https://contoso.crm.dynamics.com",
  ZENAI4_GEMINI_PROJECT: "acme-prod",
  ZENAI4_GEMINI_APP_IDS: "support-app, sales-app",
  ZENAI4_GEMINI_ACCESS_TOKEN: SECRETS.geminiToken,
  ZENAI4_GITHUB_TOKEN: SECRETS.ghToken,
  ZENAI4_GITHUB_ORG: "acme",
};

const assertGetOnly = (calls: Array<{ url: string; method: string }>, allowedPosts: RegExp[] = []) => {
  for (const c of calls) {
    if (c.method === "GET") continue;
    assert.ok(c.method === "POST" && allowedPosts.some((r) => r.test(c.url)), `unexpected ${c.method} ${c.url}`);
  }
};

// ------------------------------------------------------------------ helpers

test("secret patterns: keys are found by provider with a 4-hex fingerprint; scrubbing removes them", () => {
  const text = `const a = "${SECRETS.anthropicKey}";\nOPENAI_API_KEY=${SECRETS.openaiKey}\n# google ${SECRETS.googleKey}\nnothing here`;
  const hits = findKeys(text);
  assert.deepEqual(hits.map((h) => [h.provider, h.line]), [["anthropic", 1], ["openai", 2], ["google", 3]]);
  assert.equal(hits[0].fingerprint, fingerprintSecret(SECRETS.anthropicKey));
  assert.match(hits[0].fingerprint, /^[0-9a-f]{4}$/);
  const scrubbed = scrubSecrets(text + " Bearer abcdefghijklmnopqrstuvwxyz gai.a.key123.secretsecretsecretsecret");
  for (const s of [SECRETS.anthropicKey, SECRETS.openaiKey, SECRETS.googleKey, "abcdefghijklmnopqrstuvwxyz", "secretsecretsecretsecret"]) assert.equal(scrubbed.includes(s), false);
});

test("readOnlyFetch refuses anything but GET (except an exact token endpoint)", async () => {
  const { f, calls } = fixtureFetch([{ method: "POST", match: /token/, json: {} }, { match: /./, json: {} }]);
  const ro = readOnlyFetch(f, ["https://login.example/token"]);
  await ro("https://x.test/a");
  await ro("https://login.example/token", { method: "POST" });
  for (const m of ["POST", "PUT", "PATCH", "DELETE"]) {
    await assert.rejects(ro("https://x.test/a", { method: m }), ReadOnlyViolation);
  }
  await assert.rejects(ro("https://login.example/token?x=1", { method: "POST" }), ReadOnlyViolation, "exact URL only");
  assert.equal(calls.length, 2);
});

test("missing credentials env vars fail the run with the variable NAME, never a value", async () => {
  const c = new OktaConnector({}, { env: { ZENAI4_OKTA_DOMAIN: "acme.okta.com" }, fetch: fixtureFetch([]).f });
  const { run, cp } = await runAndAssertNoSecrets(c);
  assert.equal(run.status, "error");
  assert.match(run.error!, /missing environment variable\(s\): ZENAI4_OKTA_API_TOKEN/);
  assert.equal(cp.scheduler.status().find((j) => j.jobId === "connector:okta")!.lastRun!.status, "error");
  cp.close();
  assert.throws(() => connectorsFromEnv({ ZENAI4_DISCOVERY_CONNECTORS: "entra_id,nope" }), /unknown connector "nope"/);
  assert.deepEqual(connectorsFromEnv({ ZENAI4_DISCOVERY_CONNECTORS: "entra_id, okta,copilot_studio,gemini_enterprise,github" }).map((x) => x.kind), ["entra_id", "okta", "copilot_studio", "gemini_enterprise", "github"]);
});

// ------------------------------------------------------------------ Entra ID

test("Entra ID: lists agent identities (beta) and own-tenant service principals with paging", async () => {
  const { f, calls } = fixtureFetch([
    { method: "POST", match: "https://login.microsoftonline.com/tenant-123/oauth2/v2.0/token", json: { access_token: SECRETS.graphAccess, token_type: "Bearer" } },
    { match: /\/beta\/servicePrincipals\/microsoft\.graph\.agentIdentity\?\$select/, json: {
      value: [{ id: "ai-1", appId: "app-1", displayName: "HR Onboarding Agent", agentIdentityBlueprintId: "bp-1", accountEnabled: true }],
      "@odata.nextLink": "https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity?$skiptoken=p2",
    } },
    { match: /\$skiptoken=p2/, json: { value: [{ id: "ai-2", appId: "app-2", displayName: "Invoice Agent", agentIdentityBlueprintId: "bp-1" }] } },
    { match: /\/v1\.0\/servicePrincipals\?\$filter=/, json: { value: [
      { id: "sp-1", appId: "app-9", displayName: "billing-bot", appOwnerOrganizationId: "tenant-123", tags: ["WindowsAzureActiveDirectoryIntegratedApp"] },
      { id: "sp-ms", appId: "00000003-0000-0000-c000-000000000000", displayName: "Microsoft Graph", appOwnerOrganizationId: "f8cdef31-a31e-4b4a-93e4-5f571e91255a" },
    ] } },
  ]);
  const c = new EntraIdConnector({ includeServicePrincipals: true }, { fetch: f, env: ENV });
  const { run, items, cp } = await runAndAssertNoSecrets(c);
  assert.equal(run.status, "ok", run.error);
  assert.equal(run.items, 3);
  assert.deepEqual(items.map((i) => i.displayName).sort(), ["HR Onboarding Agent", "Invoice Agent", "billing-bot"]);
  assert.equal(items.find((i) => i.displayName === "Invoice Agent")!.kind, "agent_identity");
  assert.equal(items.find((i) => i.displayName === "billing-bot")!.attributes.appId, "app-9");
  assertGetOnly(calls, [/login\.microsoftonline\.com\/tenant-123\/oauth2\/v2\.0\/token$/]);
  assert.ok(calls.filter((x) => x.method === "GET").every((x) => x.headers.authorization === `Bearer ${SECRETS.graphAccess}`));
  // Second run dedupes
  await cp.scheduler.runOnce(`connector:${c.id}`);
  assert.equal(cp.discovery.list().length, 3);
  assert.ok(cp.discovery.list().every((d) => d.count === 2));
  cp.close();
});

test("Entra ID: a tenant without Agent ID (beta 404) is not an error", async () => {
  const { f } = fixtureFetch([
    { method: "POST", match: /oauth2\/v2\.0\/token$/, json: { access_token: SECRETS.graphAccess } },
    { match: /agentIdentity/, status: 404, json: { error: { code: "Request_ResourceNotFound" } } },
  ]);
  const { run, items, cp } = await runAndAssertNoSecrets(new EntraIdConnector({}, { fetch: f, env: ENV }));
  assert.equal(run.status, "ok", run.error);
  assert.equal(items.length, 0);
  cp.close();
});

// ------------------------------------------------------------------ Okta

test("Okta: lists only service apps (client_credentials), follows Link paging on-tenant only", async () => {
  const { f, calls } = fixtureFetch([
    { match: "https://acme.okta.com/api/v1/apps?limit=200", json: [
      { id: "0oa1", label: "Claims Agent", status: "ACTIVE", signOnMode: "OPENID_CONNECT", settings: { oauthClient: { application_type: "service" } } },
      { id: "0oa2", label: "Employee Portal", status: "ACTIVE", signOnMode: "OPENID_CONNECT", settings: { oauthClient: { application_type: "web", grant_types: ["authorization_code"] } } },
    ], headers: { link: '<https://acme.okta.com/api/v1/apps?after=0oa2&limit=200>; rel="next"' } },
    { match: "https://acme.okta.com/api/v1/apps?after=0oa2&limit=200", json: [
      { id: "0oa3", label: "Report Bot", status: "INACTIVE", settings: { oauthClient: { grant_types: ["client_credentials"] } } },
    ], headers: { link: '<https://evil.example/api/v1/apps?after=x>; rel="next"' } },
  ]);
  const { run, items, cp } = await runAndAssertNoSecrets(new OktaConnector({}, { fetch: f, env: ENV }));
  assert.equal(run.status, "ok", run.error);
  assert.deepEqual(items.map((i) => i.displayName).sort(), ["Claims Agent", "Report Bot"]);
  assert.equal(calls.length, 2, "did not follow an off-tenant next link");
  assertGetOnly(calls);
  assert.equal(calls[0].headers.authorization, `SSWS ${SECRETS.oktaToken}`);
  cp.close();
});

// ------------------------------------------------------------------ Copilot Studio

test("Copilot Studio: lists Dataverse bots with owner names", async () => {
  const { f, calls } = fixtureFetch([
    { method: "POST", match: /oauth2\/v2\.0\/token$/, json: { access_token: SECRETS.dataverseAccess } },
    { match: /contoso\.crm\.dynamics\.com\/api\/data\/v9\.2\/bots\?\$select=/, json: { value: [
      { botid: "b-1", name: "IT Helpdesk", schemaname: "cr_itHelpdesk", statecode: 0, statuscode: 1, _ownerid_value: "u-1", "_ownerid_value@OData.Community.Display.V1.FormattedValue": "Priya N" },
      { botid: "b-2", name: "Travel Booker", schemaname: "cr_travel", statecode: 1, statuscode: 2, _ownerid_value: "u-2" },
    ] } },
  ]);
  const { run, items, cp } = await runAndAssertNoSecrets(new CopilotStudioConnector({}, { fetch: f, env: ENV }));
  assert.equal(run.status, "ok", run.error);
  const it = items.find((i) => i.displayName === "IT Helpdesk")!;
  assert.equal(it.kind, "copilot_agent");
  assert.equal(it.attributes.ownerName, "Priya N");
  assert.equal(items.length, 2);
  const tokenCall = calls.find((c) => c.method === "POST")!;
  assert.match(tokenCall.body!, /scope=https%3A%2F%2Fcontoso\.crm\.dynamics\.com%2F\.default/);
  assertGetOnly(calls, [/oauth2\/v2\.0\/token$/]);
  cp.close();
  const bad = new CopilotStudioConnector({}, { fetch: f, env: { ...ENV, ZENAI4_DATAVERSE_URL: "https://evil.example" } });
  await assert.rejects(bad.run(), /must look like/);
});

// ------------------------------------------------------------------ Gemini Enterprise

test("Gemini Enterprise: lists agents per app with pageToken paging", async () => {
  const base = "https://discoveryengine.googleapis.com/v1alpha/projects/acme-prod/locations/global/collections/default_collection/engines";
  const { f, calls } = fixtureFetch([
    { match: `${base}/support-app/assistants/default_assistant/agents`, json: {
      agents: [{ name: "projects/123/locations/global/collections/default_collection/engines/support-app/assistants/default_assistant/agents/111", displayName: "Refund Helper", state: "ENABLED", a2aAgentDefinition: { jsonAgentCard: "{}" } }],
      nextPageToken: "tok2",
    } },
    { match: `${base}/support-app/assistants/default_assistant/agents?pageToken=tok2`, json: {
      agents: [{ name: "projects/123/.../agents/112", displayName: "FAQ", adkAgentDefinition: {} }],
    } },
    { match: `${base}/sales-app/assistants/default_assistant/agents`, json: {} },
  ]);
  const { run, items, cp } = await runAndAssertNoSecrets(new GeminiEnterpriseConnector({}, { fetch: f, env: ENV }));
  assert.equal(run.status, "ok", run.error);
  assert.deepEqual(items.map((i) => [i.displayName, i.kind]).sort(), [["FAQ", "adk_agent"], ["Refund Helper", "a2a_agent"]]);
  assert.equal(calls.length, 3);
  assertGetOnly(calls);
  assert.equal(calls[0].headers["x-goog-user-project"], "acme-prod");
  cp.close();
  // Regional endpoint
  const eu = fixtureFetch([{ match: /^https:\/\/eu-discoveryengine\.googleapis\.com\/v1alpha\/projects\/acme-prod\/locations\/eu\//, json: { agents: [] } }]);
  await new GeminiEnterpriseConnector({}, { fetch: eu.f, env: { ...ENV, ZENAI4_GEMINI_LOCATION: "eu", ZENAI4_GEMINI_APP_IDS: "x" } }).run();
  assert.equal(eu.calls.length, 1);
});

// ------------------------------------------------------------------ GitHub

test("GitHub: finds MCP servers and leaked LLM keys, storing only repo/path/line/provider/fingerprint", async () => {
  const mcpJson = JSON.stringify({
    mcpServers: {
      postgres: { command: "/usr/local/bin/npx", args: ["-y", "@modelcontextprotocol/server-postgres", "postgresql://user:dbpassword123@db/prod"], env: { PGPASSWORD: "hunter2hunter2" } },
      remote: { type: "http", url: "https://mcp.vendor.example/sse", headers: { Authorization: "Bearer remoteMcpBearerToken12345" } },
    },
  });
  const vscodeMcp = `{
    // VS Code style, with comments and trailing commas
    "servers": { "github": { "type": "stdio", "command": "docker", "args": ["run", "ghcr.io/github/github-mcp-server"], }, },
  }`;
  const leaky = `import os\nclient = Anthropic(api_key="${SECRETS.anthropicKey}")\n# old: ${SECRETS.openaiKey}\n`;
  const api = "https://api.github.com";
  const { f, calls } = fixtureFetch([
    { match: /\/search\/code\?q=filename%3Amcp\.json%20org%3Aacme/, json: { items: [{ path: "mcp.json", sha: "s1", repository: { full_name: "acme/agents" } }] } },
    { match: /\/search\/code\?q=filename%3Aclaude_desktop_config\.json/, json: { items: [] } },
    { match: /\/search\/code\?q=path%3A\.vscode/, json: { items: [{ path: ".vscode/mcp.json", repository: { full_name: "acme/web" } }] } },
    { match: /\/search\/code\?q=%22sk-ant-%22/, json: { items: [{ path: "bots/run.py", repository: { full_name: "acme/agents" } }] } },
    { match: /\/search\/code\?q=%22sk-proj-%22/, json: { items: [{ path: "bots/run.py", repository: { full_name: "acme/agents" } }] } },
    { match: /\/search\/code\?q=/, json: { items: [] } },
    { match: `${api}/repos/acme/agents/contents/mcp.json`, text: mcpJson },
    { match: `${api}/repos/acme/web/contents/.vscode/mcp.json`, text: vscodeMcp },
    { match: `${api}/repos/acme/agents/contents/bots/run.py`, text: leaky },
  ]);
  const { run, items, cp } = await runAndAssertNoSecrets(new GitHubConnector({}, { fetch: f, env: ENV }), [
    "dbpassword123", "hunter2hunter2", "remoteMcpBearerToken12345",
  ]);
  assert.equal(run.status, "ok", run.error);
  assertGetOnly(calls);
  assert.ok(calls.every((c) => c.headers.authorization === `Bearer ${SECRETS.ghToken}`));

  const mcp = items.filter((i) => i.kind === "mcp_server");
  assert.deepEqual(mcp.map((i) => i.attributes.serverName).sort(), ["github", "postgres", "remote"]);
  const pg = mcp.find((i) => i.attributes.serverName === "postgres")!;
  assert.equal(pg.attributes.command, "npx");
  assert.equal(pg.attributes.package, "@modelcontextprotocol/server-postgres");
  assert.deepEqual(pg.attributes.envVarNames, ["PGPASSWORD"], "env var names only");
  assert.equal(mcp.find((i) => i.attributes.serverName === "remote")!.attributes.urlHost, "mcp.vendor.example");

  const keys = items.filter((i) => i.kind === "llm_api_key");
  assert.deepEqual(keys.map((k) => [k.attributes.provider, k.attributes.line]).sort(), [["anthropic", 2], ["openai", 3]]);
  const ak = keys.find((k) => k.attributes.provider === "anthropic")!;
  assert.deepEqual(Object.keys(ak.attributes).sort(), ["keyFingerprint", "line", "path", "provider", "repo"]);
  assert.equal(ak.attributes.keyFingerprint, fingerprintSecret(SECRETS.anthropicKey));
  assert.equal(ak.attributes.repo, "acme/agents");
  // file fetched once even though two searches matched it
  assert.equal(calls.filter((c) => c.url.endsWith("/contents/bots/run.py")).length, 1);
  cp.close();
});

test("mcpServersIn ignores files that are not MCP configs", () => {
  assert.deepEqual(mcpServersIn("not json", "r", "p"), []);
  assert.deepEqual(mcpServersIn(JSON.stringify({ foo: 1 }), "r", "p"), []);
});
