// Policy routes and the MCP admin client: authentication, roles, versioning, audit, fail-closed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { buildControlPlane, DEFAULT_PROFILES } from "./control-plane.js";
import { createSecureGateway } from "../gateway/secure-server.js";
import { GatewayClient, GatewayError } from "../mcp/gateway-client.js";
import { buildAdminServer } from "../mcp/admin-server.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const policy = (version: number, over: object = {}) => ({
  id: "pol-refund", version, toolName: "issue_refund", defaultDecision: "allow",
  rules: [{ kind: "parameter_threshold", field: "amount", greaterThan: 200, thenDecision: "deny", reason: "over limit" }],
  ...over,
});

async function env() {
  const dbPath = join(mkdtempSync(join(tmpdir(), "governai-admin-")), "cp.db");
  const cp = buildControlPlane({ dbPath });
  for (const p of DEFAULT_PROFILES) cp.profiles.upsert(p);
  cp.directory.upsert({ email: "dave@example.com", displayName: "dave", active: true, roles: ["admin"] });
  cp.directory.upsert({ email: "erin@example.com", displayName: "erin", active: true, roles: ["auditor"] });
  cp.directory.upsert({ email: "alice@example.com", displayName: "alice", active: true, roles: ["agent_owner"] });
  const server = createSecureGateway(cp).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const tok = (e: string) => cp.credentials.issueUserToken(e).token;
  return {
    cp, base, dbPath, dave: tok("dave@example.com"), erin: tok("erin@example.com"), alice: tok("alice@example.com"),
    async close() { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); cp.close(); },
  };
}

test("policy routes: admin only, validated, versioned, durable and logged", async () => {
  const e = await env();
  try {
    const put = (token: string | undefined, body: unknown) =>
      fetch(`${e.base}/v1/policies`, { method: "PUT", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });

    assert.equal((await put(undefined, policy(1))).status, 401);
    assert.equal((await put(e.alice, policy(1))).status, 403);
    assert.equal((await put(e.erin, policy(1))).status, 403, "auditors may read, not write");
    assert.equal((await put(e.dave, policy(1, { rules: [{ kind: "parameter_threshold", field: "amount", thenDecision: "allow", reason: "x", typo: 1 }] }))).status, 400, "unknown rule fields are rejected");
    assert.equal((await put(e.dave, policy(1))).status, 200);
    assert.equal((await put(e.dave, policy(1))).status, 409, "same version refused");
    assert.equal((await put(e.dave, policy(2))).status, 200);

    const got = await fetch(`${e.base}/v1/policies/issue_refund`, { headers: { authorization: `Bearer ${e.erin}` } });
    assert.equal(((await got.json()) as any).policy.version, 2);

    const logged = e.cp.audit.query({ action: "policy.set", limit: 50 });
    assert.ok(logged.every((x) => x.stream === "user"));
    assert.equal(logged.filter((x) => x.outcome === "success").length, 2);
    assert.equal(e.cp.audit.verifyChain(), -1);

    // durable: a fresh control plane on the same database enforces the stored policy
    e.cp.close();
    const again = buildControlPlane({ dbPath: e.dbPath });
    assert.equal(again.policyEngine.getPolicy("issue_refund")?.version, 2);
    again.close();
  } finally { await e.close().catch(() => {}); }
});

test("MCP admin server acts only through the gateway, with the caller's own role", async () => {
  const e = await env();
  try {
    const connect = async (token: string) => {
      const server = buildAdminServer(new GatewayClient(e.base, token));
      const [a, b] = InMemoryTransport.createLinkedPair();
      await server.connect(a);
      const client = new Client({ name: "t", version: "0" });
      await client.connect(b);
      return client;
    };
    const text = (r: any) => JSON.parse(r.content[0].text);

    const admin = await connect(e.dave);
    const ok = await admin.callTool({ name: "set_policy", arguments: { policy: policy(1) } });
    assert.ok(!ok.isError, JSON.stringify(ok));
    assert.equal((await admin.callTool({ name: "verify_audit_chain", arguments: {} })).isError, undefined);

    const owner = await connect(e.alice); // not an admin: the gateway refuses, MCP cannot bypass it
    const denied: any = await owner.callTool({ name: "set_policy", arguments: { policy: policy(2) } });
    assert.equal(denied.isError, true);
    assert.equal(text(denied).status, 403);

    const bad = await connect("gai.u.nope.nope"); // wrong credential: identical 401
    const r: any = await bad.callTool({ name: "list_agents", arguments: {} });
    assert.equal(text(r).status, 401);
  } finally { await e.close(); }
});

test("MCP admin client fails closed when the gateway is unreachable and refuses to start without config", async () => {
  await assert.rejects(new GatewayClient("http://127.0.0.1:1", "t", 500).request("GET", "/v1/agents"), (err: any) => err instanceof GatewayError && /unreachable/.test(err.message));
  assert.throws(() => new GatewayClient("", "t"), /GOVERNAI_GATEWAY_URL/);
  assert.throws(() => new GatewayClient("http://x", ""), /GOVERNAI_USER_TOKEN/);
});
