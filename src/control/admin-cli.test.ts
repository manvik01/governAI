// Bootstrap admin CLI, run as a real child process against a real database file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import Database from "better-sqlite3";
import { buildControlPlane } from "./control-plane.js";
import { createSecureGateway } from "../gateway/secure-server.js";

const CLI = new URL("./admin-cli.js", import.meta.url).pathname;
const KEY = randomBytes(32).toString("base64");

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "zenai4-cli-"));
  const db = join(dir, "g.db");
  const cli = (...args: string[]) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { env: { ...process.env, ZENAI4_DB_PATH: db, ZENAI4_BACKUP_KEY: KEY }, encoding: "utf8" });
    return { code: r.status, out: r.stdout.trim(), err: r.stderr };
  };
  return { dir, db, cli };
}

async function gateway(db: string) {
  const cp = buildControlPlane({ dbPath: db });
  const server = createSecureGateway(cp).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    get: (path: string, token: string) => fetch(base + path, { headers: { authorization: `Bearer ${token}` } }),
    async close() { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); cp.close(); },
  };
}

test("init creates the first admin once, prints the token only on stdout, and logs it", async () => {
  const { db, cli } = setup();
  const first = cli("init", "--admin-email", "Ops@Acme.test", "--admin-name", "Ops");
  assert.equal(first.code, 0, first.err);
  assert.match(first.out, /^gai\.u\.[^.]+\.[^.\s]+$/, "stdout is exactly the token");
  assert.ok(!first.err.includes(first.out), "token not echoed to stderr");

  const again = cli("init", "--admin-email", "x@acme.test", "--admin-name", "X");
  assert.equal(again.code, 1);
  assert.match(again.err, /already initialised/);

  const gw = await gateway(db);
  try {
    assert.equal((await gw.get("/v1/agents", first.out)).status, 200, "the printed token works on the gateway");
  } finally { await gw.close(); }

  const raw = new Database(db, { readonly: true });
  const dump = JSON.stringify(raw.prepare("SELECT * FROM credentials").all()) + JSON.stringify(raw.prepare("SELECT * FROM audit_events").all());
  raw.close();
  assert.ok(!dump.includes(first.out.split(".").at(-1)!), "secret never stored or logged");
  const cp = buildControlPlane({ dbPath: db });
  const events = cp.audit.query({ stream: "user", limit: 100 }).map((e) => e.action);
  assert.ok(events.includes("cli.init") && events.includes("cli.token.issue"));
  assert.ok(cp.profiles.list().length >= 2, "default profiles seeded");
  cp.close();
});

test("users, tokens and deactivation; usage errors exit 2", async () => {
  const { db, cli } = setup();
  cli("init", "--admin-email", "ops@acme.test", "--admin-name", "Ops");
  assert.equal(cli("user", "add", "--email", "ana@acme.test", "--name", "Ana", "--roles", "auditor").code, 0);
  assert.equal(cli("user", "add", "--email", "bad@acme.test", "--roles", "superuser").code, 2);
  assert.equal(cli("token", "issue", "--email", "nobody@acme.test").code, 1);
  assert.equal(cli("frobnicate").code, 2);

  const tok = cli("token", "issue", "--email", "ana@acme.test", "--ttl-hours", "1");
  assert.equal(tok.code, 0);
  const gw = await gateway(db);
  try {
    assert.equal((await gw.get("/v1/audit/verify", tok.out)).status, 200);
    assert.equal(cli("user", "deactivate", "--email", "ana@acme.test").code, 0);
    assert.equal((await gw.get("/v1/audit/verify", tok.out)).status, 401, "deactivated user's token stops working");
  } finally { await gw.close(); }
  assert.match(cli("user", "list").out, /inactive\s+ana@acme\.test/);
});

test("profile add validates input", () => {
  const { dir, cli } = setup();
  cli("init", "--admin-email", "ops@acme.test", "--admin-name", "Ops");
  const good = join(dir, "p.json"), bad = join(dir, "bad.json");
  writeFileSync(good, JSON.stringify({ id: "finance-ro", name: "Finance read-only", description: "Reads ledgers", allowedTools: ["read_invoice"], allowedDataClasses: ["financial"], allowedModels: ["claude-sonnet-5"], maxAutonomy: "A1", requiresSecurityReview: true }));
  writeFileSync(bad, JSON.stringify({ id: "x", maxAutonomy: "A9" }));
  assert.equal(cli("profile", "add", "--file", good).code, 0);
  assert.equal(cli("profile", "add", "--file", bad).code, 1);
  assert.match(cli("profile", "list").out, /finance-ro/);
});

test("audit verify detects tampering", () => {
  const { db, cli } = setup();
  cli("init", "--admin-email", "ops@acme.test", "--admin-name", "Ops");
  assert.equal(cli("audit", "verify").out, "intact");
  const raw = new Database(db);
  raw.prepare("UPDATE audit_events SET action = 'nothing.to.see' WHERE seq = (SELECT MIN(seq) FROM audit_events)").run();
  raw.close();
  const r = cli("audit", "verify");
  assert.equal(r.code, 1);
  assert.match(r.out, /BROKEN/);
});

test("encrypted backup restores with an intact chain; wrong key or altered file is refused", () => {
  const { dir, cli, db } = setup();
  cli("init", "--admin-email", "ops@acme.test", "--admin-name", "Ops");
  cli("user", "add", "--email", "ana@acme.test", "--roles", "auditor");
  const bak = join(dir, "g.bak");
  assert.equal(cli("backup", "--out", bak).code, 0);
  assert.equal(cli("backup", "--out", bak).code, 1, "never overwrites");
  assert.ok(!readFileSync(bak).includes(Buffer.from("ana@acme.test")), "backup is encrypted");

  const restored = join(dir, "r.db");
  const r = cli("restore", "--in", bak, "--to", restored);
  assert.equal(r.code, 0, r.err);
  const a = new Database(db, { readonly: true }), b = new Database(restored, { readonly: true });
  assert.equal((b.prepare("SELECT COUNT(*) n FROM directory_users").get() as any).n, (a.prepare("SELECT COUNT(*) n FROM directory_users").get() as any).n);
  a.close(); b.close();

  const altered = readFileSync(bak); altered[altered.length - 5] ^= 0xff;
  writeFileSync(join(dir, "alt.bak"), altered);
  const bad = cli("restore", "--in", join(dir, "alt.bak"), "--to", join(dir, "x.db"));
  assert.equal(bad.code, 1);
  assert.match(bad.err, /failed authentication/);

  const wrongKey = spawnSync(process.execPath, [CLI, "restore", "--in", bak, "--to", join(dir, "y.db")], { env: { ...process.env, ZENAI4_BACKUP_KEY: randomBytes(32).toString("base64") }, encoding: "utf8" });
  assert.equal(wrongKey.status, 1);
});

test("old GOVERNAI_* variable names still work after the rename to ZenAi4", () => {
  const dir = mkdtempSync(join(tmpdir(), "zenai4-legacy-"));
  const db = join(dir, "legacy.db");
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith("ZENAI4_")) delete env[k];
  const r = spawnSync(process.execPath, [CLI, "init", "--admin-email", "ops@acme.test", "--admin-name", "Ops"], { env: { ...env, GOVERNAI_DB_PATH: db }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, new RegExp(`Initialised ${db.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
});
