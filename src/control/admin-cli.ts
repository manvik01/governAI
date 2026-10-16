#!/usr/bin/env node
// zenai4-admin: operator CLI for a ZenAi4 deployment.
//
// It talks to the database directly, so whoever can run it (shell access to the
// container or host) is effectively an administrator - protect that access like
// root. Every action it takes is written to the USER audit stream as
// "cli:<os user>", and secrets it creates are printed once and never stored.
//
//   zenai4-admin init --admin-email ops@acme.com --admin-name "Ops Admin"
//   zenai4-admin user add --email ana@acme.com --name "Ana" --roles security_reviewer
//   zenai4-admin user deactivate --email ana@acme.com
//   zenai4-admin user list
//   zenai4-admin token issue --email ana@acme.com [--ttl-hours 8]
//   zenai4-admin profile list | profile add --file profile.json
//   zenai4-admin audit verify | audit export [--out file.jsonl]
//   zenai4-admin backup --out /backups/zenai4.bak      (needs ZENAI4_BACKUP_KEY)
//   zenai4-admin restore --in /backups/zenai4.bak --to /data/restored.db
//
// Reads ZENAI4_DB_PATH (default ./zenai4.db). Exit codes: 0 ok, 1 failure, 2 usage.

import "../config/env-compat.js";
import { parseArgs } from "node:util";
import { userInfo } from "node:os";
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { buildControlPlane, DEFAULT_PROFILES, type ControlPlane } from "./control-plane.js";
import type { Role } from "./identity.js";
import type { AccessProfile } from "./access-profiles.js";

const ROLES: Role[] = ["admin", "security_reviewer", "budget_admin", "auditor", "agent_owner", "ci_registrar"];
const AUTONOMY = ["A0", "A1", "A2", "A3", "A4"];
const MAGIC = Buffer.from("GAIBAK1\n");

const HELP = `zenai4-admin - operator CLI (reads ZENAI4_DB_PATH)

  init --admin-email <e> --admin-name <n> [--ttl-hours 8]   first admin + default profiles (once only)
  user add --email <e> --name <n> --roles <r1,r2>           roles: ${ROLES.join(", ")}
  user deactivate --email <e>                                also revokes the user's tokens
  user list
  token issue --email <e> [--ttl-hours 8]                    prints the token once
  profile list
  profile add --file <profile.json>
  audit verify                                               exit 1 if the chain is broken
  audit export [--out <file.jsonl>]
  backup --out <file>                                        encrypted; needs ZENAI4_BACKUP_KEY
  restore --in <file> --to <new.db>                          decrypts, then verifies integrity

Exit codes: 0 ok, 1 failure, 2 usage error.
`;

class UsageError extends Error {}
class CliError extends Error {}

const operator = () => {
  try { return `cli:${userInfo().username}`; } catch { return "cli:unknown"; }
};

function log(cp: ControlPlane, action: string, outcome: "success" | "denied" | "failure", details: Record<string, unknown>, targetId?: string) {
  cp.audit.append({ stream: "user", actorType: "user", actorId: operator(), action, outcome, targetId, details });
}

function need(v: string | undefined, flag: string): string {
  if (!v || !v.trim()) throw new UsageError(`missing --${flag}`);
  return v.trim();
}

function parseRoles(s: string): Role[] {
  const roles = s.split(",").map((r) => r.trim()).filter(Boolean);
  const bad = roles.filter((r) => !ROLES.includes(r as Role));
  if (!roles.length || bad.length) throw new UsageError(`--roles must be a comma list of: ${ROLES.join(", ")}`);
  return roles as Role[];
}

const hasAdmin = (cp: ControlPlane) =>
  (cp.db.prepare(`SELECT roles FROM directory_users WHERE active = 1`).all() as Array<{ roles: string }>)
    .some((r) => (JSON.parse(r.roles) as string[]).includes("admin"));

function validProfile(p: any): p is AccessProfile {
  return p && typeof p.id === "string" && p.id && typeof p.name === "string" && typeof p.description === "string"
    && Array.isArray(p.allowedTools) && Array.isArray(p.allowedDataClasses) && Array.isArray(p.allowedModels)
    && AUTONOMY.includes(p.maxAutonomy) && typeof p.requiresSecurityReview === "boolean";
}

function backupKey(): Buffer {
  const raw = process.env.ZENAI4_BACKUP_KEY;
  if (!raw) throw new CliError("ZENAI4_BACKUP_KEY is not set (32 random bytes, base64). Generate one with: openssl rand -base64 32");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) throw new CliError("ZENAI4_BACKUP_KEY must decode to exactly 32 bytes");
  return key;
}

async function run(argv: string[]): Promise<number> {
  const [group, sub, ...rest] = argv;
  if (!group || group === "help" || group === "--help") {
    process.stdout.write(HELP);
    return group ? 0 : 2;
  }
  const flagArgs = ["init", "backup", "restore"].includes(group) ? [sub, ...rest].filter((x) => x !== undefined) : rest;
  const { values } = parseArgs({
    args: flagArgs,
    options: {
      "admin-email": { type: "string" }, "admin-name": { type: "string" }, email: { type: "string" }, name: { type: "string" },
      roles: { type: "string" }, "ttl-hours": { type: "string" }, file: { type: "string" }, out: { type: "string" },
      in: { type: "string" }, to: { type: "string" },
    },
    strict: true,
  });

  if (group === "restore") return restore(need(values.in, "in"), need(values.to, "to"));

  const dbPath = process.env.ZENAI4_DB_PATH ?? "./zenai4.db";
  const cp = buildControlPlane({ dbPath, siemPath: process.env.ZENAI4_SIEM_PATH });
  try {
    switch (`${group}${["init", "backup"].includes(group) ? "" : " " + (sub ?? "")}`) {
      case "init": {
        const email = need(values["admin-email"], "admin-email").toLowerCase();
        const name = need(values["admin-name"], "admin-name");
        if (hasAdmin(cp)) {
          log(cp, "cli.init", "denied", { reason: "admin_exists" });
          throw new CliError("already initialised: an admin exists. Use `user add` and `token issue` instead.");
        }
        if (cp.profiles.list().length === 0) for (const p of DEFAULT_PROFILES) cp.profiles.upsert(p);
        cp.directory.upsert({ email, displayName: name, active: true, roles: ["admin"] });
        const tok = cp.credentials.issueUserToken(email, ttlMinutes(values["ttl-hours"]));
        log(cp, "cli.init", "success", { adminEmail: email, profiles: cp.profiles.list().map((p) => p.id) }, email);
        log(cp, "cli.token.issue", "success", { email, keyId: tok.keyId, expiresAt: tok.expiresAt }, email);
        process.stderr.write(`Initialised ${dbPath}. Admin: ${email}\nAdmin token (shown once, expires ${tok.expiresAt}):\n`);
        process.stdout.write(tok.token + "\n");
        return 0;
      }
      case "user add": {
        const email = need(values.email, "email").toLowerCase();
        const roles = parseRoles(need(values.roles, "roles"));
        cp.directory.upsert({ email, displayName: values.name?.trim() || email, active: true, roles });
        log(cp, "cli.user.add", "success", { email, roles }, email);
        process.stderr.write(`User ${email} active with roles: ${roles.join(", ")}\n`);
        return 0;
      }
      case "user deactivate": {
        const email = need(values.email, "email").toLowerCase();
        if (!cp.directory.lookup(email)) throw new CliError(`no such user: ${email}`);
        cp.directory.deactivate(email);
        const revoked = cp.credentials.revokeAll("user", email, "user deactivated");
        log(cp, "cli.user.deactivate", "success", { email, tokensRevoked: revoked }, email);
        process.stderr.write(`User ${email} deactivated; ${revoked} token(s) revoked.\n`);
        return 0;
      }
      case "user list": {
        const rows = cp.db.prepare(`SELECT email, display_name, active, roles FROM directory_users ORDER BY email`).all() as any[];
        for (const r of rows) process.stdout.write(`${r.active ? "active  " : "inactive"}  ${r.email}  [${JSON.parse(r.roles).join(", ")}]  ${r.display_name}\n`);
        return 0;
      }
      case "token issue": {
        const email = need(values.email, "email").toLowerCase();
        const user = cp.directory.lookup(email);
        if (!user || !user.active) {
          log(cp, "cli.token.issue", "denied", { email, reason: "user_inactive_or_unknown" }, email);
          throw new CliError(`${email} is not an active user`);
        }
        const tok = cp.credentials.issueUserToken(email, ttlMinutes(values["ttl-hours"]));
        log(cp, "cli.token.issue", "success", { email, keyId: tok.keyId, expiresAt: tok.expiresAt }, email);
        process.stderr.write(`Token for ${email} (shown once, expires ${tok.expiresAt}):\n`);
        process.stdout.write(tok.token + "\n");
        return 0;
      }
      case "profile list": {
        for (const p of cp.profiles.list()) process.stdout.write(`${p.id}  review=${p.requiresSecurityReview}  maxAutonomy=${p.maxAutonomy}  tools=${p.allowedTools.join(",")}  models=${p.allowedModels.join(",")}\n`);
        return 0;
      }
      case "profile add": {
        const file = need(values.file, "file");
        let p: unknown;
        try { p = JSON.parse(readFileSync(file, "utf8")); } catch { throw new CliError(`cannot read JSON from ${file}`); }
        if (!validProfile(p)) throw new CliError("invalid profile: needs id, name, description, allowedTools[], allowedDataClasses[], allowedModels[], maxAutonomy (A0-A4), requiresSecurityReview (boolean)");
        cp.profiles.upsert(p);
        log(cp, "cli.profile.upsert", "success", { profile: p }, p.id);
        process.stderr.write(`Profile ${p.id} saved.\n`);
        return 0;
      }
      case "audit verify": {
        const broken = cp.audit.verifyChain();
        const ledgerBroken = cp.ledger.verifyChain();
        log(cp, "cli.audit.verify", broken === -1 && ledgerBroken === -1 ? "success" : "failure", { auditFirstBroken: broken, ledgerFirstBroken: ledgerBroken });
        if (broken === -1 && ledgerBroken === -1) { process.stdout.write("intact\n"); return 0; }
        process.stdout.write(`BROKEN audit=${broken === -1 ? "ok" : `seq ${broken}`} ledger=${ledgerBroken === -1 ? "ok" : `index ${ledgerBroken}`}\n`);
        return 1;
      }
      case "audit export": {
        const data = cp.audit.exportJsonl({ limit: Number.MAX_SAFE_INTEGER });
        log(cp, "cli.audit.export", "success", { out: values.out ?? "stdout" });
        if (values.out) writeFileSync(values.out, data, { mode: 0o600 }); else process.stdout.write(data);
        return 0;
      }
      case "backup": {
        const out = need(values.out, "out");
        const key = backupKey();
        if (existsSync(out)) throw new CliError(`${out} already exists; refusing to overwrite`);
        const tmp = join(mkdtempSync(join(tmpdir(), "zenai4-bak-")), "snap.db");
        await cp.db.backup(tmp); // online, consistent snapshot
        const plain = readFileSync(tmp);
        unlinkSync(tmp);
        const iv = randomBytes(12);
        const c = createCipheriv("aes-256-gcm", key, iv);
        const body = Buffer.concat([c.update(plain), c.final()]);
        writeFileSync(out, Buffer.concat([MAGIC, iv, c.getAuthTag(), body]), { mode: 0o600 });
        log(cp, "cli.backup", "success", { out, bytes: plain.length });
        process.stderr.write(`Encrypted backup written to ${out} (${plain.length} bytes before encryption).\n`);
        return 0;
      }
      default:
        throw new UsageError(`unknown command: ${group} ${sub ?? ""}`.trim());
    }
  } finally {
    cp.close();
  }
}

function ttlMinutes(h: string | undefined): number {
  if (h === undefined) return 8 * 60;
  const n = Number(h);
  if (!Number.isFinite(n) || n <= 0 || n > 24 * 30) throw new UsageError("--ttl-hours must be between 0 and 720");
  return Math.round(n * 60);
}

function restore(input: string, to: string): number {
  const key = backupKey();
  if (existsSync(to)) throw new CliError(`${to} already exists; restore into a new path, then point ZENAI4_DB_PATH at it`);
  const buf = readFileSync(input);
  if (!buf.subarray(0, MAGIC.length).equals(MAGIC)) throw new CliError("not a ZenAi4 backup file");
  const iv = buf.subarray(MAGIC.length, MAGIC.length + 12);
  const tag = buf.subarray(MAGIC.length + 12, MAGIC.length + 28);
  const d = createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  let plain: Buffer;
  try { plain = Buffer.concat([d.update(buf.subarray(MAGIC.length + 28)), d.final()]); }
  catch { throw new CliError("backup failed authentication: wrong key or the file was altered"); }
  writeFileSync(to, plain, { mode: 0o600 });
  const cp = buildControlPlane({ dbPath: to });
  try {
    const broken = cp.audit.verifyChain();
    const ledgerBroken = cp.ledger.verifyChain();
    if (broken !== -1 || ledgerBroken !== -1) {
      cp.close();
      unlinkSync(to);
      throw new CliError(`restored database failed integrity check (audit seq ${broken}, ledger index ${ledgerBroken}); removed`);
    }
    log(cp, "cli.restore", "success", { from: input });
    process.stderr.write(`Restored to ${to}; audit chain and ledger intact.\n`);
    return 0;
  } finally {
    try { cp.close(); } catch { /* already closed */ }
  }
}

if (import.meta.url === `file://${process.argv[1]}` || /(zenai4|governai)-admin$/.test(process.argv[1] ?? "")) {
  run(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      if (err instanceof UsageError || (err as any)?.code?.startsWith?.("ERR_PARSE_ARGS")) { process.stderr.write(`usage error: ${err.message}\nRun \`zenai4-admin help\`.\n`); process.exit(2); }
      if (err instanceof CliError) { process.stderr.write(`error: ${err.message}\n`); process.exit(1); }
      process.stderr.write(`error: ${(err as Error)?.message ?? "unexpected failure"}\n`);
      if (process.env.ZENAI4_DEBUG === "1") console.error(err);
      process.exit(1);
    },
  );
}
