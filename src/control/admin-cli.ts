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
// Phase 1 (registration and discovery) - commands that act for a person take
// --as <email>: that directory user's roles and separation-of-duties rules
// apply exactly as on the HTTP API, and the audit entry records both the
// person and the OS operator.
//   zenai4-admin apply -f agent.yaml --as owner@acme.com
//       (or, with ZENAI4_URL + ZENAI4_TOKEN set, POSTs to the gateway - CI mode)
//   zenai4-admin agent register --as <e> --name .. --purpose .. --owner .. --sub-owner .. --profile ..
//       --business-unit .. --platform .. --model-provider .. --model-version .. --autonomy A1
//       --tools name:reversible|irreversible:dc1+dc2,... [--data-classes ..] [--expires-at 2027-01-01] [--draft]
//   zenai4-admin agent list | show --id | submit --id --as | transition --id --to --as | retire --id --as
//   zenai4-admin agent risk-tier --id --tier high [--reason ..] --as | recertify --id --as | expiring [--days 14]
//   zenai4-admin discovery list [--status new] [--triage] | claim --id --as | assign-owner --id --owner --as
//   zenai4-admin discovery ignore --id --reason --as | disable --id [--reason] --as
//   zenai4-admin discovery import-egress --file egress.csv --as | run [--connector id] | status
//   zenai4-admin sweep                                    run the expiry sweep now
//
// Phase 1.1 (telemetry and reconciliation):
//   zenai4-admin source add --name otel-vm1 [--kind otlp|steps] [--capture none|metadata|redacted] --as <e>
//   zenai4-admin source revoke --id <id> --reason <r> --as <e> | source list
//   zenai4-admin telemetry alerts [--status open] [--kind drift] | ack --id <id> --reason <r> --as <e>
//   zenai4-admin telemetry reconcile | retention | dormant | violations [--agent id] | verify
//   zenai4-admin agent activity --id <id> [--days 90]
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
import type { RegistrationRequest } from "./registration.js";
import { connectorsFromEnv } from "../discovery/connectors.js";
import { DISCOVERY_STATUSES, type DiscoveryStatus } from "../discovery/discovery.js";
import type { LifecycleState, RiskTier, ToolGrant } from "../types.js";
import { hasRole } from "./identity.js";
import { CAPTURE_MODES, type CaptureMode } from "../telemetry/config.js";
import type { AlertKind } from "../telemetry/store.js";

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

Registration and discovery (--as <email> = the person acting; their roles apply):
  apply -f <agent.yaml> --as <e>                             create / update / no-op by metadata.id
        (remote: set ZENAI4_URL and ZENAI4_TOKEN; --as is then the token's user)
  agent register --as <e> --name <n> --purpose <p> --owner <e> --sub-owner <e> --profile <id>
        --business-unit <bu> --platform <p> --model-provider <p> --model-version <m> --autonomy <A0-A4>
        --tools <name:reversible|irreversible[:dc1+dc2],...> [--data-classes <dc,..>] [--models <m,..>]
        [--expires-at <date>] [--mode enforcement|posture] [--draft]
  agent list | agent show --id <id> | agent expiring [--days 14]
  agent submit --id <id> --as <e>                            draft -> pending approval
  agent transition --id <id> --to <state> [--reason <r>] --as <e>
  agent retire --id <id> [--reason <r>] --as <e>             terminal; revokes credentials
  agent risk-tier --id <id> --tier <low|medium|high|critical> [--reason <r>] --as <e>
  agent recertify --id <id> --as <e>                         extends expiry by 90 days
  discovery list [--status <s>] [--triage] [--source <s>]
  discovery claim --id <id> --as <e>                         creates a draft owned by <e>
  discovery assign-owner --id <id> --owner <e> --as <e>      security/admin only
  discovery ignore --id <id> --reason <r> --as <e>
  discovery disable --id <id> [--reason <r>] --as <e>        suspends a linked agent, revokes credentials
  discovery import-egress --file <egress.csv> --as <e>
  discovery run [--connector <id>]                           runs connectors from ZENAI4_DISCOVERY_CONNECTORS now
  discovery status
  sweep                                                      expiry sweep now

Telemetry intake and reconciliation (phase 1.1):
  source add --name <n> [--kind otlp|steps] [--capture none|metadata|redacted] --as <e>
                                                             security/admin; prints the source token once
  source revoke --id <id> --reason <r> --as <e>              the token stops working at once
  source list
  telemetry alerts [--status open|acknowledged] [--kind <k>] [--agent <id>]
  telemetry ack --id <alert> --reason <r> --as <e>           security/admin; reason required
  telemetry reconcile                                        run reconciliation now
  telemetry retention                                        null payloads past retention now
  telemetry dormant                                          active agents with no recent activity
  telemetry violations [--agent <id>] | telemetry verify     violation log; verify its hash chain
  agent activity --id <id> [--days 90]                       what the agent actually did

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
  const flagArgs = ["init", "backup", "restore", "apply", "sweep"].includes(group) ? [sub, ...rest].filter((x) => x !== undefined) : rest;
  const { values } = parseArgs({
    args: flagArgs,
    options: {
      "admin-email": { type: "string" }, "admin-name": { type: "string" }, email: { type: "string" }, name: { type: "string" },
      roles: { type: "string" }, "ttl-hours": { type: "string" }, file: { type: "string" }, out: { type: "string" },
      in: { type: "string" }, to: { type: "string" },
      f: { type: "string", short: "f" }, as: { type: "string" }, id: { type: "string" }, purpose: { type: "string" },
      owner: { type: "string" }, "sub-owner": { type: "string" }, profile: { type: "string" }, "business-unit": { type: "string" },
      platform: { type: "string" }, "model-provider": { type: "string" }, "model-version": { type: "string" }, models: { type: "string" },
      autonomy: { type: "string" }, tools: { type: "string" }, "data-classes": { type: "string" }, "expires-at": { type: "string" },
      mode: { type: "string" }, draft: { type: "boolean" }, tier: { type: "string" }, reason: { type: "string" }, days: { type: "string" },
      status: { type: "string" }, triage: { type: "boolean" }, source: { type: "string" }, connector: { type: "string" },
      "agent-limit-micro": { type: "string" }, "task-limit-micro": { type: "string" },
      kind: { type: "string" }, capture: { type: "string" }, agent: { type: "string" },
    },
    strict: true,
  });

  if (group === "restore") return restore(need(values.in, "in"), need(values.to, "to"));
  if (group === "apply" && process.env.ZENAI4_URL) return applyRemote(need(values.f ?? values.file, "f"));

  const dbPath = process.env.ZENAI4_DB_PATH ?? "./zenai4.db";
  const cp = buildControlPlane({ dbPath, siemPath: process.env.ZENAI4_SIEM_PATH });
  try {
    switch (`${group}${["init", "backup", "apply", "sweep"].includes(group) ? "" : " " + (sub ?? "")}`) {
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
      case "apply": {
        const file = need(values.f ?? values.file, "f");
        const as = actingAs(cp, values.as);
        let text: string;
        try { text = readFileSync(file, "utf8"); } catch { throw new CliError(`cannot read ${file}`); }
        const out = cp.manifests.applyText(text, as, { requestId: operator() });
        log(cp, "cli.apply", out.ok ? "success" : "denied", { as, file, result: out.ok ? out.action : undefined, violations: out.ok ? undefined : out.violations }, out.ok ? out.agent.id : undefined);
        if (!out.ok) return fail(out.violations);
        process.stdout.write(`${out.action} ${out.agent.id} state=${out.agent.lifecycleState} tier=${out.agent.riskTier}${out.reReview ? " (re-review required)" : ""}${out.missing?.length ? ` missing=${out.missing.join(",")}` : ""}\n`);
        return 0;
      }
      case "agent register": {
        const as = actingAs(cp, values.as);
        const req = registrationFromFlags(values);
        if (values.draft) {
          const d = cp.registration.createDraft({ ...req, ownerEmail: req.ownerEmail ?? as }, as, { requestId: operator() });
          log(cp, "cli.agent.register", d.ok ? "success" : "denied", { as, draft: true, violations: d.ok ? undefined : d.violations }, d.ok ? d.agent.id : undefined);
          if (!d.ok) return fail(d.violations);
          process.stdout.write(`${d.agent.id} draft\n`);
          return 0;
        }
        const out = cp.registration.submit(req as RegistrationRequest, as, { requestId: operator() });
        log(cp, "cli.agent.register", out.ok ? "success" : "denied", { as, violations: out.ok ? undefined : out.violations }, out.ok ? out.agent.id : undefined);
        if (!out.ok) return fail(out.violations);
        process.stderr.write(`Registered ${out.agent.id}: ${out.agent.lifecycleState}, risk ${out.agent.riskTier}, expires ${out.agent.expiresAt}\n`);
        if (out.credential) { process.stderr.write(`Agent credential (shown once, expires ${out.credential.expiresAt}):\n`); process.stdout.write(out.credential.token + "\n"); }
        else process.stdout.write(`${out.agent.id}\n`);
        return 0;
      }
      case "agent list": {
        for (const a of cp.registry.list()) process.stdout.write(`${a.id}  ${a.lifecycleState.padEnd(16)} ${a.riskTier.padEnd(8)} expires=${a.expiresAt.slice(0, 10)}  ${a.name}  owner=${a.ownerEmail}${a.manifestId ? `  manifest=${a.manifestId}` : ""}\n`);
        return 0;
      }
      case "agent show": {
        const a = cp.registry.get(need(values.id, "id"));
        if (!a) throw new CliError("no such agent");
        process.stdout.write(JSON.stringify({ ...a, tools: cp.registry.grantsFor(a.id).map(({ agentId: _x, ...t }) => t) }, null, 2) + "\n");
        return 0;
      }
      case "agent expiring": {
        const days = values.days ? Number(values.days) : 14;
        if (!Number.isFinite(days) || days <= 0) throw new UsageError("--days must be a positive number");
        for (const a of cp.registration.expiringWithin(days)) process.stdout.write(`${a.id}  expires=${a.expiresAt}  ${a.name}  owner=${a.ownerEmail}\n`);
        return 0;
      }
      case "agent submit": return result(cp, "cli.agent.submit", values.as, (as) => cp.registration.submitDraft(need(values.id, "id"), as, { requestId: operator() }), (r) => `${r.agent.id} ${r.agent.lifecycleState}`, true);
      case "agent transition": {
        const to = need(values.to, "to") as LifecycleState;
        if (!["draft", "pending_approval", "active", "suspended", "rejected", "retired"].includes(to)) throw new UsageError("--to must be a lifecycle state");
        return result(cp, "cli.agent.transition", values.as, (as) => cp.registration.transition(need(values.id, "id"), to, as, values.reason, { requestId: operator() }), (r) => `${r.agent.id} ${r.agent.lifecycleState}`, true);
      }
      case "agent retire": return result(cp, "cli.agent.retire", values.as, (as) => cp.registration.retire(need(values.id, "id"), as, values.reason ?? "retired via CLI", { requestId: operator() }), (r) => `${r.agent.id} ${r.agent.lifecycleState}`);
      case "agent risk-tier": {
        const tier = need(values.tier, "tier") as RiskTier;
        return result(cp, "cli.agent.risk_tier", values.as, (as) => cp.registration.setRiskTier(need(values.id, "id"), tier, as, values.reason, { requestId: operator() }), (r) => `${r.agent.id} tier=${r.agent.riskTier} computed=${r.agent.computedRiskTier} state=${r.agent.lifecycleState}`);
      }
      case "agent recertify": return result(cp, "cli.agent.recertify", values.as, (as) => cp.registration.recertify(need(values.id, "id"), as, { requestId: operator() }), (r) => `${r.agent.id} ${r.agent.lifecycleState} expires=${r.agent.expiresAt}`, true);
      case "discovery list": {
        const status = values.status as DiscoveryStatus | undefined;
        if (status && !DISCOVERY_STATUSES.includes(status)) throw new UsageError(`--status must be one of ${DISCOVERY_STATUSES.join(", ")}`);
        for (const d of cp.discovery.list({ status, source: values.source, queue: values.triage ? "triage" : undefined })) {
          process.stdout.write(`${d.id}  ${d.status.padEnd(10)} ${d.source.padEnd(17)} x${d.count}  last=${d.lastSeen}  ${d.displayName}${d.ownerEmail ? `  owner=${d.ownerEmail}` : ""}${d.agentId ? `  agent=${d.agentId}` : ""}\n`);
        }
        return 0;
      }
      case "discovery claim": return result(cp, "cli.discovery.claim", values.as, (as) => cp.discovery.claim(need(values.id, "id"), as, { requestId: operator() }), (r) => `${r.item.id} claimed -> draft ${r.agent.id} owner=${r.agent.ownerEmail}`);
      case "discovery assign-owner": return result(cp, "cli.discovery.assign_owner", values.as, (as) => cp.discovery.assignOwner(need(values.id, "id"), need(values.owner, "owner"), as, { requestId: operator() }), (r) => `${r.item.id} claimed -> draft ${r.agent.id} owner=${r.agent.ownerEmail}`);
      case "discovery ignore": return result(cp, "cli.discovery.ignore", values.as, (as) => cp.discovery.ignore(need(values.id, "id"), as, values.reason, { requestId: operator() }), (r) => `${r.item.id} ignored`);
      case "discovery disable": return result(cp, "cli.discovery.disable", values.as, (as) => cp.discovery.disable(need(values.id, "id"), as, values.reason, { requestId: operator() }), (r) => `${r.item.id} disabled${r.agent ? ` agent ${r.agent.id} ${r.agent.lifecycleState}` : ""}${r.manualActionRequired ? `\nmanual action: ${r.manualActionRequired}` : ""}`);
      case "discovery import-egress": {
        const file = need(values.file, "file");
        let csv: string;
        try { csv = readFileSync(file, "utf8"); } catch { throw new CliError(`cannot read ${file}`); }
        return result(cp, "cli.discovery.import_egress", values.as, (as) => cp.discovery.importEgressCsv(csv, as, { requestId: operator() }), (r) => `rows=${r.rows} matched=${r.matched} skipped=${r.skipped} new=${r.created}${r.errors.length ? `\n${r.errors.join("\n")}` : ""}`);
      }
      case "discovery run": {
        for (const c of connectorsFromEnv()) cp.scheduler.addConnector(c, cp.discovery);
        const ids = cp.scheduler.jobIds().filter((j) => j.startsWith("connector:") && (!values.connector || j === `connector:${values.connector}`));
        if (!ids.length) throw new CliError("no connectors configured (set ZENAI4_DISCOVERY_CONNECTORS)");
        log(cp, "cli.discovery.run", "success", { jobs: ids });
        let failed = false;
        for (const id of ids) {
          const r = await cp.scheduler.runOnce(id);
          failed ||= r.status === "error";
          process.stdout.write(`${id}  ${r.status}  items=${r.items} new=${r.created}${r.error ? `  error=${r.error}` : ""}\n`);
        }
        return failed ? 1 : 0;
      }
      case "discovery status": {
        for (const j of cp.scheduler.status()) process.stdout.write(`${j.jobId}  every=${j.intervalMs / 3_600_000}h  last=${j.lastRun ? `${j.lastRun.status} ${j.lastRun.finishedAt ?? ""} items=${j.lastRun.items}${j.lastRun.error ? ` error=${j.lastRun.error}` : ""}` : "never"}\n`);
        return 0;
      }
      case "sweep": {
        const r = await cp.scheduler.runOnce("expiry-sweep");
        log(cp, "cli.sweep", r.status === "ok" ? "success" : "failure", { suspended: r.items });
        process.stdout.write(`expired agents suspended: ${r.items}\n`);
        return r.status === "ok" ? 0 : 1;
      }
      case "source add": {
        const as = actingAs(cp, values.as);
        const name = need(values.name, "name");
        const kind = values.kind ?? "otlp";
        if (!["otlp", "steps", "litellm", "file", "syslog"].includes(kind)) throw new UsageError("--kind must be otlp, steps, litellm, file or syslog");
        const capture = (values.capture ?? "metadata") as CaptureMode;
        if (!CAPTURE_MODES.includes(capture)) throw new UsageError(`--capture must be one of ${CAPTURE_MODES.join(", ")}`);
        if (!hasRole(cp.directory.lookup(as), "security_reviewer", "admin")) {
          log(cp, "cli.source.add", "denied", { as, name, violations: ["only a security reviewer or admin may create an intake source"] });
          return fail(["only a security reviewer or admin may create an intake source"]);
        }
        const { source, token } = cp.telemetry.createSource(name, kind, capture, as);
        cp.audit.append({ stream: "user", actorType: "user", actorId: as, action: "intake.source.create", targetType: "intake_source", targetId: source.id, outcome: "success", requestId: operator(), details: { name, kind, captureMode: capture } });
        log(cp, "cli.source.add", "success", { as, sourceId: source.id, name, kind, captureMode: capture }, source.id);
        process.stderr.write(`Intake source ${source.id} (${name}, ${kind}, capture=${capture}). Token (shown once):\n`);
        process.stdout.write(token + "\n");
        return 0;
      }
      case "source revoke": {
        const as = actingAs(cp, values.as);
        const id = need(values.id, "id");
        const reason = need(values.reason, "reason");
        const v: string[] = [];
        const src = cp.telemetry.getSource(id);
        if (!hasRole(cp.directory.lookup(as), "security_reviewer", "admin")) v.push("only a security reviewer or admin may revoke an intake source");
        if (!src) v.push(`unknown source ${id}`);
        else if (src.revokedAt) v.push("source is already revoked");
        if (v.length) { log(cp, "cli.source.revoke", "denied", { as, violations: v }, id); return fail(v); }
        cp.telemetry.revokeSource(id, as, reason);
        cp.audit.append({ stream: "user", actorType: "user", actorId: as, action: "intake.source.revoke", targetType: "intake_source", targetId: id, outcome: "success", requestId: operator(), details: { reason } });
        log(cp, "cli.source.revoke", "success", { as, reason }, id);
        process.stderr.write(`Intake source ${id} revoked.\n`);
        return 0;
      }
      case "source list": {
        for (const x of cp.telemetry.listSources()) process.stdout.write(`${x.id}  ${x.enabled ? "enabled " : "revoked "} ${x.kind.padEnd(7)} capture=${x.captureMode.padEnd(8)} last=${x.lastSeenAt ?? "never"}  ${x.name}\n`);
        return 0;
      }
      case "telemetry alerts": {
        const status = values.status === "open" || values.status === "acknowledged" ? values.status : values.status ? (() => { throw new UsageError("--status must be open or acknowledged"); })() : undefined;
        for (const a of cp.telemetry.listAlerts({ status, kind: values.kind as AlertKind | undefined, agentId: values.agent })) {
          process.stdout.write(`${a.id}  ${a.status.padEnd(12)} ${a.severity.padEnd(6)} ${a.kind.padEnd(19)} x${a.count}  last=${a.lastSeen}${a.agentId ? `  agent=${a.agentId}` : ""}  ${JSON.stringify(a.details).slice(0, 160)}\n`);
        }
        return 0;
      }
      case "telemetry ack": {
        const as = actingAs(cp, values.as);
        const id = need(values.id, "id");
        const reason = need(values.reason, "reason");
        const a = cp.telemetry.getAlert(id);
        const v: string[] = [];
        if (!hasRole(cp.directory.lookup(as), "security_reviewer", "admin")) v.push("only a security reviewer or admin may acknowledge an alert");
        if (!a) v.push(`unknown alert ${id}`);
        else if (a.status !== "open") v.push(`alert is already ${a.status}`);
        if (v.length) { cp.audit.append({ stream: "user", actorType: "user", actorId: as, action: "telemetry.alert.ack", targetType: "telemetry_alert", targetId: id, outcome: "denied", requestId: operator(), details: { violations: v } }); return fail(v); }
        cp.telemetry.ackAlert(id, as, reason);
        cp.audit.append({ stream: "user", actorType: "user", actorId: as, action: "telemetry.alert.ack", targetType: "telemetry_alert", targetId: id, outcome: "success", requestId: operator(), details: { kind: a!.kind, agentId: a!.agentId, reason } });
        log(cp, "cli.telemetry.ack", "success", { as, reason }, id);
        process.stderr.write(`Alert ${id} acknowledged.\n`);
        return 0;
      }
      case "telemetry reconcile": {
        const r = await cp.scheduler.runOnce("telemetry-reconcile");
        log(cp, "cli.telemetry.reconcile", r.status === "ok" ? "success" : "failure", { runId: r.id, items: r.items });
        process.stdout.write(`reconcile ${r.status} steps=${r.items} new=${r.created}${r.error ? ` error=${r.error}` : ""}\n`);
        return r.status === "ok" ? 0 : 1;
      }
      case "telemetry retention": {
        const r = await cp.scheduler.runOnce("telemetry-retention");
        log(cp, "cli.telemetry.retention", r.status === "ok" ? "success" : "failure", { purged: r.items });
        process.stdout.write(`payloads purged: ${r.items}\n`);
        return r.status === "ok" ? 0 : 1;
      }
      case "telemetry dormant": {
        for (const d of cp.reconcile.dormantAgents()) process.stdout.write(`${d.agent.id}  idle=${d.idleDays}d  last=${d.lastSeen ?? "never"}  ${d.agent.name}  owner=${d.agent.ownerEmail}\n`);
        return 0;
      }
      case "telemetry violations": {
        for (const x of cp.telemetry.listViolations({ agentId: values.agent })) process.stdout.write(`#${x.seq}  ${x.ts}  ${x.decision.padEnd(17)} ${x.policyId}${x.policyVersion !== undefined ? ` v${x.policyVersion}` : ""}${x.rule ? ` rule=${x.rule}` : ""}  agent=${x.agentId ?? x.observedAgentKey ?? "?"}  ${x.blockedAction ?? ""}\n`);
        return 0;
      }
      case "telemetry verify": {
        const broken = cp.telemetry.verifyViolationChain();
        log(cp, "cli.telemetry.verify", broken === -1 ? "success" : "failure", { firstBroken: broken });
        process.stdout.write(broken === -1 ? "intact\n" : `BROKEN at violation seq ${broken}\n`);
        return broken === -1 ? 0 : 1;
      }
      case "agent activity": {
        const days = values.days ? Number(values.days) : 90;
        if (!Number.isFinite(days) || days <= 0) throw new UsageError("--days must be a positive number");
        const s = cp.reconcile.activitySummary(need(values.id, "id"), days);
        if (!s) throw new CliError("no such agent");
        process.stdout.write(JSON.stringify(s, null, 2) + "\n");
        return 0;
      }
      default:
        throw new UsageError(`unknown command: ${group} ${sub ?? ""}`.trim());
    }
  } finally {
    cp.close();
  }
}

/** The person a CLI action is performed as: must be an active directory user. */
function actingAs(cp: ControlPlane, as: string | undefined): string {
  const email = need(as, "as").toLowerCase();
  const u = cp.directory.lookup(email);
  if (!u?.active) throw new CliError(`--as ${email} is not an active user in the directory`);
  return email;
}

function fail(violations: string[]): number {
  process.stderr.write(`refused:\n${violations.map((v) => `  - ${v}`).join("\n")}\n`);
  return 1;
}

/** Runs a service call as --as, logs the CLI action, prints the outcome. */
function result<T extends { ok: boolean }>(
  cp: ControlPlane, action: string, asFlag: string | undefined, fn: (as: string) => T,
  render: (r: Extract<T, { ok: true }>) => string, maybeCredential = false,
): number {
  const as = actingAs(cp, asFlag);
  const r = fn(as) as any;
  log(cp, action, r.ok ? "success" : "denied", { as, violations: r.ok ? undefined : r.violations }, r.agent?.id ?? r.item?.id);
  if (!r.ok) return fail(r.violations);
  process.stderr.write(render(r) + "\n");
  if (maybeCredential && r.credential) { process.stderr.write(`Agent credential (shown once, expires ${r.credential.expiresAt}):\n`); process.stdout.write(r.credential.token + "\n"); }
  return 0;
}

const list = (s: string | undefined) => (s ?? "").split(",").map((x) => x.trim()).filter(Boolean);

/** --tools issue_refund:irreversible:financial+customer_pii,read_invoice:reversible
 * Tools without their own data classes get --data-classes. */
export function parseTools(spec: string | undefined, defaultClasses: string[]): Omit<ToolGrant, "agentId">[] {
  return list(spec).map((t) => {
    const [toolName, rev = "reversible", dcs] = t.split(":");
    if (!toolName || !["reversible", "irreversible"].includes(rev)) throw new UsageError(`bad --tools entry "${t}": use name:reversible|irreversible[:dc1+dc2]`);
    return { toolName, reversible: rev === "reversible", dataClasses: dcs ? dcs.split("+").filter(Boolean) : defaultClasses };
  });
}

function registrationFromFlags(v: Record<string, any>): Partial<RegistrationRequest> {
  const micro = (s: string | undefined, flag: string) => {
    if (s === undefined) return undefined;
    const n = Number(s);
    if (!Number.isInteger(n) || n < 0) throw new UsageError(`--${flag} must be a non-negative integer (micro-USD)`);
    return n;
  };
  if (v.autonomy && !AUTONOMY.includes(v.autonomy)) throw new UsageError("--autonomy must be A0-A4");
  if (v.mode && !["enforcement", "posture"].includes(v.mode)) throw new UsageError("--mode must be enforcement or posture");
  const models = list(v.models);
  return {
    name: v.name, purpose: v.purpose, ownerEmail: v.owner?.toLowerCase(), subOwnerEmail: v["sub-owner"]?.toLowerCase(),
    accessProfileId: v.profile, businessUnit: v["business-unit"], platform: v.platform,
    modelProvider: v["model-provider"], modelVersion: v["model-version"], permittedModels: models.length ? models : undefined,
    autonomyDefault: v.autonomy, mode: v.mode ?? "enforcement",
    tools: parseTools(v.tools, list(v["data-classes"])),
    budgetPolicy: { agentLimitMicro: micro(v["agent-limit-micro"], "agent-limit-micro"), defaultTaskLimitMicro: micro(v["task-limit-micro"], "task-limit-micro") },
    expiresAt: v["expires-at"],
  };
}

/** CI mode: POST the manifest to the gateway. The token is read from the
 * environment, sent only in the Authorization header, and never printed. */
async function applyRemote(file: string): Promise<number> {
  const base = process.env.ZENAI4_URL!.replace(/\/+$/, "");
  const token = process.env.ZENAI4_TOKEN;
  if (!token) throw new CliError("ZENAI4_URL is set but ZENAI4_TOKEN is not");
  if (!/^https:\/\//.test(base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(base)) throw new CliError("ZENAI4_URL must be https:// (http only for localhost)");
  let text: string;
  try { text = readFileSync(file, "utf8"); } catch { throw new CliError(`cannot read ${file}`); }
  const res = await fetch(`${base}/v1/agents/apply`, { method: "POST", headers: { "content-type": "application/yaml", authorization: `Bearer ${token}` }, body: text });
  let body: any;
  try { body = await res.json(); } catch { body = {}; }
  if (!res.ok) {
    process.stderr.write(`apply refused (HTTP ${res.status}):\n${(body.violations ?? [body.error ?? "unknown error"]).map((v: string) => `  - ${v}`).join("\n")}\n`);
    return 1;
  }
  process.stdout.write(`${body.action} ${body.agentId} state=${body.lifecycleState} tier=${body.riskTier}${body.reReview ? " (re-review required)" : ""}${body.missing?.length ? ` missing=${body.missing.join(",")}` : ""}\n`);
  return 0;
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
