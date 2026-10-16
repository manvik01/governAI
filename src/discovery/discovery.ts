// Discovery: every agent the control plane can SEE, registered or not.
//
// Sightings arrive from four directions and all land in one table,
// discovered_agents, deduplicated by a fingerprint:
//   - the gateway: calls with unknown, revoked, expired or malformed
//     credentials ("possible unregistered agent");
//   - network egress logs a customer imports (CSV), filtered to known LLM
//     provider domains ("something is calling a provider directly");
//   - read-only discovery connectors (Entra ID, Okta, Copilot Studio,
//     Gemini Enterprise, GitHub) run by the scheduler;
//   - (later) observed agents from log intake.
//
// Secrets: a fingerprint is built ONLY from non-secret attributes (source
// address, user agent, the public credential key-id prefix, a connector's
// external id). Every attribute is scrubbed of anything shaped like a key
// or token before it is written, and the presented credential itself is
// never passed in. For leaked API keys the connector supplies provider,
// repo, path, line and a 4-hex SHA-256 prefix - never the key.
//
// Repeated sightings update count/last_seen on the existing row; they are
// not audited individually (that would flood the log); the first sighting
// and every status change are.
//
// Triage (the "shadow agent queue"): status new + no owner + no linked
// agent. Transitions:
//   new      -> claimed     claim (an active agent_owner; creates a Draft agent
//                           prefilled from the discovery, owned by the claimer)
//   new      -> claimed     assign-owner (security/admin names an agent_owner;
//                           the Draft is owned by that person)
//   claimed  -> registered  automatic, when the Draft is submitted
//   new|claimed -> ignored  security/admin, with a reason (false positive)
//   any      -> disabled    security/admin; a linked agent is suspended (or
//                           retired if never approved) and its credentials revoked
// Illegal transitions are refused with a reason and audited.

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
import type { AuditLog } from "../control/audit-log.js";
import { hasRole, type IdentityDirectory } from "../control/identity.js";
import type { Ctx, RegistrationService } from "../control/registration.js";
import { scrubValue, scrubSecrets } from "../control/secret-patterns.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { Agent } from "../types.js";

export type DiscoveryStatus = "new" | "claimed" | "registered" | "ignored" | "disabled";
export const DISCOVERY_STATUSES: DiscoveryStatus[] = ["new", "claimed", "registered", "ignored", "disabled"];

export type DiscoverySource =
  | "gateway" | "egress_import" | "entra_id" | "okta" | "copilot_studio" | "gemini_enterprise" | "github";

export interface DiscoveredAgent {
  id: string;
  fingerprint: string;
  source: DiscoverySource;
  kind: string;
  displayName: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
  status: DiscoveryStatus;
  ownerEmail?: string;
  agentId?: string;
  attributes: Record<string, unknown>;
  statusBy?: string;
  statusReason?: string;
  statusAt?: string;
}

export interface Sighting {
  source: DiscoverySource;
  kind: string;
  /** Non-secret identity of the thing seen; hashed into the fingerprint. */
  identity: string[];
  displayName: string;
  attributes?: Record<string, unknown>;
  /** Defaults to 1. Egress rows carry their own count. */
  count?: number;
  firstSeen?: string;
  lastSeen?: string;
  /** Registered agent this sighting is already known to belong to. */
  agentId?: string;
}

export type DiscoveryResult<T = {}> = ({ ok: true } & T) | { ok: false; violations: string[]; notFound?: boolean };

const TRANSITIONS: Record<DiscoveryStatus, DiscoveryStatus[]> = {
  new: ["claimed", "ignored", "disabled"],
  claimed: ["registered", "ignored", "disabled"],
  registered: ["disabled"],
  ignored: ["new", "disabled"],
  disabled: [],
};

/** Domains whose traffic means "an LLM provider is being called". */
export const LLM_PROVIDER_DOMAINS: Array<[RegExp, string]> = [
  [/(^|\.)api\.openai\.com$/, "openai"],
  [/\.openai\.azure\.com$/, "azure-openai"],
  [/(^|\.)api\.anthropic\.com$/, "anthropic"],
  [/(^|\.)generativelanguage\.googleapis\.com$/, "google"],
  [/(^|\.)aiplatform\.googleapis\.com$/, "google-vertex"],
  [/^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/, "aws-bedrock"],
  [/(^|\.)api\.mistral\.ai$/, "mistral"],
  [/(^|\.)api\.cohere\.(ai|com)$/, "cohere"],
  [/(^|\.)api\.groq\.com$/, "groq"],
  [/(^|\.)api\.x\.ai$/, "xai"],
  [/(^|\.)api\.deepseek\.com$/, "deepseek"],
  [/(^|\.)api\.together\.(xyz|ai)$/, "together"],
  [/(^|\.)openrouter\.ai$/, "openrouter"],
  [/(^|\.)api-inference\.huggingface\.co$/, "huggingface"],
];

export function providerForDomain(domain: string): string | undefined {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  return LLM_PROVIDER_DOMAINS.find(([re]) => re.test(d))?.[1];
}

const PLATFORM_FOR_SOURCE: Record<DiscoverySource, string> = {
  gateway: "custom", egress_import: "custom", entra_id: "entra-id", okta: "okta",
  copilot_studio: "copilot-studio", gemini_enterprise: "gemini-enterprise", github: "custom",
};

export const fingerprintOf = (source: string, identity: string[]) =>
  createHash("sha256").update([source, ...identity.map((s) => s.toLowerCase())].join("\u0000")).digest("hex");

export class DiscoveryService {
  constructor(
    private db: Database.Database,
    private audit: AuditLog,
    private registry: AgentRegistry,
    private registration: RegistrationService,
    private directory: IdentityDirectory,
    private now: () => Date = () => new Date(),
  ) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS discovered_agents (
        id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL UNIQUE,
        source TEXT NOT NULL,
        kind TEXT NOT NULL,
        display_name TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        count INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('new','claimed','registered','ignored','disabled')),
        owner_email TEXT,
        agent_id TEXT,
        attributes TEXT NOT NULL,
        status_by TEXT,
        status_reason TEXT,
        status_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_discovered_status ON discovered_agents(status, last_seen);
    `);
    // A claimed discovery becomes "registered" as soon as its draft is submitted.
    const previous = registration.onSubmitted;
    registration.onSubmitted = (agent, by) => {
      previous?.(agent, by);
      if (agent.discoveryId) this.markRegistered(agent.discoveryId, agent, by);
    };
  }

  // ------------------------------------------------------------------ write path

  /** Records a sighting. Returns the row and whether it was new. */
  record(s: Sighting, ctx: Ctx = {}): { item: DiscoveredAgent; created: boolean } {
    const fingerprint = fingerprintOf(s.source, s.identity);
    const now = this.now().toISOString();
    const attributes = scrubValue(s.attributes ?? {});
    const displayName = scrubSecrets(s.displayName).slice(0, 200);
    const count = Math.max(1, Math.floor(s.count ?? 1));
    const first = s.firstSeen ?? now;
    const last = s.lastSeen ?? now;

    const tx = this.db.transaction(() => {
      const existing = this.db.prepare(`SELECT id FROM discovered_agents WHERE fingerprint = ?`).get(fingerprint) as { id: string } | undefined;
      if (existing) {
        this.db.prepare(`UPDATE discovered_agents SET count = count + ?, last_seen = max(last_seen, ?), first_seen = min(first_seen, ?),
            attributes = ?, display_name = ?, agent_id = coalesce(agent_id, ?) WHERE id = ?`)
          .run(count, last, first, JSON.stringify(attributes), displayName, s.agentId ?? null, existing.id);
        return { id: existing.id, created: false };
      }
      const id = nanoid(12);
      this.db.prepare(`INSERT INTO discovered_agents (id, fingerprint, source, kind, display_name, first_seen, last_seen, count, status, agent_id, attributes)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)`)
        .run(id, fingerprint, s.source, s.kind, displayName, first, last, count, s.agentId ?? null, JSON.stringify(attributes));
      return { id, created: true };
    });
    const { id, created } = tx.immediate();
    const item = this.get(id)!;
    if (created) {
      this.audit.append({
        stream: "audit", actorType: "system", actorId: `discovery:${s.source}`, action: "discovery.sighted", targetType: "discovery", targetId: id,
        outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
        details: { source: s.source, kind: s.kind, displayName, fingerprint: fingerprint.slice(0, 12), linkedAgentId: s.agentId },
      });
    }
    return { item, created };
  }

  /** Imports network egress logs: CSV with header
   *   source_host,destination_domain,count,first_seen,last_seen
   * Rows for non-LLM destinations are skipped. One discovery per
   * (source host, provider); repeated imports accumulate counts. */
  importEgressCsv(csv: string, by: string, ctx: Ctx = {}): DiscoveryResult<{ rows: number; matched: number; skipped: number; created: number; errors: string[] }> {
    const user = this.directory.lookup(by);
    if (!hasRole(user, "security_reviewer", "admin")) return this.deny(by, "discovery.import_egress", "egress", ["only security reviewers or admins may import egress logs"], ctx);
    const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const header = (lines.shift() ?? "").split(",").map((h) => h.trim().toLowerCase().replace(/^"|"$/g, ""));
    const want = ["source_host", "destination_domain", "count", "first_seen", "last_seen"];
    const idx = want.map((w) => header.indexOf(w));
    if (idx.some((i) => i < 0)) return this.deny(by, "discovery.import_egress", "egress", [`CSV header must contain: ${want.join(", ")}`], ctx);
    if (lines.length > 100_000) return this.deny(by, "discovery.import_egress", "egress", ["too many rows (max 100000 per import)"], ctx);

    const errors: string[] = [];
    let matched = 0, skipped = 0, created = 0;
    lines.forEach((line, n) => {
      const cols = splitCsvLine(line);
      const [host, domain, countS, firstS, lastS] = idx.map((i) => (cols[i] ?? "").trim());
      const rowNo = n + 2;
      if (!host || !domain) { errors.push(`row ${rowNo}: source_host and destination_domain are required`); return; }
      const provider = providerForDomain(domain);
      if (!provider) { skipped++; return; }
      const count = Number(countS || "1");
      const first = new Date(firstS), last = new Date(lastS || firstS);
      if (!Number.isInteger(count) || count < 0) { errors.push(`row ${rowNo}: count must be a non-negative integer`); return; }
      if (Number.isNaN(first.getTime()) || Number.isNaN(last.getTime())) { errors.push(`row ${rowNo}: first_seen/last_seen must be dates`); return; }
      matched++;
      const r = this.record({
        source: "egress_import", kind: "direct_provider_traffic", identity: [host, provider],
        displayName: `${host} -> ${provider}`, count: Math.max(count, 1),
        firstSeen: first.toISOString(), lastSeen: last.toISOString(),
        attributes: { sourceHost: host, destinationDomain: domain.toLowerCase(), provider },
      }, ctx);
      if (r.created) created++;
    });
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "discovery.import_egress", targetType: "discovery", targetId: "egress",
      outcome: errors.length && !matched ? "failure" : "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { rows: lines.length, matched, skipped, created, errors: errors.slice(0, 20) },
    });
    return { ok: true, rows: lines.length, matched, skipped, created, errors };
  }

  // ------------------------------------------------------------------ read path

  get(id: string): DiscoveredAgent | undefined {
    const r = this.db.prepare(`SELECT * FROM discovered_agents WHERE id = ?`).get(id) as any;
    return r ? rowTo(r) : undefined;
  }

  list(f: { status?: DiscoveryStatus; source?: string; queue?: "triage"; limit?: number } = {}): DiscoveredAgent[] {
    const where: string[] = [];
    const args: unknown[] = [];
    if (f.status) { where.push("status = ?"); args.push(f.status); }
    if (f.source) { where.push("source = ?"); args.push(f.source); }
    if (f.queue === "triage") where.push("status = 'new' AND owner_email IS NULL AND agent_id IS NULL");
    const sql = `SELECT * FROM discovered_agents ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY last_seen DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...args, Math.min(f.limit ?? 500, 5000)) as any[]).map(rowTo);
  }

  // ------------------------------------------------------------------ triage

  private deny(by: string, action: string, targetId: string, violations: string[], ctx: Ctx, notFound = false): { ok: false; violations: string[]; notFound?: boolean } {
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action, targetType: "discovery", targetId,
      outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { violations },
    });
    return { ok: false, violations, ...(notFound ? { notFound } : {}) };
  }

  private setStatus(item: DiscoveredAgent, to: DiscoveryStatus, by: string, reason: string | undefined, patch: { ownerEmail?: string; agentId?: string } = {}) {
    const at = this.now().toISOString();
    this.db.prepare(`UPDATE discovered_agents SET status = ?, status_by = ?, status_reason = ?, status_at = ?,
        owner_email = coalesce(?, owner_email), agent_id = coalesce(?, agent_id) WHERE id = ?`)
      .run(to, by, reason ?? null, at, patch.ownerEmail ?? null, patch.agentId ?? null, item.id);
    return this.get(item.id)!;
  }

  private checkTransition(item: DiscoveredAgent | undefined, id: string, to: DiscoveryStatus): string[] {
    if (!item) return [`unknown discovery ${id}`];
    if (!TRANSITIONS[item.status].includes(to)) return [`illegal discovery transition: ${item.status} -> ${to}`];
    return [];
  }

  /** Draft prefilled from what discovery knows. Purpose and access are left
   * for the owner to state; nothing is granted until the draft is submitted
   * and passes every registration check. */
  private draftFrom(item: DiscoveredAgent, ownerEmail: string, by: string, ctx: Ctx) {
    const a = item.attributes as Record<string, any>;
    return this.registration.createDraft({
      name: item.displayName,
      ownerEmail,
      platform: PLATFORM_FOR_SOURCE[item.source],
      modelProvider: typeof a.provider === "string" ? a.provider : undefined,
      purpose: "",
    }, by, ctx, { discoveryId: item.id, issueCredential: false });
  }

  /** An active agent_owner takes ownership: creates a Draft they own. */
  claim(id: string, by: string, ctx: Ctx = {}): DiscoveryResult<{ item: DiscoveredAgent; agent: Agent }> {
    const item = this.get(id);
    const user = this.directory.lookup(by);
    const v = this.checkTransition(item, id, "claimed");
    if (!hasRole(user, "agent_owner")) v.push("only an active agent_owner may claim a discovered agent");
    if (item?.agentId) v.push(`already linked to agent ${item.agentId}`);
    if (v.length || !item) return this.deny(by, "discovery.claim", id, v, ctx, !item);
    const d = this.draftFrom(item, user!.email, by, ctx);
    if (!d.ok) return this.deny(by, "discovery.claim", id, d.violations, ctx);
    const updated = this.setStatus(item, "claimed", by, "claimed by owner", { ownerEmail: user!.email, agentId: d.agent.id });
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "discovery.claim", targetType: "discovery", targetId: id,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { from: item.status, to: "claimed", draftAgentId: d.agent.id },
    });
    return { ok: true, item: updated, agent: d.agent };
  }

  /** Security names an owner for an unowned discovery; the draft is theirs. */
  assignOwner(id: string, ownerEmail: string, by: string, ctx: Ctx = {}): DiscoveryResult<{ item: DiscoveredAgent; agent: Agent }> {
    const item = this.get(id);
    const user = this.directory.lookup(by);
    const owner = ownerEmail ? this.directory.lookup(ownerEmail) : undefined;
    const v = this.checkTransition(item, id, "claimed");
    if (!hasRole(user, "security_reviewer", "admin")) v.push("only a security reviewer or admin may assign an owner");
    if (!hasRole(owner, "agent_owner")) v.push(`"${ownerEmail}" is not an active user with the agent_owner role`);
    if (item?.agentId) v.push(`already linked to agent ${item.agentId}`);
    if (v.length || !item) return this.deny(by, "discovery.assign_owner", id, v, ctx, !item);
    const d = this.draftFrom(item, owner!.email, by, ctx);
    if (!d.ok) return this.deny(by, "discovery.assign_owner", id, d.violations, ctx);
    const updated = this.setStatus(item, "claimed", by, `owner assigned: ${owner!.email}`, { ownerEmail: owner!.email, agentId: d.agent.id });
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "discovery.assign_owner", targetType: "discovery", targetId: id,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { from: item.status, to: "claimed", owner: owner!.email, draftAgentId: d.agent.id },
    });
    return { ok: true, item: updated, agent: d.agent };
  }

  ignore(id: string, by: string, reason: string | undefined, ctx: Ctx = {}): DiscoveryResult<{ item: DiscoveredAgent }> {
    const item = this.get(id);
    const user = this.directory.lookup(by);
    const v = this.checkTransition(item, id, "ignored");
    if (!hasRole(user, "security_reviewer", "admin")) v.push("only a security reviewer or admin may ignore a discovered agent");
    if (!reason?.trim()) v.push("a reason is required to ignore a discovered agent");
    if (v.length || !item) return this.deny(by, "discovery.ignore", id, v, ctx, !item);
    const updated = this.setStatus(item, "ignored", by, reason);
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "discovery.ignore", targetType: "discovery", targetId: id,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { from: item.status, to: "ignored", reason },
    });
    return { ok: true, item: updated };
  }

  /** Marks the discovery disabled. A linked agent is stopped: suspended if it
   * was active, retired if it never got approved; credentials are revoked
   * either way. Connectors are read-only, so a vendor-side identity (Entra
   * service principal, Okta app...) must be disabled in that system by hand;
   * the response says so. */
  disable(id: string, by: string, reason: string | undefined, ctx: Ctx = {}): DiscoveryResult<{ item: DiscoveredAgent; agent?: Agent; manualActionRequired?: string }> {
    const item = this.get(id);
    const user = this.directory.lookup(by);
    const v = this.checkTransition(item, id, "disabled");
    if (!hasRole(user, "security_reviewer", "admin")) v.push("only a security reviewer or admin may disable a discovered agent");
    if (v.length || !item) return this.deny(by, "discovery.disable", id, v, ctx, !item);
    const why = reason?.trim() || "disabled from discovery triage";

    let agent: Agent | undefined;
    if (item.agentId) {
      const linked = this.registry.get(item.agentId);
      if (linked && linked.lifecycleState === "active") {
        const r = this.registration.suspend(linked.id, by, why, ctx);
        if (r.ok) agent = r.agent;
      } else if (linked && ["draft", "pending_approval", "rejected"].includes(linked.lifecycleState)) {
        const r = this.registration.retire(linked.id, by, why, ctx);
        if (r.ok) agent = r.agent;
      } else if (linked) {
        // Already suspended/retired: still make sure nothing can authenticate.
        this.registration.revokeAgentCredentials(linked.id, "discovery_disabled", ctx);
        agent = linked;
      }
    }
    const updated = this.setStatus(item, "disabled", by, why);
    const manual = ["entra_id", "okta", "copilot_studio", "gemini_enterprise", "github"].includes(item.source)
      ? `connectors are read-only: disable or delete "${item.displayName}" in ${item.source} (and rotate any leaked key) by hand`
      : undefined;
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "discovery.disable", targetType: "discovery", targetId: id,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { from: item.status, to: "disabled", reason: why, linkedAgentId: item.agentId, agentState: agent?.lifecycleState, manualActionRequired: manual },
    });
    return { ok: true, item: updated, agent, manualActionRequired: manual };
  }

  private markRegistered(discoveryId: string, agent: Agent, by: string) {
    const item = this.get(discoveryId);
    if (!item || !TRANSITIONS[item.status].includes("registered")) return;
    this.setStatus(item, "registered", by, `draft ${agent.id} submitted`, { agentId: agent.id });
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "discovery", action: "discovery.registered", targetType: "discovery", targetId: discoveryId,
      outcome: "success", details: { from: item.status, to: "registered", agentId: agent.id, lifecycleState: agent.lifecycleState },
    });
  }
}

function rowTo(r: any): DiscoveredAgent {
  return {
    id: r.id, fingerprint: r.fingerprint, source: r.source, kind: r.kind, displayName: r.display_name,
    firstSeen: r.first_seen, lastSeen: r.last_seen, count: r.count, status: r.status,
    ownerEmail: r.owner_email ?? undefined, agentId: r.agent_id ?? undefined, attributes: JSON.parse(r.attributes),
    statusBy: r.status_by ?? undefined, statusReason: r.status_reason ?? undefined, statusAt: r.status_at ?? undefined,
  };
}

/** Minimal RFC 4180 line splitter (quoted fields, doubled quotes). */
export function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}
