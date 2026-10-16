// Registration as code: an agent.yaml manifest checked into the agent's repo.
//
// CI applies the manifest on every deploy (`zenai4-admin apply -f agent.yaml`
// or `POST /v1/agents/apply`). Apply is idempotent and keyed by the manifest's
// stable `metadata.id`, never by name, so renaming an agent updates it rather
// than creating a second one:
//
//   unknown id                -> create (a draft if required fields are missing)
//   known id, same spec hash  -> no-op (still audited, so CI runs are evidence)
//   known id, changed spec    -> update through RegistrationService, which
//                                re-runs the identity and access-profile checks
//                                and sends widened high/critical agents back to
//                                security review
//
// Design decisions:
//   - The schema is strict: an unknown or misspelt key is rejected, so a typo
//     cannot silently drop a restriction (same rule as policy parsing).
//   - Apply never issues an agent credential. A CI log is the worst place for a
//     one-time secret; the owner fetches it with `credentials/rotate`.
//   - The manifest names people (owner, sub-owner), not the CI identity. The
//     CI identity needs the ci_registrar role (or admin) to act for them, and
//     it can never review, own or claim an agent.
//   - Budgets are integer micro-USD, as everywhere else.

import { createHash } from "node:crypto";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { AuditLog } from "./audit-log.js";
import { missingForSubmission, type Ctx, type RegistrationRequest, type RegistrationService } from "./registration.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { Agent } from "../types.js";

const id = z.string().regex(/^[a-z0-9][a-z0-9._-]{1,62}$/, "lowercase letters, digits, '.', '_' or '-' (2-63 chars)");
const email = z.string().email();
const microUsd = z.number().int().nonnegative();
const dateLike = z.union([z.string(), z.date()]).transform((v, ctx) => {
  const d = v instanceof Date ? v : new Date(v);
  if (Number.isNaN(d.getTime())) {
    ctx.addIssue({ code: "custom", message: "not a valid date" });
    return z.NEVER;
  }
  return d.toISOString();
});

export const manifestSchema = z.strictObject({
  apiVersion: z.literal("zenai4/v1"),
  kind: z.literal("Agent"),
  metadata: z.strictObject({
    /** Stable identifier; the idempotency key for apply. */
    id,
    name: z.string().min(1).max(200),
    labels: z.record(z.string(), z.string()).optional(),
  }),
  spec: z.strictObject({
    purpose: z.string().min(1).optional(),
    owner: email,
    subOwner: email.optional(),
    businessUnit: z.string().min(1).optional(),
    platform: z.string().min(1).optional(),
    model: z
      .strictObject({
        provider: z.string().min(1),
        version: z.string().min(1),
        permitted: z.array(z.string().min(1)).min(1).optional(),
      })
      .optional(),
    accessProfile: z.string().min(1).optional(),
    autonomy: z.enum(["A0", "A1", "A2", "A3", "A4"]).optional(),
    mode: z.enum(["enforcement", "posture"]).optional(),
    tools: z
      .array(
        z.strictObject({
          name: z.string().min(1),
          reversible: z.boolean(),
          dataClasses: z.array(z.string().min(1)).default([]),
        }),
      )
      .optional(),
    budget: z
      .strictObject({ agentLimitMicro: microUsd.optional(), defaultTaskLimitMicro: microUsd.optional() })
      .optional(),
    expiresAt: dateLike.optional(),
  }),
});

export type AgentManifest = z.infer<typeof manifestSchema>;

export function parseManifest(text: string): { ok: true; manifest: AgentManifest; hash: string } | { ok: false; errors: string[] } {
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 50 });
  } catch (e) {
    return { ok: false, errors: [`not valid YAML: ${(e as Error).message.split("\n")[0]}`] };
  }
  return validateManifest(raw);
}

export function validateManifest(raw: unknown): { ok: true; manifest: AgentManifest; hash: string } | { ok: false; errors: string[] } {
  const r = manifestSchema.safeParse(raw);
  if (!r.success) return { ok: false, errors: r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`) };
  return { ok: true, manifest: r.data, hash: manifestHash(r.data) };
}

/** Stable hash of everything that defines the agent (labels excluded). */
export function manifestHash(m: AgentManifest): string {
  const canon = (v: unknown): unknown =>
    Array.isArray(v) ? v.map(canon) : v && typeof v === "object"
      ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, canon((v as any)[k])]))
      : v;
  return createHash("sha256").update(JSON.stringify(canon({ name: m.metadata.name, spec: m.spec }))).digest("hex");
}

/** Maps a manifest onto the registration request shape (fields may be missing). */
export function manifestToRequest(m: AgentManifest): Partial<RegistrationRequest> & { ownerEmail: string } {
  const s = m.spec;
  return {
    name: m.metadata.name,
    purpose: s.purpose,
    ownerEmail: s.owner.toLowerCase(),
    subOwnerEmail: s.subOwner?.toLowerCase(),
    accessProfileId: s.accessProfile,
    businessUnit: s.businessUnit,
    platform: s.platform,
    modelProvider: s.model?.provider,
    modelVersion: s.model?.version,
    permittedModels: s.model?.permitted,
    autonomyDefault: s.autonomy,
    mode: s.mode,
    tools: s.tools?.map((t) => ({ toolName: t.name, reversible: t.reversible, dataClasses: t.dataClasses })),
    budgetPolicy: s.budget,
    expiresAt: s.expiresAt,
  };
}

export type ApplyResult =
  | { ok: true; action: "created" | "drafted" | "updated" | "unchanged"; agent: Agent; widened?: string[]; reReview?: boolean; missing?: string[] }
  | { ok: false; violations: string[] };

export class ManifestService {
  constructor(
    private registry: AgentRegistry,
    private registration: RegistrationService,
    private audit: AuditLog,
  ) {}

  applyText(text: string, by: string, ctx: Ctx = {}): ApplyResult {
    const parsed = parseManifest(text);
    if (!parsed.ok) return this.refuse(by, "(unparsed)", parsed.errors, ctx);
    return this.apply(parsed.manifest, parsed.hash, by, ctx);
  }

  applyObject(raw: unknown, by: string, ctx: Ctx = {}): ApplyResult {
    const parsed = validateManifest(raw);
    if (!parsed.ok) return this.refuse(by, "(unparsed)", parsed.errors, ctx);
    return this.apply(parsed.manifest, parsed.hash, by, ctx);
  }

  private refuse(by: string, manifestId: string, violations: string[], ctx: Ctx): ApplyResult {
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.apply", targetType: "manifest", targetId: manifestId,
      outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { violations },
    });
    return { ok: false, violations };
  }

  private done(by: string, m: AgentManifest, hash: string, r: Extract<ApplyResult, { ok: true }>, ctx: Ctx): ApplyResult {
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.apply", targetType: "agent", targetId: r.agent.id,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { manifestId: m.metadata.id, manifestHash: hash, result: r.action, lifecycleState: r.agent.lifecycleState, riskTier: r.agent.riskTier, widened: r.widened, reReview: r.reReview },
    });
    return r;
  }

  apply(m: AgentManifest, hash: string, by: string, ctx: Ctx = {}): ApplyResult {
    const req = manifestToRequest(m);
    const opts = { issueCredential: false, manifestId: m.metadata.id, manifestHash: hash, delegateRoles: ["ci_registrar" as const] };
    const existing = this.registry.findByManifestId(m.metadata.id);

    if (!existing) {
      const missing = missingForSubmission(req);
      if (missing.length) {
        const d = this.registration.createDraft(req, by, ctx, opts);
        if (!d.ok) return this.refuse(by, m.metadata.id, d.violations, ctx);
        return this.done(by, m, hash, { ok: true, action: "drafted", agent: d.agent, missing }, ctx);
      }
      const s = this.registration.submit(req as RegistrationRequest, by, ctx, opts);
      if (!s.ok) return this.refuse(by, m.metadata.id, s.violations, ctx);
      return this.done(by, m, hash, { ok: true, action: "created", agent: s.agent }, ctx);
    }

    if (existing.manifestHash === hash) {
      return this.done(by, m, hash, { ok: true, action: "unchanged", agent: existing }, ctx);
    }
    if (existing.lifecycleState === "retired") {
      return this.refuse(by, m.metadata.id, [`agent ${existing.id} for manifest "${m.metadata.id}" is retired; use a new metadata.id to register a successor`], ctx);
    }

    const u = this.registration.updateRegistration(existing.id, req, by, ctx, opts);
    if (!u.ok) return this.refuse(by, m.metadata.id, u.violations, ctx);
    let agent = u.agent;
    // A draft that the manifest has now completed moves on to approval.
    if (agent.lifecycleState === "draft" && missingForSubmission(manifestToRequest(m)).length === 0) {
      const s = this.registration.submitDraft(agent.id, by, ctx, opts);
      if (!s.ok) return this.refuse(by, m.metadata.id, s.violations, ctx);
      agent = s.agent;
    }
    return this.done(by, m, hash, { ok: true, action: "updated", agent, widened: u.widened, reReview: u.reReview }, ctx);
  }
}
