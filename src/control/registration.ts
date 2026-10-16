// Registration service: the gate every agent passes before it can act.
//
//   submit  -> verify identities, fit request to an access profile, register
//   review  -> a human security reviewer (never the owner/sub-owner/submitter)
//              completes a checklist and approves or rejects
//   activate-> a one-time credential is issued; only then can the agent call
//              the gateway
//
// Checks performed at submission (each failure is returned AND audit-logged):
//   - submitter, owner and sub-owner are active people in the directory
//   - owner and sub-owner both hold the agent_owner role and are different people
//   - the submitter is the owner, the sub-owner, or an admin
//   - the access profile exists and the requested tools, data classes,
//     models and autonomy all fit inside it
//   - purpose, models and budget policy are present and well-formed
//
// Review requirement: a profile can force review, and the registry forces it
// for high/critical risk regardless. Review needs a reviewer who holds the
// security_reviewer role, is not the owner/sub-owner/submitter, and a fully
// ticked checklist to approve. Separation of duties is the point: the people
// accountable for an agent cannot be the ones who clear it.
//
// Every outcome - success, denial, failure - is written to the audit log.
//
// Phase 1 additions (registration and discovery):
//   - drafts: discovery claims and incomplete agent.yaml manifests create a
//     "draft" owned by a named person; submitDraft() runs the full checks
//     above and moves it on to pending_approval (and on to active when no
//     review is needed). Draft -> pending -> active is always explicit.
//   - updates: updateRegistration() re-runs every submission check; an update
//     that WIDENS access (new tool, new data class, irreversible tool, higher
//     autonomy, new model or provider) on an active agent whose resulting
//     tier is high/critical (or whose profile demands review) goes back to
//     pending_approval and its credentials are revoked until re-approved.
//   - risk tier: owners may only raise it; only a security reviewer (not an
//     owner of the agent) may lower it, and lowering below the computed
//     floor requires a written reason. Who/why is stored on the agent.
//   - lifecycle: transition() enforces the registry's transition table and
//     audits refusals; retiring is terminal and revokes credentials.
//   - expiry: every agent expires (default and maximum 90 days); owners
//     recertify() to extend by 90 days from now; expirySweep() suspends
//     expired agents and revokes credentials. The registry refuses expired
//     agents even before the sweep runs.

import type { AuditLog } from "./audit-log.js";
import type { CredentialService } from "./credentials.js";
import { hasRole, type IdentityDirectory } from "./identity.js";
import { profileViolations, type AccessProfileStore } from "./access-profiles.js";
import { canTransition, tierRank, type AgentRegistry, type RegisterAgentInput } from "../registry/registry.js";
import type { Agent, AutonomyLevel, GovernanceMode, BudgetPolicy, LifecycleState, RiskTier, ToolGrant } from "../types.js";

const DAY_MS = 86_400_000;
const AUTONOMY_ORDER: AutonomyLevel[] = ["A0", "A1", "A2", "A3", "A4"];

export const REQUIRED_REVIEW_CHECKLIST = [
  "identity_verified",
  "least_privilege_reviewed",
  "data_classification_confirmed",
  "logging_enabled",
  "kill_switch_tested",
] as const;

export interface RegistrationRequest {
  name: string;
  purpose: string;
  ownerEmail: string;
  subOwnerEmail: string;
  accessProfileId: string;
  businessUnit: string;
  platform: string;
  modelProvider: string;
  modelVersion: string;
  autonomyDefault: AutonomyLevel;
  mode: GovernanceMode;
  tools: Omit<ToolGrant, "agentId">[];
  permittedModels?: string[];
  budgetPolicy: BudgetPolicy;
  expiresInDays?: number;
  /** Explicit expiry date (ISO date or timestamp). Must be in the future and
   * within the maximum certification period (90 days by default). */
  expiresAt?: string;
}

/** Fields a draft may be missing; everything else is required at submission. */
export type DraftRequest = Partial<RegistrationRequest> & { ownerEmail: string };

export interface RegistrationOptions {
  /** Default certification period (days) for new and recertified agents. */
  certificationDays?: number;
  /** Longest expiry an explicit expiresAt may ask for. */
  maxExpiryDays?: number;
  /** How long after expiry an expired-and-suspended agent may still be recertified. */
  recertGraceDays?: number;
  now?: () => Date;
}

export interface SubmitOptions {
  /** Issue a credential when the agent activates without review (default true). */
  issueCredential?: boolean;
  manifestId?: string;
  manifestHash?: string;
  discoveryId?: string;
  /** Extra roles allowed to submit on behalf of the named owner (e.g. ci_registrar). */
  delegateRoles?: Array<"ci_registrar">;
}

export interface Ctx {
  sourceIp?: string;
  requestId?: string;
}

export type IssuedCredential = { token: string; keyId: string; expiresAt: string };
export type SubmitResult =
  | { ok: true; agent: Agent; credential?: IssuedCredential; needsReview: boolean }
  | { ok: false; violations: string[] };
export type ActionResult<T = {}> = ({ ok: true } & T) | { ok: false; violations: string[] };

const same = (a?: string, b?: string) => Boolean(a && b && a.toLowerCase() === b.toLowerCase());

type ToolSpec = Omit<ToolGrant, "agentId">;

/** What changed that grants MORE access than before. Empty = not widened. */
export function wideningChanges(
  before: { tools: ToolSpec[]; autonomy?: AutonomyLevel; models: string[]; modelProvider?: string },
  after: { tools: ToolSpec[]; autonomy?: AutonomyLevel; models: string[]; modelProvider?: string },
): string[] {
  const out: string[] = [];
  const prev = new Map(before.tools.map((t) => [t.toolName, t]));
  for (const t of after.tools) {
    const p = prev.get(t.toolName);
    if (!p) { out.push(`new tool "${t.toolName}"`); continue; }
    for (const dc of t.dataClasses) if (!p.dataClasses.includes(dc)) out.push(`new data class "${dc}" on tool "${t.toolName}"`);
    if (p.reversible && !t.reversible) out.push(`tool "${t.toolName}" became irreversible`);
  }
  if (AUTONOMY_ORDER.indexOf(after.autonomy ?? "A0") > AUTONOMY_ORDER.indexOf(before.autonomy ?? "A0")) {
    out.push(`autonomy ${before.autonomy ?? "none"} -> ${after.autonomy}`);
  }
  for (const m of after.models) if (!before.models.includes(m)) out.push(`new model "${m}"`);
  if (before.modelProvider && after.modelProvider && before.modelProvider !== after.modelProvider) {
    out.push(`model provider ${before.modelProvider} -> ${after.modelProvider}`);
  }
  return out;
}

/** Required fields a draft must have before it can be submitted. */
export function missingForSubmission(r: Partial<RegistrationRequest>): string[] {
  const m: string[] = [];
  for (const k of ["name", "purpose", "ownerEmail", "subOwnerEmail", "accessProfileId", "businessUnit", "platform", "modelProvider", "modelVersion", "autonomyDefault", "mode"] as const) {
    const v = r[k];
    if (typeof v !== "string" || !v.trim()) m.push(k);
  }
  if (!Array.isArray(r.tools)) m.push("tools");
  if (!r.budgetPolicy || typeof r.budgetPolicy !== "object") m.push("budgetPolicy");
  return m;
}

/** Rebuilds a registration request from a stored agent (for drafts and updates). */
export function requestFromAgent(a: Agent, tools: ToolSpec[]): Partial<RegistrationRequest> {
  return {
    name: a.name, purpose: a.purpose, ownerEmail: a.ownerEmail, subOwnerEmail: a.subOwnerEmail, accessProfileId: a.accessProfileId,
    businessUnit: a.businessUnit, platform: a.platform, modelProvider: a.modelProvider, modelVersion: a.modelVersion,
    autonomyDefault: a.autonomyDefault, mode: a.mode, tools, permittedModels: a.permittedModels, budgetPolicy: a.budgetPolicy,
    expiresAt: a.expiresAt,
  };
}

export class RegistrationService {
  private certificationDays: number;
  private maxExpiryDays: number;
  private recertGraceDays: number;
  private now: () => Date;
  /** Set by the discovery service so a submitted claim marks its discovery row registered. */
  onSubmitted?: (agent: Agent, by: string) => void;

  constructor(
    private registry: AgentRegistry,
    private directory: IdentityDirectory,
    private profiles: AccessProfileStore,
    private credentials: CredentialService,
    private audit: AuditLog,
    opts: RegistrationOptions = {},
  ) {
    this.certificationDays = opts.certificationDays ?? 90;
    this.maxExpiryDays = opts.maxExpiryDays ?? this.certificationDays;
    this.recertGraceDays = opts.recertGraceDays ?? 30;
    this.now = opts.now ?? (() => new Date());
  }

  private deny(by: string, action: string, targetId: string, violations: string[], ctx: Ctx, details: Record<string, unknown> = {}) {
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action, targetType: "agent", targetId,
      outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { ...details, violations },
    });
    return { ok: false as const, violations };
  }

  private issueCredential(agentId: string, via: string, ctx: Ctx): IssuedCredential {
    const credential = this.credentials.issueAgentCredential(agentId);
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.issue", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { keyId: credential.keyId, expiresAt: credential.expiresAt, via },
    });
    return credential;
  }

  private revokeCredentials(agentId: string, reason: string, ctx: Ctx) {
    const count = this.credentials.revokeAll("agent", agentId, reason);
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.revoke", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { count, reason },
    });
    return count;
  }

  /** May `by` change this agent's registration? Owner, sub-owner, admin, or a delegate role. */
  mayManage(agent: Agent, by: string, delegateRoles: Array<"ci_registrar"> = []): boolean {
    const user = this.directory.lookup(by);
    return hasRole(user, "admin", ...delegateRoles) ||
      (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail)));
  }

  /** Revokes every credential of an agent (audited). Used by discovery's disable. */
  revokeAgentCredentials(agentId: string, reason: string, ctx: Ctx = {}) {
    return this.revokeCredentials(agentId, reason, ctx);
  }

  /** Expiry requested by the caller, validated: future, within the maximum. */
  private expiryViolations(req: { expiresAt?: string; expiresInDays?: number }): string[] {
    const v: string[] = [];
    const now = this.now().getTime();
    if (req.expiresAt !== undefined) {
      const t = new Date(req.expiresAt).getTime();
      if (Number.isNaN(t)) v.push(`expiresAt "${req.expiresAt}" is not a valid date`);
      else if (t <= now) v.push("expiresAt must be in the future");
      else if (t > now + this.maxExpiryDays * DAY_MS + 60_000) v.push(`expiresAt is more than ${this.maxExpiryDays} days away; agents must be recertified at least every ${this.maxExpiryDays} days`);
    }
    if (req.expiresInDays !== undefined && (!Number.isFinite(req.expiresInDays) || req.expiresInDays <= 0 || req.expiresInDays > this.maxExpiryDays)) {
      v.push(`expiresInDays must be between 1 and ${this.maxExpiryDays}`);
    }
    return v;
  }

  /** Every check a complete registration must pass. Shared by submit, submitDraft and updates. */
  private validate(req: RegistrationRequest, submittedBy: string, opts: { delegateRoles?: Array<"ci_registrar"> } = {}) {
    const v: string[] = [];
    const submitter = this.directory.lookup(submittedBy);
    const owner = this.directory.lookup(req.ownerEmail);
    const sub = req.subOwnerEmail ? this.directory.lookup(req.subOwnerEmail) : undefined;

    if (!submitter?.active) v.push("submitter is not an active user in the identity directory");
    if (!owner?.active) v.push(`owner "${req.ownerEmail}" is not an active user in the identity directory`);
    else if (!hasRole(owner, "agent_owner")) v.push(`owner "${req.ownerEmail}" does not hold the agent_owner role`);
    if (!req.subOwnerEmail?.trim()) v.push("a sub-owner is required");
    else if (!sub?.active) v.push(`sub-owner "${req.subOwnerEmail}" is not an active user in the identity directory`);
    else if (!hasRole(sub, "agent_owner")) v.push(`sub-owner "${req.subOwnerEmail}" does not hold the agent_owner role`);
    if (same(req.ownerEmail, req.subOwnerEmail)) v.push("owner and sub-owner must be different people");
    if (submitter?.active && !same(submittedBy, req.ownerEmail) && !same(submittedBy, req.subOwnerEmail) && !hasRole(submitter, "admin", ...(opts.delegateRoles ?? []))) {
      v.push("only the owner, the sub-owner or an admin may register this agent");
    }
    if (!req.purpose?.trim()) v.push("an approved purpose is required");

    const profile = this.profiles.get(req.accessProfileId);
    if (!profile) v.push(`access profile "${req.accessProfileId}" does not exist`);
    else {
      v.push(
        ...profileViolations(profile, {
          tools: req.tools,
          models: req.permittedModels ?? [req.modelVersion],
          autonomy: req.autonomyDefault,
        }),
      );
    }
    v.push(...this.expiryViolations(req));
    return { violations: v, profile };
  }

  submit(req: RegistrationRequest, submittedBy: string, ctx: Ctx = {}, opts: SubmitOptions = {}): SubmitResult {
    const { violations: v, profile } = this.validate(req, submittedBy, opts);

    let agent: Agent | undefined;
    if (v.length === 0 && profile) {
      try {
        const input: RegisterAgentInput = {
          ...req, registeredBy: submittedBy, forcePendingReview: profile.requiresSecurityReview,
          manifestId: opts.manifestId, manifestHash: opts.manifestHash, discoveryId: opts.discoveryId,
        };
        agent = this.registry.register(input);
      } catch (e) {
        v.push((e as Error).message);
      }
    }

    if (!agent) {
      this.audit.append({
        stream: "user", actorType: "user", actorId: submittedBy, action: "agent.register", targetType: "agent", targetId: req.name,
        outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { violations: v, owner: req.ownerEmail, subOwner: req.subOwnerEmail },
      });
      return { ok: false, violations: v };
    }

    const needsReview = agent.lifecycleState === "pending_approval";
    let credential: IssuedCredential | undefined;
    if (!needsReview && opts.issueCredential !== false) credential = this.issueCredential(agent.id, "auto_activation", ctx);
    return { ok: true, agent, credential, needsReview };
  }

  /** Creates a draft: only the owner is checked now (active person with the
   * agent_owner role); everything else is checked by submitDraft(). */
  createDraft(req: DraftRequest, createdBy: string, ctx: Ctx = {}, opts: SubmitOptions = {}): ActionResult<{ agent: Agent }> {
    const v: string[] = [];
    const by = this.directory.lookup(createdBy);
    const owner = this.directory.lookup(req.ownerEmail);
    if (!by?.active) v.push("submitter is not an active user in the identity directory");
    if (!owner?.active) v.push(`owner "${req.ownerEmail}" is not an active user in the identity directory`);
    else if (!hasRole(owner, "agent_owner")) v.push(`owner "${req.ownerEmail}" does not hold the agent_owner role`);
    if (by?.active && !same(createdBy, req.ownerEmail) && !same(createdBy, req.subOwnerEmail) && !hasRole(by, "admin", "security_reviewer", ...(opts.delegateRoles ?? []))) {
      v.push("only the owner, the sub-owner, security or an admin may create this draft");
    }
    v.push(...this.expiryViolations(req));
    if (v.length) return this.deny(createdBy, "agent.draft", req.name ?? "(draft)", v, ctx, { owner: req.ownerEmail });
    const agent = this.registry.register({
      name: req.name?.trim() || "unnamed draft",
      purpose: req.purpose ?? "",
      ownerEmail: req.ownerEmail.toLowerCase(),
      subOwnerEmail: req.subOwnerEmail,
      accessProfileId: req.accessProfileId,
      registeredBy: createdBy,
      businessUnit: req.businessUnit ?? "",
      platform: req.platform ?? "",
      modelProvider: req.modelProvider ?? "",
      modelVersion: req.modelVersion ?? "",
      autonomyDefault: req.autonomyDefault ?? "A0",
      mode: req.mode ?? "enforcement",
      tools: req.tools ?? [],
      permittedModels: req.permittedModels,
      budgetPolicy: req.budgetPolicy ?? {},
      expiresAt: req.expiresAt,
      expiresInDays: req.expiresInDays,
      draft: true,
      manifestId: opts.manifestId,
      manifestHash: opts.manifestHash,
      discoveryId: opts.discoveryId,
    });
    return { ok: true, agent };
  }

  /** Draft -> pending_approval (-> active when no review is needed). Runs every
   * submission check against the draft's current fields. */
  submitDraft(agentId: string, by: string, ctx: Ctx = {}, opts: SubmitOptions = {}): SubmitResult {
    const agent = this.registry.get(agentId);
    if (!agent) return this.deny(by, "agent.submit", agentId, [`unknown agent ${agentId}`], ctx);
    if (agent.lifecycleState !== "draft") return this.deny(by, "agent.submit", agentId, [`agent is "${agent.lifecycleState}", not a draft`], ctx);
    const req = requestFromAgent(agent, this.registry.grantsFor(agentId).map(({ agentId: _a, ...t }) => t));
    const missing = missingForSubmission(req);
    if (missing.length) return this.deny(by, "agent.submit", agentId, [`draft is incomplete: missing ${missing.join(", ")}`], ctx);
    // Expiry is re-based at submission so a long-lived draft does not start life expired.
    const full = { ...(req as RegistrationRequest), expiresAt: undefined };
    const { violations, profile } = this.validate(full, by, opts);
    if (violations.length || !profile) return this.deny(by, "agent.submit", agentId, violations, ctx);

    const expiresAt = new Date(this.now().getTime() + this.certificationDays * DAY_MS).toISOString();
    const tier = agent.riskTier;
    const needsReview = profile.requiresSecurityReview || tierRank(tier) >= tierRank("high");
    let updated = this.registry.transition(agentId, "pending_approval", by, "submitted for approval", {
      securityReview: needsReview ? { status: "pending" } : undefined, expiresAt, registeredBy: by,
    });
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.submit", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { riskTier: tier, needsReview },
    });
    let credential: IssuedCredential | undefined;
    if (!needsReview) {
      updated = this.registry.approve(agentId, "system:auto-approval");
      if (opts.issueCredential !== false) credential = this.issueCredential(agentId, "auto_activation", ctx);
    }
    try { this.onSubmitted?.(updated, by); } catch { /* discovery bookkeeping must not undo a submission */ }
    return { ok: true, agent: updated, credential, needsReview };
  }

  /** Changes a registration. Re-runs every submission check (drafts only need
   * their owner checked). Widening an active agent into high/critical (or into a
   * review-required profile) sends it back to security review and revokes its
   * credentials until it is re-approved. */
  updateRegistration(
    agentId: string,
    req: Partial<RegistrationRequest>,
    by: string,
    ctx: Ctx = {},
    opts: SubmitOptions = {},
  ): ActionResult<{ agent: Agent; widened: string[]; reReview: boolean }> {
    const agent = this.registry.get(agentId);
    if (!agent) return this.deny(by, "agent.update", agentId, [`unknown agent ${agentId}`], ctx);
    if (agent.lifecycleState === "retired") return this.deny(by, "agent.update", agentId, ["agent is retired; retired agents cannot be changed"], ctx);
    if (!this.mayManage(agent, by, opts.delegateRoles)) return this.deny(by, "agent.update", agentId, ["only the owner, the sub-owner or an admin may change this agent"], ctx);

    const beforeTools = this.registry.grantsFor(agentId).map(({ agentId: _a, ...t }) => t);
    const merged = { ...requestFromAgent(agent, beforeTools), ...stripUndefined(req) };
    // A changed modelVersion without an explicit permitted list means "just that model".
    if (req.modelVersion && !req.permittedModels) merged.permittedModels = [req.modelVersion];

    if (agent.lifecycleState === "draft") {
      if (merged.ownerEmail && !same(merged.ownerEmail, agent.ownerEmail)) {
        const o = this.directory.lookup(merged.ownerEmail);
        if (!hasRole(o, "agent_owner")) return this.deny(by, "agent.update", agentId, [`owner "${merged.ownerEmail}" is not an active agent_owner`], ctx);
      }
      const ev = this.expiryViolations(req);
      if (ev.length) return this.deny(by, "agent.update", agentId, ev, ctx);
    } else {
      const missing = missingForSubmission(merged);
      if (missing.length) return this.deny(by, "agent.update", agentId, [`registration is incomplete: missing ${missing.join(", ")}`], ctx);
      // An unchanged stored expiry is not re-validated (it may legitimately be close).
      const full = { ...(merged as RegistrationRequest), expiresAt: req.expiresAt };
      const { violations } = this.validate(full, by, opts);
      if (violations.length) return this.deny(by, "agent.update", agentId, violations, ctx);
    }

    const widened = wideningChanges(
      { tools: beforeTools, autonomy: agent.autonomyDefault, models: agent.permittedModels, modelProvider: agent.modelProvider },
      { tools: merged.tools ?? [], autonomy: merged.autonomyDefault, models: merged.permittedModels ?? [], modelProvider: merged.modelProvider },
    );
    let updated = this.registry.update(agentId, {
      name: merged.name, purpose: merged.purpose, ownerEmail: merged.ownerEmail, subOwnerEmail: merged.subOwnerEmail,
      accessProfileId: merged.accessProfileId, businessUnit: merged.businessUnit, platform: merged.platform,
      modelProvider: merged.modelProvider, modelVersion: merged.modelVersion, permittedModels: merged.permittedModels,
      budgetPolicy: merged.budgetPolicy, autonomyDefault: merged.autonomyDefault, mode: merged.mode,
      ...(req.expiresAt ? { expiresAt: new Date(req.expiresAt).toISOString() } : {}),
      ...(opts.manifestHash ? { manifestHash: opts.manifestHash } : {}),
      tools: req.tools ? merged.tools : undefined,
    }, by);

    const profile = merged.accessProfileId ? this.profiles.get(merged.accessProfileId) : undefined;
    const reviewTier = tierRank(updated.riskTier) >= tierRank("high") || profile?.requiresSecurityReview === true;
    let reReview = false;
    if (widened.length && reviewTier && (updated.lifecycleState === "active" || updated.lifecycleState === "suspended")) {
      updated = this.sendToReReview(agentId, "system:registration-service", "access widened; security re-review required", widened, "access_widened_pending_review", ctx) ?? updated;
      reReview = true;
    } else if (widened.length && updated.lifecycleState === "pending_approval") {
      // Anything a reviewer may already have looked at is stale now.
      updated = this.registry.update(agentId, { securityReview: { status: "pending", notes: `widened: ${widened.join("; ")}` } }, "system:registration-service");
    }
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.update", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { widened, reReview, riskTier: updated.riskTier, lifecycleState: updated.lifecycleState, via: opts.manifestId ? "manifest" : "api" },
    });
    return { ok: true, agent: updated, widened, reReview };
  }

  /** Sends an active (or suspended) agent back to security review with the
   * reasons recorded on the pending review, and revokes its credentials until
   * it is re-approved. Shared by widening updates and by telemetry
   * reconciliation (observed drift in enforce_review mode). Returns undefined
   * when the agent is in a state that cannot go to review. */
  sendToReReview(agentId: string, actor: string, reason: string, widened: string[], revokeReason: string, ctx: Ctx = {}): Agent | undefined {
    const agent = this.registry.get(agentId);
    if (!agent || !(agent.lifecycleState === "active" || agent.lifecycleState === "suspended")) return undefined;
    const updated = this.registry.transition(agentId, "pending_approval", actor, reason, {
      securityReview: { status: "pending", notes: `widened: ${widened.join("; ")}` },
    });
    this.revokeCredentials(agentId, revokeReason, ctx);
    return updated;
  }

  /** Records a risk-tier raise decided by the system (telemetry: repeated
   * policy violations). Stored as a "raise" override by "system:<name>", so
   * owners cannot lower it (only a security reviewer can, under the Phase 1
   * rules in setRiskTier) and the audit shows who raised it and why. */
  systemRaiseRiskTier(agentId: string, tier: RiskTier, actor: string, reason: string, ctx: Ctx = {}): Agent | undefined {
    const agent = this.registry.get(agentId);
    if (!agent || agent.lifecycleState === "retired" || tierRank(tier) <= tierRank(agent.riskTier)) return undefined;
    const updated = this.registry.setRiskOverride(agentId, { tier, direction: "raise", by: actor, reason, at: this.now().toISOString() }, actor);
    this.audit.append({
      stream: "audit", actorType: "system", actorId: actor, action: "agent.risk_tier.set", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { from: agent.riskTier, to: updated.riskTier, computed: updated.computedRiskTier, direction: "raise", reason },
    });
    return updated;
  }

  /** Owners raise; security lowers (never their own agent); lowering below the
   * computed floor needs a reason. Raising into high/critical an agent that was
   * never security-approved sends it to review. */
  setRiskTier(agentId: string, tier: RiskTier, by: string, reason: string | undefined, ctx: Ctx = {}): ActionResult<{ agent: Agent }> {
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(by);
    const v: string[] = [];
    if (!agent) return this.deny(by, "agent.risk_tier.set", agentId, [`unknown agent ${agentId}`], ctx, { tier });
    if (!["low", "medium", "high", "critical"].includes(tier)) return this.deny(by, "agent.risk_tier.set", agentId, [`unknown risk tier "${tier}"`], ctx, { tier });
    if (agent.lifecycleState === "retired") v.push("agent is retired");
    const computed = agent.computedRiskTier ?? agent.riskTier;
    const current = agent.riskTier;
    const isOwner = hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail));
    const isSecurity = hasRole(user, "security_reviewer");
    const lowering = tierRank(tier) < tierRank(current);
    if (tier === current) v.push(`risk tier is already ${current}`);
    else if (lowering) {
      if (!isSecurity) v.push("only a security reviewer may lower a risk tier");
      else if (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail) || same(by, agent.registeredBy)) {
        v.push("separation of duties: an owner, sub-owner or submitter cannot lower their own agent's risk tier");
      }
      if (tierRank(tier) < tierRank(computed) && !reason?.trim()) v.push(`lowering below the computed tier (${computed}) requires a reason`);
    } else if (!isOwner && !isSecurity) {
      v.push("only the owner, the sub-owner or a security reviewer may raise a risk tier");
    }
    if (v.length) return this.deny(by, "agent.risk_tier.set", agentId, v, ctx, { tier, current, computed });

    let updated = this.registry.setRiskOverride(
      agentId,
      tier === computed && !lowering ? undefined : { tier, direction: lowering ? "lower" : "raise", by, reason: reason?.trim() || undefined, at: this.now().toISOString() },
      by,
    );
    let reReview = false;
    if (!lowering && tierRank(updated.riskTier) >= tierRank("high") && updated.lifecycleState === "active" && updated.securityReview?.status !== "approved") {
      updated = this.registry.transition(agentId, "pending_approval", "system:registration-service", `risk tier raised to ${updated.riskTier}; security approval required`, {
        securityReview: { status: "pending" },
      });
      this.revokeCredentials(agentId, "risk_raised_pending_review", ctx);
      reReview = true;
    }
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.risk_tier.set", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
      details: { from: current, to: updated.riskTier, computed, direction: lowering ? "lower" : "raise", reason, reReview },
    });
    return { ok: true, agent: updated };
  }

  /** Generic lifecycle request (API/CLI). Enforces the transition table first,
   * then routes to the specific operation that owns the rules for that move. */
  transition(agentId: string, to: LifecycleState, by: string, reason: string | undefined, ctx: Ctx = {}): ActionResult<{ agent: Agent; credential?: IssuedCredential }> {
    const agent = this.registry.get(agentId);
    if (!agent) return this.deny(by, "agent.transition", agentId, [`unknown agent ${agentId}`], ctx, { to });
    const from = agent.lifecycleState;
    if (!canTransition(from, to)) {
      return this.deny(by, "agent.transition", agentId, [`illegal lifecycle transition: ${from} -> ${to}`], ctx, { from, to });
    }
    switch (to) {
      case "suspended": return this.suspend(agentId, by, reason ?? "suspended", ctx);
      case "retired": return this.retire(agentId, by, reason ?? "retired", ctx);
      case "pending_approval": {
        if (from === "draft") {
          const r = this.submitDraft(agentId, by, ctx);
          return r.ok ? { ok: true, agent: r.agent, credential: r.credential } : r;
        }
        // suspended -> pending_approval: ask security to look again (owners, security, admins).
        const user = this.directory.lookup(by);
        const ok = hasRole(user, "admin", "security_reviewer") || (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail)));
        if (!ok) return this.deny(by, "agent.transition", agentId, ["not permitted to request re-review of this agent"], ctx, { from, to });
        const updated = this.registry.transition(agentId, "pending_approval", by, reason ?? "re-review requested", { securityReview: { status: "pending" } });
        return { ok: true, agent: updated };
      }
      case "draft": {
        const user = this.directory.lookup(by);
        const ok = hasRole(user, "admin") || (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail)));
        if (!ok) return this.deny(by, "agent.transition", agentId, ["only the owner, sub-owner or an admin may reopen a rejected agent as a draft"], ctx, { from, to });
        return { ok: true, agent: this.registry.transition(agentId, "draft", by, reason ?? "reopened", { securityReview: undefined }) };
      }
      case "active":
        return this.deny(by, "agent.transition", agentId, [from === "suspended" ? "a suspended agent returns to active only through recertification (if it expired) or a fresh security review" : "agents become active only through security review"], ctx, { from, to });
      case "rejected":
        return this.deny(by, "agent.transition", agentId, ["agents are rejected only through security review"], ctx, { from, to });
    }
    return this.deny(by, "agent.transition", agentId, [`unsupported transition to ${to}`], ctx, { from, to });
  }

  /** Terminal. Owners, security and admins may retire; credentials are revoked. */
  retire(agentId: string, by: string, reason: string, ctx: Ctx = {}): ActionResult<{ agent: Agent }> {
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(by);
    const v: string[] = [];
    if (!agent) v.push(`unknown agent ${agentId}`);
    else if (!(hasRole(user, "admin", "security_reviewer") || (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail))))) v.push("not permitted to retire this agent");
    else if (!canTransition(agent.lifecycleState, "retired")) v.push(`illegal lifecycle transition: ${agent.lifecycleState} -> retired`);
    if (v.length || !agent) return this.deny(by, "agent.retire", agentId, v, ctx);
    const updated = this.registry.retire(agentId, reason, by);
    this.revokeCredentials(agentId, "agent_retired", ctx);
    return { ok: true, agent: updated };
  }

  /** Owner/sub-owner confirm the agent is still needed: expiry moves to now +
   * the certification period. An agent the sweep suspended for expiry (within
   * the grace window) is reactivated and gets a fresh one-time credential. */
  recertify(agentId: string, by: string, ctx: Ctx = {}): ActionResult<{ agent: Agent; credential?: IssuedCredential }> {
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(by);
    const v: string[] = [];
    const now = this.now();
    if (!agent) v.push(`unknown agent ${agentId}`);
    else {
      if (!(hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail)))) v.push("only the agent's owner or sub-owner may recertify it");
      const owner = this.directory.lookup(agent.ownerEmail);
      if (!owner?.active) v.push("the agent's owner is no longer active; assign a new owner before recertifying");
      const expiredSuspended = agent.lifecycleState === "suspended" && agent.suspendedReason === "expired";
      if (agent.lifecycleState !== "active" && !expiredSuspended) v.push(`agent is "${agent.lifecycleState}"${agent.lifecycleState === "suspended" ? ` (${agent.suspendedReason ?? "suspended"})` : ""}; only active or expiry-suspended agents can be recertified`);
      if (expiredSuspended && now.getTime() - new Date(agent.expiresAt).getTime() > this.recertGraceDays * DAY_MS) {
        v.push(`agent expired more than ${this.recertGraceDays} days ago; it needs a fresh security review`);
      }
    }
    if (v.length || !agent) return this.deny(by, "agent.recertify", agentId, v, ctx);
    const expiresAt = new Date(now.getTime() + this.certificationDays * DAY_MS).toISOString();
    let updated = this.registry.recertify(agentId, expiresAt, by);
    let credential: IssuedCredential | undefined;
    if (updated.lifecycleState === "suspended") {
      updated = this.registry.transition(agentId, "active", by, "recertified after expiry");
      credential = this.issueCredential(agentId, "recertification", ctx);
    } else {
      // Credential lifetime follows certification: no forced rotation on recertify.
      const extended = this.credentials.extendAgentCredentials(agentId, expiresAt);
      if (extended) {
        this.audit.append({
          stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.extend", targetType: "agent", targetId: agentId,
          outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { count: extended, expiresAt, via: "recertification" },
        });
      }
    }
    this.audit.append({
      stream: "user", actorType: "user", actorId: by, action: "agent.recertify", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { previousExpiresAt: agent.expiresAt, expiresAt, reactivated: Boolean(credential) },
    });
    return { ok: true, agent: updated, credential };
  }

  /** Suspends every active agent past its expiry and revokes its credentials.
   * Run by the scheduler; safe to run at any time and any number of times. */
  expirySweep(ctx: Ctx = {}): Agent[] {
    const out: Agent[] = [];
    for (const a of this.registry.list()) {
      if (a.lifecycleState !== "active" || !this.registry.isExpired(a)) continue;
      const updated = this.registry.transition(a.id, "suspended", "system:expiry-sweep", "expired");
      this.revokeCredentials(a.id, "agent_expired", ctx);
      this.audit.append({
        stream: "audit", actorType: "system", actorId: "system:expiry-sweep", action: "agent.expired", targetType: "agent", targetId: a.id,
        outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { expiresAt: a.expiresAt, owner: a.ownerEmail },
      });
      out.push(updated);
    }
    return out;
  }

  /** Active agents whose expiry falls within the next `days` days (not yet expired). */
  expiringWithin(days = 14): Agent[] {
    const now = this.now().getTime();
    const horizon = now + days * DAY_MS;
    return this.registry.list()
      .filter((a) => a.lifecycleState === "active")
      .filter((a) => { const t = new Date(a.expiresAt).getTime(); return t > now && t <= horizon; })
      .sort((a, b) => a.expiresAt.localeCompare(b.expiresAt));
  }

  review(
    agentId: string,
    reviewer: string,
    decision: "approve" | "reject",
    checklist: Record<string, boolean>,
    notes: string | undefined,
    ctx: Ctx = {},
  ): ActionResult<{ agent: Agent; credential?: IssuedCredential }> {
    const v: string[] = [];
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(reviewer);

    if (!agent) v.push(`unknown agent ${agentId}`);
    else if (agent.lifecycleState !== "pending_approval") v.push(`agent is "${agent.lifecycleState}", not awaiting review`);
    if (!hasRole(user, "security_reviewer")) v.push("reviewer must hold the security_reviewer role");
    if (agent && (same(reviewer, agent.ownerEmail) || same(reviewer, agent.subOwnerEmail) || same(reviewer, agent.registeredBy))) {
      v.push("separation of duties: the owner, sub-owner or submitter cannot review their own agent");
    }
    if (decision === "approve") {
      const missing = REQUIRED_REVIEW_CHECKLIST.filter((k) => checklist?.[k] !== true);
      if (missing.length) v.push(`checklist incomplete: ${missing.join(", ")}`);
    }
    if (v.length > 0 || !agent) {
      this.audit.append({
        stream: "user", actorType: "user", actorId: reviewer, action: "agent.review", targetType: "agent", targetId: agentId,
        outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { decision, violations: v },
      });
      return { ok: false, violations: v };
    }

    const review = { status: decision === "approve" ? ("approved" as const) : ("rejected" as const), reviewer, decidedAt: new Date().toISOString(), checklist, notes };
    if (decision === "reject") {
      const updated = this.registry.reject(agentId, notes ?? "rejected by security review", reviewer, review);
      this.audit.append({
        stream: "user", actorType: "user", actorId: reviewer, action: "agent.review", targetType: "agent", targetId: agentId,
        outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { decision, notes },
      });
      return { ok: true, agent: updated };
    }

    const updated = this.registry.approve(agentId, reviewer, review);
    const credential = this.credentials.issueAgentCredential(agentId);
    this.audit.append({
      stream: "user", actorType: "user", actorId: reviewer, action: "agent.review", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { decision, checklist, notes },
    });
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.issue", targetType: "agent", targetId: agentId,
      outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { keyId: credential.keyId, expiresAt: credential.expiresAt, via: "security_review" },
    });
    return { ok: true, agent: updated, credential };
  }

  /** Suspends an agent AND revokes its credentials, so the gateway stops
   * accepting it immediately rather than only at the next policy check. */
  suspend(agentId: string, by: string, reason: string, ctx: Ctx = {}): ActionResult<{ agent: Agent }> {
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(by);
    const allowed = agent && (hasRole(user, "admin", "security_reviewer") || (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail))));
    const legal = agent && canTransition(agent.lifecycleState, "suspended");
    if (!agent || !allowed || !legal) {
      const violations = [!agent ? `unknown agent ${agentId}` : !allowed ? "not permitted to suspend this agent" : `illegal lifecycle transition: ${agent.lifecycleState} -> suspended`];
      this.audit.append({ stream: "user", actorType: "user", actorId: by, action: "agent.suspend", targetType: "agent", targetId: agentId, outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { violations } });
      return { ok: false, violations };
    }
    const updated = this.registry.suspend(agentId, reason, by);
    const revoked = this.credentials.revokeAll("agent", agentId, "agent_suspended");
    this.audit.append({ stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.revoke", targetType: "agent", targetId: agentId, outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { count: revoked, reason: "agent_suspended" } });
    return { ok: true, agent: updated };
  }

  rotateCredential(agentId: string, by: string, ctx: Ctx = {}): ActionResult<{ credential: IssuedCredential }> {
    const agent = this.registry.get(agentId);
    const user = this.directory.lookup(by);
    const allowed = agent && (hasRole(user, "admin") || (hasRole(user, "agent_owner") && (same(by, agent.ownerEmail) || same(by, agent.subOwnerEmail))));
    const violations: string[] = [];
    if (!agent) violations.push(`unknown agent ${agentId}`);
    else if (!allowed) violations.push("not permitted to rotate this agent's credential");
    else if (agent.lifecycleState !== "active") violations.push(`agent is "${agent.lifecycleState}"; only active agents have credentials`);
    if (violations.length) {
      this.audit.append({ stream: "user", actorType: "user", actorId: by, action: "credential.rotate", targetType: "agent", targetId: agentId, outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { violations } });
      return { ok: false, violations };
    }
    const credential = this.credentials.rotateAgentCredential(agentId, "rotated");
    this.audit.append({ stream: "user", actorType: "user", actorId: by, action: "credential.rotate", targetType: "agent", targetId: agentId, outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { keyId: credential.keyId, expiresAt: credential.expiresAt } });
    return { ok: true, credential };
  }
}

function stripUndefined<T extends object>(o: T): Partial<T> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Partial<T>;
}
