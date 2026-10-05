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

import type { AuditLog } from "./audit-log.js";
import type { CredentialService } from "./credentials.js";
import { hasRole, type IdentityDirectory } from "./identity.js";
import { profileViolations, type AccessProfileStore } from "./access-profiles.js";
import type { AgentRegistry, RegisterAgentInput } from "../registry/registry.js";
import type { Agent, AutonomyLevel, GovernanceMode, BudgetPolicy, ToolGrant } from "../types.js";

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

export class RegistrationService {
  constructor(
    private registry: AgentRegistry,
    private directory: IdentityDirectory,
    private profiles: AccessProfileStore,
    private credentials: CredentialService,
    private audit: AuditLog,
  ) {}

  submit(req: RegistrationRequest, submittedBy: string, ctx: Ctx = {}): SubmitResult {
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
    if (submitter?.active && !same(submittedBy, req.ownerEmail) && !same(submittedBy, req.subOwnerEmail) && !hasRole(submitter, "admin")) {
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

    let agent: Agent | undefined;
    if (v.length === 0 && profile) {
      try {
        const input: RegisterAgentInput = { ...req, registeredBy: submittedBy, forcePendingReview: profile.requiresSecurityReview };
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
    if (!needsReview) {
      credential = this.credentials.issueAgentCredential(agent.id);
      this.audit.append({
        stream: "audit", actorType: "system", actorId: "registration-service", action: "credential.issue", targetType: "agent", targetId: agent.id,
        outcome: "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { keyId: credential.keyId, expiresAt: credential.expiresAt, via: "auto_activation" },
      });
    }
    return { ok: true, agent, credential, needsReview };
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
    if (!agent || !allowed) {
      const violations = [!agent ? `unknown agent ${agentId}` : "not permitted to suspend this agent"];
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
