// Agent Registry: the source of truth for every agent, its owners, tools and
// lifecycle state. Persisted in SQLite (pass the control plane's shared
// connection, or nothing for an isolated in-memory registry), so agents and
// their lifecycle survive a restart. In the full product this is backed by
// Postgres and fed by discovery connectors (Entra/Okta, agent platforms,
// GitHub).
//
// Every state change is announced through an optional change listener, so
// the control plane can write an audit-log entry no matter which code path
// made the change - registry mutations cannot bypass the audit trail.
//
// Lifecycle (phase 1): draft -> pending_approval -> active -> suspended ->
// retired, plus rejected. Every state change goes through transition(),
// which refuses anything not in LIFECYCLE_TRANSITIONS, so no caller can, for
// example, revive a retired agent. "Active" also means "not expired": an
// agent past expiresAt is refused by isActive() even before the expiry sweep
// has suspended it, so the gateway never depends on a background job.
//
// Risk tier: computedRiskTier is what the rules derive from tools, data
// classes and autonomy; riskOverride is a recorded human decision; riskTier
// is the effective tier everything else reads (see effectiveRiskTier).

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type {
  Agent,
  BudgetPolicy,
  AutonomyLevel,
  GovernanceMode,
  LifecycleState,
  RiskTier,
  SecurityReview,
  RiskOverride,
  ToolGrant,
} from "../types.js";

export interface RegisterAgentInput {
  name: string;
  purpose: string;
  ownerEmail: string;
  /** Deputy owner. Optional at this low level; the RegistrationService requires it. */
  subOwnerEmail?: string;
  accessProfileId?: string;
  registeredBy?: string;
  businessUnit: string;
  platform: string;
  modelProvider: string;
  modelVersion: string;
  autonomyDefault: AutonomyLevel;
  mode: GovernanceMode;
  tools: Omit<ToolGrant, "agentId">[];
  /** Models the agent may call. Defaults to just `modelVersion`. */
  permittedModels?: string[];
  /** Required: an agent cannot be registered without a budget policy. */
  budgetPolicy: BudgetPolicy;
  expiresInDays?: number;
  /** Explicit expiry instant (ISO). Wins over expiresInDays. */
  expiresAt?: string;
  /** Start in pending_approval even if the computed risk tier would not require it. */
  forcePendingReview?: boolean;
  /** Create a draft: incomplete fields allowed, cannot act until submitted. */
  draft?: boolean;
  manifestId?: string;
  manifestHash?: string;
  discoveryId?: string;
}

/** Fields an update (manifest re-apply, draft completion) may change. */
export type AgentUpdate = Partial<
  Pick<
    Agent,
    | "name" | "purpose" | "ownerEmail" | "subOwnerEmail" | "accessProfileId" | "businessUnit" | "platform"
    | "modelProvider" | "modelVersion" | "permittedModels" | "budgetPolicy" | "autonomyDefault" | "mode"
    | "expiresAt" | "manifestHash" | "registeredBy" | "securityReview"
  >
> & { tools?: Omit<ToolGrant, "agentId">[] };

/** The only lifecycle moves the registry will make. Retired is terminal. */
export const LIFECYCLE_TRANSITIONS: Record<LifecycleState, readonly LifecycleState[]> = {
  draft: ["pending_approval", "active", "retired"],
  pending_approval: ["active", "rejected", "retired"],
  // active -> pending_approval: widened access or a raised tier needs a fresh security review
  active: ["suspended", "retired", "pending_approval"],
  // suspended -> active: recertification of an expired agent (gated in the service)
  suspended: ["active", "retired", "pending_approval"],
  rejected: ["draft", "retired"],
  retired: [],
};

export function canTransition(from: LifecycleState, to: LifecycleState): boolean {
  return LIFECYCLE_TRANSITIONS[from]?.includes(to) ?? false;
}

export class IllegalTransitionError extends Error {
  constructor(public from: LifecycleState, public to: LifecycleState) {
    super(`illegal lifecycle transition: ${from} -> ${to}`);
  }
}

export type RegistryChange = {
  action:
    | "agent.registered" | "agent.drafted" | "agent.approved" | "agent.rejected" | "agent.suspended" | "agent.retired"
    | "agent.transition" | "agent.updated" | "agent.risk_tier.changed" | "agent.recertified";
  agentId: string;
  /** Email of the human, or "system:..." for automated changes. */
  actor: string;
  details: Record<string, unknown>;
};

export class AgentRegistry {
  private db: Database.Database;
  private listener?: (c: RegistryChange) => void;

  private now: () => Date;

  constructor(db?: Database.Database, now: () => Date = () => new Date()) {
    this.now = now;
    this.db = db ?? new Database(":memory:");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS agent_grants (agent_id TEXT NOT NULL, tool_name TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (agent_id, tool_name));
    `);
  }

  /** Subscribes to every registry state change (used for audit logging). */
  setChangeListener(fn: (c: RegistryChange) => void) {
    this.listener = fn;
  }

  private emit(c: RegistryChange) {
    try {
      this.listener?.(c);
    } catch {
      /* audit transport failures must not corrupt registry state */
    }
  }

  register(input: RegisterAgentInput): Agent {
    // Every agent has an owner, an approved purpose, permitted models and a
    // budget policy. Refuse to register one that is missing any. A draft only
    // needs an owner: the rest is checked when it is submitted.
    const draft = input.draft === true;
    if (!input.ownerEmail?.trim()) throw new Error("Agent registration requires an owner");
    if (!draft && !input.purpose?.trim()) throw new Error("Agent registration requires an approved purpose");
    if (!draft && !input.budgetPolicy) throw new Error("Agent registration requires a budget policy");
    for (const [k, v] of Object.entries(input.budgetPolicy ?? {})) {
      if (v !== undefined && (!Number.isInteger(v) || v < 0)) {
        throw new Error(`budgetPolicy.${k} must be a non-negative integer (micro-USD)`);
      }
    }
    const permittedModels = input.permittedModels ?? (input.modelVersion ? [input.modelVersion] : []);
    if (!draft && permittedModels.length === 0) throw new Error("Agent registration requires at least one permitted model");

    const id = nanoid();
    const now = this.now();
    let expiresAt: string;
    if (input.expiresAt) {
      const t = new Date(input.expiresAt);
      if (Number.isNaN(t.getTime())) throw new Error("expiresAt is not a valid date");
      expiresAt = t.toISOString();
    } else {
      const expires = new Date(now);
      expires.setDate(expires.getDate() + (input.expiresInDays ?? 90));
      expiresAt = expires.toISOString();
    }

    const computed = calculateRiskTier(input.tools, input.autonomyDefault);
    // High/critical agents (or any flagged for review) start pending approval;
    // others start active. Drafts start as drafts whatever their tier.
    const needsReview = computed === "high" || computed === "critical" || input.forcePendingReview === true;
    const lifecycleState: LifecycleState = draft ? "draft" : needsReview ? "pending_approval" : "active";

    const agent: Agent = {
      id,
      name: input.name,
      purpose: input.purpose ?? "",
      ownerEmail: input.ownerEmail,
      subOwnerEmail: input.subOwnerEmail,
      accessProfileId: input.accessProfileId,
      registeredBy: input.registeredBy,
      securityReview: !draft && needsReview ? { status: "pending" } : undefined,
      businessUnit: input.businessUnit,
      platform: input.platform,
      modelProvider: input.modelProvider,
      modelVersion: input.modelVersion,
      riskTier: computed,
      computedRiskTier: computed,
      permittedModels,
      budgetPolicy: input.budgetPolicy ?? {},
      autonomyDefault: input.autonomyDefault,
      lifecycleState,
      mode: input.mode,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt,
      manifestId: input.manifestId,
      manifestHash: input.manifestHash,
      discoveryId: input.discoveryId,
    };

    const tx = this.db.transaction(() => {
      this.db.prepare(`INSERT INTO agents (id, data) VALUES (?, ?)`).run(id, JSON.stringify(agent));
      this.writeGrants(id, input.tools);
    });
    tx.immediate();

    this.emit({
      action: draft ? "agent.drafted" : "agent.registered",
      agentId: id,
      actor: input.registeredBy ?? input.ownerEmail,
      details: {
        name: input.name, owner: input.ownerEmail, subOwner: input.subOwnerEmail, riskTier: computed, lifecycleState,
        accessProfileId: input.accessProfileId, expiresAt, manifestId: input.manifestId, discoveryId: input.discoveryId,
      },
    });
    return agent;
  }

  private writeGrants(agentId: string, tools: Omit<ToolGrant, "agentId">[]) {
    this.db.prepare(`DELETE FROM agent_grants WHERE agent_id = ?`).run(agentId);
    for (const t of tools) {
      this.db
        .prepare(`INSERT INTO agent_grants (agent_id, tool_name, data) VALUES (?, ?, ?)`)
        .run(agentId, t.toolName, JSON.stringify({ ...t, agentId }));
    }
  }

  /** Moves an agent along the lifecycle. Throws IllegalTransitionError for any
   * move not in LIFECYCLE_TRANSITIONS. `patch` is applied in the same write. */
  transition(agentId: string, to: LifecycleState, actor: string, reason?: string, patch: Partial<Agent> = {}): Agent {
    const agent = this.mustGet(agentId);
    const from = agent.lifecycleState;
    if (!canTransition(from, to)) throw new IllegalTransitionError(from, to);
    const now = this.now().toISOString();
    Object.assign(agent, patch, { lifecycleState: to, updatedAt: now });
    if (to === "suspended") Object.assign(agent, { suspendedAt: now, suspendedReason: reason });
    if (to === "active") Object.assign(agent, { suspendedAt: undefined, suspendedReason: undefined });
    if (to === "retired") agent.retiredAt = now;
    this.write(agent);
    const named: Partial<Record<LifecycleState, RegistryChange["action"]>> = {
      active: from === "pending_approval" ? "agent.approved" : "agent.transition",
      rejected: "agent.rejected", suspended: "agent.suspended", retired: "agent.retired",
    };
    this.emit({ action: named[to] ?? "agent.transition", agentId, actor, details: { from, to, reason } });
    return agent;
  }

  /** Changes registration fields (and optionally replaces the tool grants).
   * Recomputes the risk tier; a security "lower" override is dropped if the
   * computed tier rises, because it was granted against narrower access. */
  update(agentId: string, upd: AgentUpdate, actor: string): Agent {
    const agent = this.mustGet(agentId);
    if (agent.lifecycleState === "retired") throw new IllegalTransitionError("retired", "retired");
    const { tools, ...fields } = upd;
    const before = { computed: agent.computedRiskTier ?? agent.riskTier, effective: agent.riskTier };
    Object.assign(agent, fields, { updatedAt: this.now().toISOString() });
    if (fields.modelVersion && !fields.permittedModels && !agent.permittedModels.includes(fields.modelVersion)) {
      agent.permittedModels = [fields.modelVersion];
    }
    const grants = tools ?? this.grantsFor(agentId).map(({ agentId: _a, ...t }) => t);
    const computed = calculateRiskTier(grants, agent.autonomyDefault);
    let droppedOverride = false;
    if (agent.riskOverride?.direction === "lower" && tierRank(computed) > tierRank(before.computed)) {
      agent.riskOverride = undefined;
      droppedOverride = true;
    }
    agent.computedRiskTier = computed;
    agent.riskTier = effectiveRiskTier(computed, agent.riskOverride);
    const tx = this.db.transaction(() => {
      this.write(agent);
      if (tools) this.writeGrants(agentId, tools);
    });
    tx.immediate();
    this.emit({
      action: "agent.updated", agentId, actor,
      details: { fields: Object.keys(fields), toolsReplaced: Boolean(tools), riskTier: agent.riskTier, computedRiskTier: computed, previousRiskTier: before.effective, droppedLowerOverride: droppedOverride || undefined },
    });
    return agent;
  }

  /** Records a human risk-tier decision. Authorisation is the service's job;
   * the registry only stores it and recomputes the effective tier. */
  setRiskOverride(agentId: string, override: RiskOverride | undefined, actor: string): Agent {
    const agent = this.mustGet(agentId);
    const previous = agent.riskTier;
    const computed = agent.computedRiskTier ?? calculateRiskTier(this.grantsFor(agentId), agent.autonomyDefault);
    agent.computedRiskTier = computed;
    agent.riskOverride = override;
    agent.riskTier = effectiveRiskTier(computed, override);
    agent.updatedAt = this.now().toISOString();
    this.write(agent);
    this.emit({ action: "agent.risk_tier.changed", agentId, actor, details: { previous, effective: agent.riskTier, computed, override } });
    return agent;
  }

  /** Sets a new expiry (recertification). */
  recertify(agentId: string, expiresAt: string, actor: string): Agent {
    const agent = this.mustGet(agentId);
    const previous = agent.expiresAt;
    const now = this.now().toISOString();
    Object.assign(agent, { expiresAt, lastRecertifiedAt: now, recertifiedBy: actor, updatedAt: now });
    this.write(agent);
    this.emit({ action: "agent.recertified", agentId, actor, details: { previousExpiresAt: previous, expiresAt } });
    return agent;
  }

  private write(agent: Agent) {
    this.db.prepare(`UPDATE agents SET data = ? WHERE id = ?`).run(JSON.stringify(agent), agent.id);
  }

  approve(agentId: string, actor = "system", review?: SecurityReview): Agent {
    const agent = this.transition(agentId, "active", actor, undefined, review ? { securityReview: review } : {});
    return agent;
  }

  reject(agentId: string, reason: string, actor: string, review?: SecurityReview): Agent {
    return this.transition(agentId, "rejected", actor, reason, review ? { securityReview: review } : {});
  }

  suspend(agentId: string, reason: string, actor = "system"): Agent {
    return this.transition(agentId, "suspended", actor, reason);
  }

  retire(agentId: string, reason: string, actor: string): Agent {
    return this.transition(agentId, "retired", actor, reason);
  }

  get(agentId: string): Agent | undefined {
    const r = this.db.prepare(`SELECT data FROM agents WHERE id = ?`).get(agentId) as any;
    return r ? (JSON.parse(r.data) as Agent) : undefined;
  }

  private mustGet(agentId: string): Agent {
    const agent = this.get(agentId);
    if (!agent) throw new Error(`Unknown agent: ${agentId}`);
    return agent;
  }

  grantsFor(agentId: string): ToolGrant[] {
    return (this.db.prepare(`SELECT data FROM agent_grants WHERE agent_id = ? ORDER BY tool_name`).all(agentId) as any[]).map((r) => JSON.parse(r.data));
  }

  /** Active AND not past its expiry. Expiry is enforced here so every
   * caller (gateway auth, policy engine, model gateway) refuses an expired
   * agent even before the expiry sweep has suspended it. */
  isActive(agentId: string): boolean {
    const a = this.get(agentId);
    return a?.lifecycleState === "active" && !this.isExpired(a);
  }

  isExpired(agent: Agent): boolean {
    return new Date(agent.expiresAt).getTime() <= this.now().getTime();
  }

  findByManifestId(manifestId: string): Agent | undefined {
    const r = this.db.prepare(`SELECT data FROM agents WHERE json_extract(data, '$.manifestId') = ?`).get(manifestId) as any;
    return r ? (JSON.parse(r.data) as Agent) : undefined;
  }

  list(): Agent[] {
    return (this.db.prepare(`SELECT data FROM agents ORDER BY rowid`).all() as any[]).map((r) => JSON.parse(r.data));
  }
}

export const RISK_TIERS: readonly RiskTier[] = ["low", "medium", "high", "critical"];
export const tierRank = (t: RiskTier) => RISK_TIERS.indexOf(t);
export const maxTier = (a: RiskTier, b: RiskTier): RiskTier => (tierRank(a) >= tierRank(b) ? a : b);

/** Effective tier: an owner "raise" can only add risk (max of the two); a
 * security "lower" replaces the computed tier with the reviewer's value. */
export function effectiveRiskTier(computed: RiskTier, override?: RiskOverride): RiskTier {
  if (!override) return computed;
  return override.direction === "raise" ? maxTier(computed, override.tier) : override.tier;
}

/** Data classes that mean money or personal data. Names are normalised to
 * lower case; anything else is treated as non-sensitive for scoring. */
export const MONEY_CLASSES = new Set(["financial", "payments", "payment_card", "money", "banking"]);
export const PERSONAL_CLASSES = new Set(["customer_pii", "pii", "personal_data", "employee_pii", "health", "health_records", "biometric"]);

/** Deterministic risk scoring from the four signals in the product spec:
 * money, personal data, irreversible actions and autonomy.
 *   critical: A4 with money or irreversible actions; or A3+ with money AND irreversible
 *   high:     money AND irreversible; personal data AND irreversible; or A4
 *   medium:   any one of money, personal data, irreversible, or A3
 *   low:      none of the above
 * Replace with a scored questionnaire once real customer data is available. */
export function calculateRiskTier(
  tools: Omit<ToolGrant, "agentId">[],
  autonomy: AutonomyLevel | undefined,
): RiskTier {
  const classes = tools.flatMap((t) => t.dataClasses.map((d) => d.toLowerCase()));
  const touchesMoney = classes.some((d) => MONEY_CLASSES.has(d));
  const touchesPii = classes.some((d) => PERSONAL_CLASSES.has(d));
  const hasIrreversible = tools.some((t) => !t.reversible);
  const a = autonomy ?? "A0";
  const highAutonomy = a === "A3" || a === "A4";

  if (a === "A4" && (touchesMoney || hasIrreversible)) return "critical";
  if (highAutonomy && touchesMoney && hasIrreversible) return "critical";
  if ((touchesMoney || touchesPii) && hasIrreversible) return "high";
  if (a === "A4") return "high";
  if (touchesMoney || touchesPii || hasIrreversible || highAutonomy) return "medium";
  return "low";
}
