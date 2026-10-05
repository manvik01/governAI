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
  /** Start in pending_approval even if the computed risk tier would not require it. */
  forcePendingReview?: boolean;
}

export type RegistryChange = {
  action: "agent.registered" | "agent.approved" | "agent.rejected" | "agent.suspended" | "agent.retired";
  agentId: string;
  /** Email of the human, or "system:..." for automated changes. */
  actor: string;
  details: Record<string, unknown>;
};

export class AgentRegistry {
  private db: Database.Database;
  private listener?: (c: RegistryChange) => void;

  constructor(db?: Database.Database) {
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
    // budget policy. Refuse to register one that is missing any.
    if (!input.ownerEmail?.trim()) throw new Error("Agent registration requires an owner");
    if (!input.purpose?.trim()) throw new Error("Agent registration requires an approved purpose");
    if (!input.budgetPolicy) throw new Error("Agent registration requires a budget policy");
    for (const [k, v] of Object.entries(input.budgetPolicy)) {
      if (v !== undefined && (!Number.isInteger(v) || v < 0)) {
        throw new Error(`budgetPolicy.${k} must be a non-negative integer (micro-USD)`);
      }
    }
    const permittedModels = input.permittedModels ?? [input.modelVersion];
    if (permittedModels.length === 0) throw new Error("Agent registration requires at least one permitted model");

    const id = nanoid();
    const now = new Date();
    const expires = new Date(now);
    expires.setDate(expires.getDate() + (input.expiresInDays ?? 90));

    const riskTier = calculateRiskTier(input.tools, input.autonomyDefault);
    // High/critical agents (or any flagged for review) start pending approval;
    // others start active.
    const needsReview = riskTier === "high" || riskTier === "critical" || input.forcePendingReview === true;
    const lifecycleState: LifecycleState = needsReview ? "pending_approval" : "active";

    const agent: Agent = {
      id,
      name: input.name,
      purpose: input.purpose,
      ownerEmail: input.ownerEmail,
      subOwnerEmail: input.subOwnerEmail,
      accessProfileId: input.accessProfileId,
      registeredBy: input.registeredBy,
      securityReview: needsReview ? { status: "pending" } : undefined,
      businessUnit: input.businessUnit,
      platform: input.platform,
      modelProvider: input.modelProvider,
      modelVersion: input.modelVersion,
      riskTier,
      permittedModels,
      budgetPolicy: input.budgetPolicy,
      autonomyDefault: input.autonomyDefault,
      lifecycleState,
      mode: input.mode,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
    };

    const tx = this.db.transaction(() => {
      this.db.prepare(`INSERT INTO agents (id, data) VALUES (?, ?)`).run(id, JSON.stringify(agent));
      for (const t of input.tools) {
        this.db
          .prepare(`INSERT INTO agent_grants (agent_id, tool_name, data) VALUES (?, ?, ?)`)
          .run(id, t.toolName, JSON.stringify({ ...t, agentId: id }));
      }
    });
    tx.immediate();

    this.emit({
      action: "agent.registered",
      agentId: id,
      actor: input.registeredBy ?? input.ownerEmail,
      details: { name: input.name, owner: input.ownerEmail, subOwner: input.subOwnerEmail, riskTier, lifecycleState, accessProfileId: input.accessProfileId },
    });
    return agent;
  }

  private write(agent: Agent) {
    this.db.prepare(`UPDATE agents SET data = ? WHERE id = ?`).run(JSON.stringify(agent), agent.id);
  }

  approve(agentId: string, actor = "system", review?: SecurityReview): Agent {
    const agent = this.mustGet(agentId);
    agent.lifecycleState = "active";
    if (review) agent.securityReview = review;
    this.write(agent);
    this.emit({ action: "agent.approved", agentId, actor, details: { review: review ? { reviewer: review.reviewer, checklist: review.checklist } : undefined } });
    return agent;
  }

  reject(agentId: string, reason: string, actor: string, review?: SecurityReview): Agent {
    const agent = this.mustGet(agentId);
    agent.lifecycleState = "rejected";
    if (review) agent.securityReview = review;
    this.write(agent);
    this.emit({ action: "agent.rejected", agentId, actor, details: { reason } });
    return agent;
  }

  suspend(agentId: string, reason: string, actor = "system"): Agent {
    const agent = this.mustGet(agentId);
    agent.lifecycleState = "suspended";
    this.write(agent);
    this.emit({ action: "agent.suspended", agentId, actor, details: { reason } });
    return agent;
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

  isActive(agentId: string): boolean {
    return this.get(agentId)?.lifecycleState === "active";
  }

  list(): Agent[] {
    return (this.db.prepare(`SELECT data FROM agents ORDER BY rowid`).all() as any[]).map((r) => JSON.parse(r.data));
  }
}

/** Simple deterministic risk scoring: any irreversible tool touching money or
 * PII, or full autonomy, pushes an agent to high/critical. This is the
 * starting rule set from the product spec's risk-tier section; replace with
 * a scored questionnaire once real customer data is available. */
export function calculateRiskTier(
  tools: Omit<ToolGrant, "agentId">[],
  autonomy: AutonomyLevel,
): RiskTier {
  const touchesMoney = tools.some((t) => t.dataClasses.includes("financial"));
  const touchesPii = tools.some((t) => t.dataClasses.includes("customer_pii"));
  const hasIrreversible = tools.some((t) => !t.reversible);

  if (autonomy === "A4" && (touchesMoney || hasIrreversible)) return "critical";
  if (touchesMoney && hasIrreversible) return "high";
  if (touchesMoney || touchesPii) return "medium";
  return "low";
}
