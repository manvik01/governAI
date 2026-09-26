// Agent Registry: the source of truth for every agent, its owner, tools and
// lifecycle state. In the full product this is backed by Postgres and fed by
// discovery connectors (Entra/Okta, agent platforms, GitHub). For the demo,
// it is in-memory and seeded/registered directly.

import { nanoid } from "nanoid";
import type {
  Agent,
  AutonomyLevel,
  GovernanceMode,
  LifecycleState,
  RiskTier,
  ToolGrant,
} from "../types.js";

export interface RegisterAgentInput {
  name: string;
  purpose: string;
  ownerEmail: string;
  businessUnit: string;
  platform: string;
  modelProvider: string;
  modelVersion: string;
  autonomyDefault: AutonomyLevel;
  mode: GovernanceMode;
  tools: Omit<ToolGrant, "agentId">[];
  expiresInDays?: number;
}

export class AgentRegistry {
  private agents = new Map<string, Agent>();
  private grants = new Map<string, ToolGrant[]>(); // agentId -> grants

  register(input: RegisterAgentInput): Agent {
    const id = nanoid();
    const now = new Date();
    const expires = new Date(now);
    expires.setDate(expires.getDate() + (input.expiresInDays ?? 90));

    const riskTier = calculateRiskTier(input.tools, input.autonomyDefault);
    // High/critical agents start pending approval; low/medium start active.
    const lifecycleState: LifecycleState =
      riskTier === "high" || riskTier === "critical" ? "pending_approval" : "active";

    const agent: Agent = {
      id,
      name: input.name,
      purpose: input.purpose,
      ownerEmail: input.ownerEmail,
      businessUnit: input.businessUnit,
      platform: input.platform,
      modelProvider: input.modelProvider,
      modelVersion: input.modelVersion,
      riskTier,
      autonomyDefault: input.autonomyDefault,
      lifecycleState,
      mode: input.mode,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
    };

    this.agents.set(id, agent);
    this.grants.set(
      id,
      input.tools.map((t) => ({ ...t, agentId: id })),
    );

    return agent;
  }

  approve(agentId: string): Agent {
    const agent = this.mustGet(agentId);
    agent.lifecycleState = "active";
    return agent;
  }

  suspend(agentId: string, _reason: string): Agent {
    const agent = this.mustGet(agentId);
    agent.lifecycleState = "suspended";
    return agent;
  }

  get(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  private mustGet(agentId: string): Agent {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Unknown agent: ${agentId}`);
    return agent;
  }

  grantsFor(agentId: string): ToolGrant[] {
    return this.grants.get(agentId) ?? [];
  }

  isActive(agentId: string): boolean {
    return this.agents.get(agentId)?.lifecycleState === "active";
  }

  list(): Agent[] {
    return [...this.agents.values()];
  }
}

/** Simple deterministic risk scoring: any irreversible tool touching money or
 * PII, or full autonomy, pushes an agent to high/critical. This is the
 * starting rule set from the product spec's risk-tier section; replace with
 * a scored questionnaire once real customer data is available. */
function calculateRiskTier(
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
