// Core domain types for the agent governance control plane.
// These mirror the data model in the product spec doc: Agent, Owner, Principal,
// Tool (Capability), Policy, Run, Action Event, Approval.

export type LifecycleState =
  | "draft"
  | "pending_approval"
  | "active"
  | "suspended"
  | "retired";

export type RiskTier = "low" | "medium" | "high" | "critical";

export type AutonomyLevel = "A0" | "A1" | "A2" | "A3" | "A4";

export type GovernanceMode = "enforcement" | "posture";

/** Per-agent budget policy, set at registration. All amounts are integer
 * micro-USD (1 USD = 1_000_000) so budget arithmetic never touches floats.
 * A level left undefined means "no limit at this level from this agent's
 * policy" — org/project limits set by administrators still apply. */
export interface BudgetPolicy {
  /** Cap on everything this agent spends across all tasks. */
  agentLimitMicro?: number;
  /** Default cap applied to each new root task this agent originates. */
  defaultTaskLimitMicro?: number;
}

export interface Agent {
  id: string;
  name: string;
  purpose: string;
  ownerEmail: string;
  businessUnit: string;
  platform: string; // e.g. "custom", "copilot-studio", "gemini-enterprise"
  modelProvider: string; // e.g. "anthropic", "openai", "google"
  modelVersion: string;
  riskTier: RiskTier;
  /** Models this agent may invoke. A call naming any other model is blocked
   * before it reaches a provider — including fallback models. */
  permittedModels: string[];
  budgetPolicy: BudgetPolicy;
  autonomyDefault: AutonomyLevel;
  lifecycleState: LifecycleState;
  mode: GovernanceMode;
  createdAt: string;
  expiresAt: string;
}

export interface ToolGrant {
  agentId: string;
  toolName: string; // e.g. "issue_refund", "read_invoice"
  reversible: boolean;
  dataClasses: string[]; // e.g. ["customer_pii", "financial"]
}

export type Decision = "allow" | "deny" | "hold_for_approval";

export interface ActionRequest {
  agentId: string;
  principal: string; // human or system this agent acts on behalf of
  toolName: string;
  parameters: Record<string, unknown>;
  delegationChain?: string[]; // agent ids in the call chain, if any
}

export interface PolicyDecisionResult {
  decision: Decision;
  reason: string;
  policyId: string;
  policyVersion: number;
  ruleTriggered?: string;
}

export interface ActionEvent {
  id: string;
  runId: string;
  agentId: string;
  principal: string;
  toolName: string;
  parametersRedacted: string; // JSON string, sensitive fields hashed
  decision: Decision;
  policyId: string;
  policyVersion: number;
  ruleTriggered?: string;
  latencyMs: number;
  timestamp: string;
  prevHash: string;
  hash: string;
  approvalId?: string;
}

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired";

export interface Approval {
  id: string;
  actionEventId: string;
  approver?: string;
  status: ApprovalStatus;
  requestedAt: string;
  decidedAt?: string;
  reason?: string;
}
