// Context Layer domain types.
//
// Everything an agent needs to act — the workflow it's executing, the
// persona it's acting as, the conditions/policies that gate it, the goal
// it serves, the milestones/timeline it's tracked against — is modeled as
// a first-class, queryable entity here. None of this is ever held only in
// an LLM's conversational memory: every entity is a row, versioned, with a
// source and a validity window, exactly like the evidence ledger treats
// action events. An agent "knows" a fact only because it just read it.

export type ContextKind =
  | "workflow" // an end-to-end process definition: ordered steps, each with an owning role
  | "persona" // who/what an agent is acting as: voice, authority limits, audience
  | "condition" // a precondition/guard that must hold before a step can run
  | "policy" // a decision-matrix rule: structured condition -> action, versioned
  | "goal" // a business objective a workflow run is in service of
  | "milestone" // a checkpoint within a goal, with a target state and due date
  | "timeline" // a scheduled or observed event tied to a goal/milestone
  | "fact"; // any other current-state fact (account, deal, KPI input, etc.)

export interface WorkflowStep {
  id: string; // stable within the workflow, e.g. "qualify", "quote", "close"
  title: string;
  role: string; // which sub-agent role owns this step, e.g. "sales", "finance"
  dependsOn: string[]; // step ids that must be "done" before this step is "ready"
  requiredConditions: string[]; // condition entity ids that must hold
}

export interface WorkflowDef {
  id: string;
  domain: string; // "sales" | "ops" | "finance" | "marketing" | "governance" | ...
  title: string;
  steps: WorkflowStep[];
}

export interface PersonaDef {
  id: string;
  domain: string;
  role: string; // sub-agent role this persona applies to
  title: string;
  voice: string; // how it communicates
  authorityLimits: string[]; // plain-language limits, enforced separately by policy rows
}

export interface ConditionDef {
  id: string;
  domain: string;
  title: string;
  // A structured predicate, evaluated in code against current context facts —
  // never left to an LLM to judge from memory. Shape is deliberately generic
  // (path/op/value) so the evaluator in matrix.ts can walk it without knowing
  // what business object it describes.
  predicate: { path: string; op: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "in" | "exists"; value?: unknown };
}

export interface PolicyRuleDef {
  id: string;
  domain: string;
  ruleType: "routing" | "autonomy_gate" | "triage_priority" | "approval_threshold";
  version: number;
  // All conditions must hold (AND) for the rule to match. First-match-wins,
  // evaluated in the order rules were inserted for the domain+ruleType.
  when: ConditionDef["predicate"][];
  action: Record<string, unknown>; // e.g. { route: "finance", autonomy: "A2" } or { decision: "hold_for_approval" }
}

export interface GoalDef {
  id: string;
  domain: string;
  title: string;
  ownerPersona: string; // persona id accountable for this goal
  workflowId: string;
  targetMetric?: string; // which KPI this goal moves
  targetValue?: number;
  dueDate?: string;
}

export interface MilestoneDef {
  id: string;
  goalId: string;
  title: string;
  targetDate: string;
  status: "pending" | "at_risk" | "met" | "missed";
}

export interface TimelineEventDef {
  id: string;
  goalId: string;
  milestoneId?: string;
  label: string;
  occurredAt: string; // ISO — either scheduled (future) or observed (past)
  kind: "scheduled" | "observed";
}

/** The envelope every context entity is stored in, whatever its kind. */
export interface ContextEntity<T = unknown> {
  rowId: string; // storage row id (unique per version)
  entityId: string; // logical id, stable across versions (WorkflowDef.id, etc.)
  kind: ContextKind;
  domain: string;
  data: T;
  version: number;
  source: string; // 'stated' | 'discovery_call' | 'crm' | 'ingest:<tool>' | 'computed'
  confidence?: number;
  validFrom: string;
  validTo?: string;
  createdAt: string;
}
