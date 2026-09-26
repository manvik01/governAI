// Policy Engine: decides allow / deny / hold_for_approval for a single tool
// call. This is the module the product spec calls the main technical
// differentiator, because it evaluates STATEFUL rules (velocity, cumulative
// value) in addition to ordinary per-call parameter rules.
//
// A production version would compile these into Cedar or OPA policies
// (see the architecture section of the spec doc). This hand-rolled version
// keeps the demo dependency-free while matching the same rule shapes, so
// porting to Cedar/OPA later is a translation, not a redesign.

import type { ActionRequest, Decision, PolicyDecisionResult } from "../types.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { Ledger } from "../ledger/ledger.js";

export interface ParameterRule {
  kind: "parameter_threshold";
  /** Dot-free key into ActionRequest.parameters, e.g. "amount". */
  field: string;
  lessThanOrEqual?: number;
  greaterThan?: number;
  thenDecision: Decision;
  reason: string;
}

export interface VelocityRule {
  kind: "velocity";
  /** Look back this many minutes when counting prior calls. */
  windowMinutes: number;
  /** Max number of calls allowed to this tool in the window (undefined = no count limit). */
  maxCount?: number;
  /** Max cumulative value of a numeric field in the window (e.g. total refunded). */
  maxCumulativeField?: { field: string; max: number };
  thenDecision: Decision;
  reason: string;
}

export type PolicyRule = ParameterRule | VelocityRule;

export interface Policy {
  id: string;
  version: number;
  toolName: string;
  /** Rules are evaluated in order; the first matching rule decides. Falls
   * through to `defaultDecision` (usually "allow") if none match. */
  rules: PolicyRule[];
  defaultDecision: Decision;
}

export class PolicyEngine {
  private policies = new Map<string, Policy>(); // keyed by toolName

  constructor(
    private registry: AgentRegistry,
    private ledger: Ledger,
  ) {}

  setPolicy(policy: Policy) {
    this.policies.set(policy.toolName, policy);
  }

  getPolicy(toolName: string): Policy | undefined {
    return this.policies.get(toolName);
  }

  /** Evaluates one action request end to end: capability grant, then
   * per-call parameter rules, then stateful velocity rules. */
  evaluate(request: ActionRequest): PolicyDecisionResult {
    const agent = this.registry.get(request.agentId);
    if (!agent) {
      return {
        decision: "deny",
        reason: "Unknown agent",
        policyId: "system",
        policyVersion: 0,
      };
    }
    if (!this.registry.isActive(request.agentId)) {
      return {
        decision: "deny",
        reason: `Agent is not active (state: ${agent.lifecycleState})`,
        policyId: "system",
        policyVersion: 0,
      };
    }

    // Capability check: default deny. An agent may only call tools it was
    // explicitly granted at registration.
    const grants = this.registry.grantsFor(request.agentId);
    const grant = grants.find((g) => g.toolName === request.toolName);
    if (!grant) {
      return {
        decision: "deny",
        reason: `Agent has no grant for tool "${request.toolName}"`,
        policyId: "system",
        policyVersion: 0,
      };
    }

    const policy = this.policies.get(request.toolName);
    if (!policy) {
      // No policy configured for this tool: allow, since the capability
      // grant already gated access. A production system might instead
      // require every granted tool to have an explicit policy.
      return {
        decision: "allow",
        reason: "No policy configured; capability grant allows by default",
        policyId: "system",
        policyVersion: 0,
      };
    }

    for (const rule of policy.rules) {
      if (rule.kind === "parameter_threshold") {
        const value = request.parameters[rule.field];
        if (typeof value !== "number") continue;
        if (rule.lessThanOrEqual !== undefined && value <= rule.lessThanOrEqual) {
          continue; // this rule only fires above the threshold
        }
        if (rule.greaterThan !== undefined && value <= rule.greaterThan) {
          continue;
        }
        return {
          decision: rule.thenDecision,
          reason: rule.reason,
          policyId: policy.id,
          policyVersion: policy.version,
          ruleTriggered: `parameter_threshold:${rule.field}`,
        };
      }

      if (rule.kind === "velocity") {
        const since = new Date(Date.now() - rule.windowMinutes * 60_000).toISOString();
        const recent = this.ledger
          .forAgentSince(request.agentId, since)
          .filter((e) => e.toolName === request.toolName && e.decision === "allow");

        if (rule.maxCount !== undefined && recent.length >= rule.maxCount) {
          return {
            decision: rule.thenDecision,
            reason: rule.reason,
            policyId: policy.id,
            policyVersion: policy.version,
            ruleTriggered: `velocity:count>=${rule.maxCount}`,
          };
        }

        if (rule.maxCumulativeField) {
          const { field, max } = rule.maxCumulativeField;
          const currentValue = Number(request.parameters[field] ?? 0);
          const priorTotal = recent.reduce((sum, e) => {
            const params = JSON.parse(e.parametersRedacted) as Record<string, unknown>;
            return sum + Number(params[field] ?? 0);
          }, 0);
          if (priorTotal + currentValue > max) {
            return {
              decision: rule.thenDecision,
              reason: `${rule.reason} (prior: ${priorTotal}, this call: ${currentValue}, limit: ${max})`,
              policyId: policy.id,
              policyVersion: policy.version,
              ruleTriggered: `velocity:cumulative_${field}>${max}`,
            };
          }
        }
      }
    }

    return {
      decision: policy.defaultDecision,
      reason: "No rule matched; default decision applied",
      policyId: policy.id,
      policyVersion: policy.version,
    };
  }
}
