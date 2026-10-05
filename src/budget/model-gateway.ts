// Governed Model Gateway: the single path by which an agent reaches a model
// provider. Control order is fixed and is the heart of the PRD's
// "independent security controls" requirement:
//
//   1. agent exists and is active
//   2. model is in the agent's permittedModels         \  security checks —
//   3. policy engine decision on the call (tool grant,  >  none of them reads
//      rules, required human approval)                 /   the budget
//   4. budget: estimate worst case, reserve atomically across org/project/
//      agent/root-task
//   5. call the provider
//   6. reconcile reported usage against the reservation, then bill
//
// Steps 1-3 run BEFORE any budget is touched, and step 5 is only reachable
// after all of them pass, so a denied call neither reserves budget nor reaches
// the provider. Budget can only ever make a call MORE restricted (step 4);
// there is no code path where available budget turns a deny/hold into allow.
// There is also deliberately no option to skip a check to save tokens, and
// fallback models go through the identical steps 1-6.

import { nanoid } from "nanoid";
import type { AgentRegistry } from "../registry/registry.js";
import type { Gateway } from "../gateway/gateway.js";
import { BudgetStore, EXHAUSTION_NOTICE, type ScopeRef } from "./budget-store.js";
import { Billing } from "./billing.js";
import { costMicro, worstCaseMicro, type PricingBook } from "./pricing.js";

export const MODEL_TOOL_NAME = "llm_invoke";

export interface ModelRequest {
  /** Caller-supplied idempotency base; each attempt appends "#<n>". */
  requestId: string;
  tenantId: string;
  projectId?: string;
  agentId: string;
  principal: string;
  taskId: string;
  parentTaskId?: string;
  /** Preference order: first is primary, the rest are fallbacks. */
  models: string[];
  prompt: string;
  maxOutputTokens: number;
  /** Reference to a human approval already obtained, carried into the ledger. */
  approvalRef?: string;
}

export interface ProviderUsage {
  inputTokens: number;
  outputTokens: number;
}
export interface ProviderResult {
  text: string;
  /** Absent => usage unknown. The gateway will NOT treat that as zero. */
  usage?: ProviderUsage;
  usageEventId?: string;
}
export class ProviderError extends Error {
  constructor(
    message: string,
    /** Whether trying again / another model is sensible. */
    public retryable: boolean,
    /** True only if the provider confirmed nothing was consumed. */
    public usageConfirmedNone: boolean,
    /** Partial usage the provider did report before failing, if any. */
    public partialUsage?: ProviderUsage,
    public usageEventId?: string,
  ) {
    super(message);
  }
}
export type ProviderFn = (call: { model: string; prompt: string; maxOutputTokens: number; idempotencyKey: string }) => Promise<ProviderResult>;

export type BudgetExhaustedOutcome = {
  status: "budget_exhausted";
  scope: ScopeRef;
  limitMicro: number;
  spentMicro: number;
  reservedMicro: number;
  requestedMicro: number;
  notice: string;
  options: Array<{ action: "increase_budget" | "cancel_task"; requires: string }>;
};

export type ModelOutcome =
  | { status: "completed"; model: string; text: string; usage: ProviderUsage; costMicro: number; attempts: number; duplicate?: false }
  | { status: "completed_usage_unresolved"; model: string; text: string; attempts: number }
  | { status: "duplicate"; requestId: string }
  | { status: "blocked"; reason: "agent_inactive" | "model_not_permitted" | "policy_deny" | "approval_required" | "task_cancelled"; detail: string; attempts: number }
  | BudgetExhaustedOutcome
  | { status: "failed"; detail: string; attempts: number };

export class GovernedModelGateway {
  constructor(
    private registry: AgentRegistry,
    private gateway: Gateway,
    private budgets: BudgetStore,
    private billing: Billing,
    private pricing: PricingBook,
    private opts: { provider: string; retriesPerModel: number } = { provider: "anthropic", retriesPerModel: 1 },
  ) {}

  async invoke(req: ModelRequest, callProvider: ProviderFn): Promise<ModelOutcome> {
    if (req.models.length === 0) throw new Error("At least one model is required");
    if (!Number.isInteger(req.maxOutputTokens) || req.maxOutputTokens <= 0) {
      // An unbounded call cannot be reserved against, so it cannot be admitted.
      throw new Error("maxOutputTokens is required: every call must have a bounded worst-case cost");
    }
    const agent = this.registry.get(req.agentId);
    const rootTaskId = this.budgets.registerTask(req.taskId, req.parentTaskId);
    if (agent) this.applyAgentBudgetDefaults(agent.budgetPolicy, req.agentId, rootTaskId);

    const estInput = Math.max(1, Math.ceil(req.prompt.length / 4));
    let attempt = 0;
    let lastFailure = "no attempt made";

    for (const model of req.models) {
      for (let tryNo = 0; tryNo <= this.opts.retriesPerModel; tryNo++) {
        attempt++;
        const attemptKey = `${req.requestId}#${attempt}`;
        const base = {
          requestId: attemptKey,
          attempt,
          tenantId: req.tenantId,
          projectId: req.projectId,
          agentId: req.agentId,
          taskId: req.taskId,
          parentTaskId: req.parentTaskId,
          rootTaskId,
          provider: this.opts.provider,
          model,
          pricingVersion: this.pricing.version,
          approvalRef: req.approvalRef,
        };

        // ---- 1 & 2: agent state and permitted models (security, pre-budget)
        const block = (reason: Extract<ModelOutcome, { status: "blocked" }>["reason"], detail: string, extra: { policyVersion?: number; actionEventId?: string } = {}): ModelOutcome => {
          this.budgets.recordBlocked({ ...base, ...extra, estimatedMicro: 0, status: `blocked:${reason}`, detail });
          this.billing.billNoCharge({ tenantId: req.tenantId, requestId: attemptKey, treatment: "blocked_no_charge" });
          return { status: "blocked", reason, detail, attempts: attempt };
        };

        if (!agent || !this.registry.isActive(req.agentId)) {
          return block("agent_inactive", `agent ${req.agentId} is unknown or not active`);
        }
        if (!agent.permittedModels.includes(model)) {
          // A cheaper fallback does not get to bypass the permitted-model list.
          return block("model_not_permitted", `model "${model}" is not in the agent's permitted models`);
        }

        // ---- 3: policy (tool grant, rules, required human approval)
        const estimated = worstCaseMicro(this.pricing, model, estInput, req.maxOutputTokens);
        const decision = await this.gateway.call(
          {
            agentId: req.agentId,
            principal: req.principal,
            toolName: MODEL_TOOL_NAME,
            parameters: { model, maxOutputTokens: req.maxOutputTokens, estimatedMicro: estimated, taskId: req.taskId, requestId: attemptKey },
          },
          rootTaskId,
        );
        if (!decision.allowed) {
          const held = decision.event.decision === "hold_for_approval";
          return block(held ? "approval_required" : "policy_deny", `${decision.event.ruleTriggered ?? "policy"} (action event ${decision.event.id})`, {
            policyVersion: decision.event.policyVersion,
            actionEventId: decision.event.id,
          });
        }

        // ---- 4: budget (only now). Atomic across org/project/agent/root task.
        const reserved = this.budgets.reserve({
          ...base,
          estimatedMicro: estimated,
          policyVersion: decision.event.policyVersion,
          actionEventId: decision.event.id,
        });
        if (!reserved.ok) {
          this.billing.billNoCharge({ tenantId: req.tenantId, requestId: attemptKey, treatment: "blocked_no_charge" });
          if (reserved.reason === "task_cancelled") {
            return { status: "blocked", reason: "task_cancelled", detail: `${reserved.scope.type}:${reserved.scope.id} was cancelled`, attempts: attempt };
          }
          return {
            status: "budget_exhausted",
            scope: reserved.scope,
            limitMicro: reserved.limitMicro,
            spentMicro: reserved.spentMicro,
            reservedMicro: reserved.reservedMicro,
            requestedMicro: reserved.requestedMicro,
            notice: EXHAUSTION_NOTICE,
            options: [
              { action: "increase_budget", requires: "an authorised budget approver (separate from the requester; grants no tool permissions)" },
              { action: "cancel_task", requires: "the task owner" },
            ],
          };
        }
        if (reserved.existing && reserved.status !== "reserved") {
          // Same request id replayed after it already settled: never call the provider twice.
          return { status: "duplicate", requestId: attemptKey };
        }

        // ---- 5: provider call
        let result: ProviderResult;
        try {
          result = await callProvider({ model, prompt: req.prompt, maxOutputTokens: req.maxOutputTokens, idempotencyKey: attemptKey });
        } catch (err) {
          const pe = err instanceof ProviderError ? err : new ProviderError(String(err), true, false);
          lastFailure = pe.message;
          if (pe.partialUsage) {
            // Provider failed but reported usage: we were charged, so it is billable.
            this.settle(attemptKey, model, pe.partialUsage, pe.usageEventId ?? `${attemptKey}:partial`, `failed:${pe.message}`, true);
          } else if (pe.usageConfirmedNone) {
            this.budgets.release(attemptKey, `failed:${pe.message}`, "provider confirmed no usage");
            this.billing.billNoCharge({ tenantId: req.tenantId, requestId: attemptKey, treatment: "failed_no_usage" });
          } else {
            // Unknown whether the provider billed us: hold the estimate, don't guess zero.
            this.budgets.markUnresolved(attemptKey, `unresolved:${pe.message}`, "provider error without usage confirmation");
          }
          if (!pe.retryable) return { status: "failed", detail: pe.message, attempts: attempt };
          continue; // retry / next model — re-runs every check, charges the same root task
        }

        // ---- 6: reconcile and bill
        if (!result.usage) {
          this.budgets.markUnresolved(attemptKey, "unresolved:usage_missing", "provider response carried no usage");
          return { status: "completed_usage_unresolved", model, text: result.text, attempts: attempt };
        }
        const actual = this.settle(attemptKey, model, result.usage, result.usageEventId ?? `${attemptKey}:usage`, "ok", false);
        return { status: "completed", model, text: result.text, usage: result.usage, costMicro: actual, attempts: attempt };
      }
    }
    return { status: "failed", detail: lastFailure, attempts: attempt };
  }

  /** Reconciles usage against the reservation and bills it. Replay-safe. */
  settle(attemptKey: string, model: string, usage: ProviderUsage, usageEventId: string, status: string, failedWithUsage: boolean): number {
    const actual = costMicro(this.pricing, model, usage.inputTokens, usage.outputTokens);
    this.budgets.reconcile({ requestId: attemptKey, usageEventId, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens, actualMicro: actual, status });
    this.billing.billReconciled(attemptKey, failedWithUsage);
    return actual;
  }

  /** Lazily materialises registration-time budget defaults without ever
   * overwriting a limit an administrator has set. */
  private applyAgentBudgetDefaults(policy: { agentLimitMicro?: number; defaultTaskLimitMicro?: number }, agentId: string, rootTaskId: string) {
    if (policy.agentLimitMicro !== undefined) this.budgets.ensureBudget({ type: "agent", id: agentId }, policy.agentLimitMicro);
    if (policy.defaultTaskLimitMicro !== undefined) this.budgets.ensureBudget({ type: "task", id: rootTaskId }, policy.defaultTaskLimitMicro);
  }
}

/** Convenience for callers that don't supply their own request id. */
export function newRequestId(): string {
  return nanoid();
}
