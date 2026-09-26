// Gateway: the enforcement point an agent calls instead of calling a tool
// directly. This is the "MCP and tool gateway" from the architecture section
// of the spec doc, simplified to a plain function for the demo (no network
// hop). `server.ts` wraps this same logic behind an HTTP endpoint so it can
// also be called like a real gateway.

import { nanoid } from "nanoid";
import type { ActionRequest, ActionEvent, Approval } from "../types.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { PolicyEngine } from "../policy/engine.js";
import type { Ledger } from "../ledger/ledger.js";
import type { ApprovalChannel } from "../gateway/approvals.js";

export interface GovernedCallResult {
  event: ActionEvent;
  allowed: boolean;
  pendingApproval?: Approval;
}

export class Gateway {
  constructor(
    private registry: AgentRegistry,
    private policyEngine: PolicyEngine,
    private ledger: Ledger,
    private approvals: ApprovalChannel,
  ) {}

  /** Intercepts one tool call: evaluates policy, logs the decision, and
   * (for holds) requests an approval. Returns whether the call may proceed. */
  async call(request: ActionRequest, runId: string = nanoid()): Promise<GovernedCallResult> {
    const start = performance.now();
    const result = this.policyEngine.evaluate(request);
    const latencyMs = performance.now() - start;

    let approvalId: string | undefined;
    let pendingApproval: Approval | undefined;

    const event = this.ledger.append({
      runId,
      agentId: request.agentId,
      principal: request.principal,
      toolName: request.toolName,
      parameters: request.parameters,
      decision: result.decision,
      policyId: result.policyId,
      policyVersion: result.policyVersion,
      ruleTriggered: result.ruleTriggered,
      latencyMs,
    });

    if (result.decision === "hold_for_approval") {
      approvalId = this.ledger.recordApproval({
        actionEventId: event.id,
        requestedAt: event.timestamp,
      });
      pendingApproval = {
        id: approvalId,
        actionEventId: event.id,
        status: "pending",
        requestedAt: event.timestamp,
      };
      await this.approvals.request({
        approvalId,
        agentId: request.agentId,
        principal: request.principal,
        toolName: request.toolName,
        parameters: request.parameters,
        reason: result.reason,
      });
    }

    return {
      event,
      allowed: result.decision === "allow",
      pendingApproval,
    };
  }

  /** Resolves a pending approval and re-emits a follow-up event recording
   * the human decision, so the ledger shows both the hold and its outcome. */
  resolveApproval(
    approvalId: string,
    approver: string,
    approved: boolean,
    reason: string | undefined,
    original: ActionRequest,
    runId: string,
  ): ActionEvent {
    this.ledger.decideApproval(approvalId, approver, approved, reason);
    return this.ledger.append({
      runId,
      agentId: original.agentId,
      principal: original.principal,
      toolName: original.toolName,
      parameters: original.parameters,
      decision: approved ? "allow" : "deny",
      policyId: "approval",
      policyVersion: 1,
      ruleTriggered: approved ? "human_approval:approved" : "human_approval:rejected",
      latencyMs: 0,
      approvalId,
    });
  }
}
