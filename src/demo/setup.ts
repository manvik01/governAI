// Shared world setup for the refund-agent scenario: the same agent
// registration and policy definition are used by the in-process demo
// (src/demo/scenario.ts) and the MCP server (src/mcp/server.ts), so that
// governing an agent over MCP is provably the same governance, not a
// separate code path with its own rules.

import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine, type Policy } from "../policy/engine.js";
import { Gateway } from "../gateway/gateway.js";
import type { ApprovalChannel } from "../gateway/approvals.js";
import type { Agent } from "../types.js";

export interface DemoWorld {
  registry: AgentRegistry;
  ledger: Ledger;
  policyEngine: PolicyEngine;
  gateway: Gateway;
  agent: Agent;
  policy: Policy;
}

/** Builds the registry, ledger, policy engine and gateway, registers the
 * demo "SupportRefundAgent", approves it, and installs its refund policy.
 * `approvalChannel` is injected so callers can choose how a held decision
 * is surfaced (console log for the CLI demo, or left silent for the MCP
 * server, which reports the hold back to the calling agent instead). */
export function buildDemoWorld(dbPath: string, approvalChannel: ApprovalChannel): DemoWorld {
  const registry = new AgentRegistry();
  const ledger = new Ledger(dbPath);
  const policyEngine = new PolicyEngine(registry, ledger);
  const gateway = new Gateway(registry, policyEngine, ledger, approvalChannel);

  const agent = registry.register({
    name: "SupportRefundAgent",
    purpose: "Issues customer refunds from the support queue",
    ownerEmail: "manav@example.com",
    businessUnit: "Customer Success",
    platform: "custom",
    modelProvider: "anthropic",
    modelVersion: "claude-sonnet-5",
    autonomyDefault: "A2",
    mode: "enforcement",
    permittedModels: ["claude-sonnet-5"],
    // Budgets are integer micro-USD: $50 cap across this agent, $2 per originating task.
    budgetPolicy: { agentLimitMicro: 50_000_000, defaultTaskLimitMicro: 2_000_000 },
    tools: [
      {
        toolName: "issue_refund",
        reversible: false,
        dataClasses: ["financial", "customer_pii"],
      },
    ],
  });
  // High risk tier (touches money + irreversible) -> starts pending_approval;
  // security signs off before the agent may act, same lifecycle rule the
  // spec doc describes for the registry.
  registry.approve(agent.id);

  const policy: Policy = {
    id: "pol-refund-001",
    version: 1,
    toolName: "issue_refund",
    defaultDecision: "allow",
    rules: [
      // Per-call rule, evaluated first: anything above SGD 200 needs a human.
      {
        kind: "parameter_threshold",
        field: "amount",
        greaterThan: 200,
        thenDecision: "hold_for_approval",
        reason: "Refund exceeds SGD 200 auto-approve limit",
      },
      // Stateful rule, evaluated second: even small refunds are blocked
      // once the day's approved total would cross SGD 1,000.
      {
        kind: "velocity",
        windowMinutes: 24 * 60,
        maxCumulativeField: { field: "amount", max: 1000 },
        thenDecision: "deny",
        reason: "Daily cumulative refund limit (SGD 1,000) would be exceeded",
      },
    ],
  };
  policyEngine.setPolicy(policy);

  return { registry, ledger, policyEngine, gateway, agent, policy };
}
