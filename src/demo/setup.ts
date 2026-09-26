// Shared demo bootstrap: register the SupportRefundAgent and install the
// refund policy used by the in-process demo, MCP server, and Claude Agent
// SDK client. Keeps those three entry points from drifting.

import type { Agent } from "../types.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { PolicyEngine, Policy } from "../policy/engine.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine as PolicyEngineCtor } from "../policy/engine.js";
import { AgentRegistry as AgentRegistryCtor } from "../registry/registry.js";
import { Gateway } from "../gateway/gateway.js";
import type { ApprovalChannel } from "../gateway/approvals.js";
import { ConsoleApprovalChannel } from "../gateway/approvals.js";

export const REFUND_POLICY: Policy = {
  id: "pol-refund-001",
  version: 1,
  toolName: "issue_refund",
  defaultDecision: "allow",
  rules: [
    {
      kind: "parameter_threshold",
      field: "amount",
      greaterThan: 200,
      thenDecision: "hold_for_approval",
      reason: "Refund exceeds SGD 200 auto-approve limit",
    },
    {
      kind: "velocity",
      windowMinutes: 24 * 60,
      maxCumulativeField: { field: "amount", max: 1000 },
      thenDecision: "deny",
      reason: "Daily cumulative refund limit (SGD 1,000) would be exceeded",
    },
  ],
};

/** Registers SupportRefundAgent, security-approves it, and installs REFUND_POLICY. */
export function seedRefundDemo(
  registry: AgentRegistry,
  policyEngine: PolicyEngine,
): Agent {
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
    tools: [
      {
        toolName: "issue_refund",
        reversible: false,
        dataClasses: ["financial", "customer_pii"],
      },
    ],
  });
  registry.approve(agent.id);
  policyEngine.setPolicy(REFUND_POLICY);
  return agent;
}

export interface ControlPlane {
  registry: AgentRegistry;
  ledger: Ledger;
  policyEngine: PolicyEngine;
  gateway: Gateway;
  agent: Agent;
}

export function createSeededControlPlane(options: {
  dbPath: string;
  approvals?: ApprovalChannel;
}): ControlPlane {
  const registry = new AgentRegistryCtor();
  const ledger = new Ledger(options.dbPath);
  const policyEngine = new PolicyEngineCtor(registry, ledger);
  const gateway = new Gateway(
    registry,
    policyEngine,
    ledger,
    options.approvals ?? new ConsoleApprovalChannel(),
  );
  const agent = seedRefundDemo(registry, policyEngine);
  return { registry, ledger, policyEngine, gateway, agent };
}
