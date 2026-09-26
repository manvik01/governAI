// Shared bootstrap for the HTTP server and MCP server so both expose the
// same registry → policy → gateway → ledger stack.

import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine } from "../policy/engine.js";
import { Gateway } from "./gateway.js";
import { ConsoleApprovalChannel, type ApprovalChannel } from "./approvals.js";

export interface ControlPlane {
  registry: AgentRegistry;
  ledger: Ledger;
  policyEngine: PolicyEngine;
  gateway: Gateway;
}

export function createControlPlane(options?: {
  dbPath?: string;
  approvals?: ApprovalChannel;
}): ControlPlane {
  const registry = new AgentRegistry();
  const ledger = new Ledger(options?.dbPath ?? "./ledger.db");
  const policyEngine = new PolicyEngine(registry, ledger);
  const gateway = new Gateway(
    registry,
    policyEngine,
    ledger,
    options?.approvals ?? new ConsoleApprovalChannel(),
  );
  return { registry, ledger, policyEngine, gateway };
}
