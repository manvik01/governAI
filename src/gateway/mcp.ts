#!/usr/bin/env node
// MCP server wrapping the governance control plane so a real agent framework
// (Claude Agent SDK, LangGraph, Cursor, etc.) can call the gateway over the
// Model Context Protocol instead of in-process.
//
// Transport: stdio (the standard local MCP client spawn path).
// Run: npm run mcp

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createControlPlane } from "./controlPlane.js";
import type { Policy } from "../policy/engine.js";
import type { ActionRequest } from "../types.js";

const DB_PATH = process.env.LEDGER_DB ?? "./mcp-ledger.db";

const { registry, ledger, policyEngine, gateway } = createControlPlane({
  dbPath: DB_PATH,
});

function jsonResult(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

const toolGrantSchema = z.object({
  toolName: z.string(),
  reversible: z.boolean(),
  dataClasses: z.array(z.string()),
});

const parameterRuleSchema = z.object({
  kind: z.literal("parameter_threshold"),
  field: z.string(),
  lessThanOrEqual: z.number().optional(),
  greaterThan: z.number().optional(),
  thenDecision: z.enum(["allow", "deny", "hold_for_approval"]),
  reason: z.string(),
});

const velocityRuleSchema = z.object({
  kind: z.literal("velocity"),
  windowMinutes: z.number(),
  maxCount: z.number().optional(),
  maxCumulativeField: z
    .object({
      field: z.string(),
      max: z.number(),
    })
    .optional(),
  thenDecision: z.enum(["allow", "deny", "hold_for_approval"]),
  reason: z.string(),
});

const policySchema = z.object({
  id: z.string(),
  version: z.number(),
  toolName: z.string(),
  defaultDecision: z.enum(["allow", "deny", "hold_for_approval"]),
  rules: z.array(z.union([parameterRuleSchema, velocityRuleSchema])),
});

const server = new McpServer({
  name: "agent-governance-gateway",
  version: "0.1.0",
});

server.registerTool(
  "register_agent",
  {
    title: "Register agent",
    description:
      "Register an agent with capability grants. High/critical risk agents start pending_approval.",
    inputSchema: {
      name: z.string(),
      purpose: z.string(),
      ownerEmail: z.string(),
      businessUnit: z.string(),
      platform: z.string(),
      modelProvider: z.string(),
      modelVersion: z.string(),
      autonomyDefault: z.enum(["A0", "A1", "A2", "A3", "A4"]),
      mode: z.enum(["enforcement", "posture"]),
      tools: z.array(toolGrantSchema),
      expiresInDays: z.number().optional(),
    },
  },
  async (input) => jsonResult(registry.register(input)),
);

server.registerTool(
  "approve_agent",
  {
    title: "Approve agent",
    description: "Security sign-off that moves an agent from pending_approval to active.",
    inputSchema: {
      agentId: z.string(),
    },
  },
  async ({ agentId }) => jsonResult(registry.approve(agentId)),
);

server.registerTool(
  "suspend_agent",
  {
    title: "Suspend agent (kill switch)",
    description: "Immediately suspend an agent so subsequent governed calls are denied.",
    inputSchema: {
      agentId: z.string(),
      reason: z.string().default("manual suspend"),
    },
  },
  async ({ agentId, reason }) => jsonResult(registry.suspend(agentId, reason)),
);

server.registerTool(
  "set_policy",
  {
    title: "Set tool policy",
    description:
      "Install a policy for a tool name, including per-call parameter rules and stateful velocity/cumulative rules.",
    inputSchema: {
      policy: policySchema,
    },
  },
  async ({ policy }) => {
    policyEngine.setPolicy(policy as Policy);
    return jsonResult(policy);
  },
);

server.registerTool(
  "governed_call",
  {
    title: "Governed tool call",
    description:
      "The enforcement point: evaluate policy for one tool call, append to the evidence ledger, and request approval when held. Use this instead of invoking the tool directly.",
    inputSchema: {
      agentId: z.string(),
      principal: z.string(),
      toolName: z.string(),
      parameters: z.record(z.string(), z.unknown()),
      runId: z.string().optional(),
      delegationChain: z.array(z.string()).optional(),
    },
  },
  async (input) => {
    const request: ActionRequest = {
      agentId: input.agentId,
      principal: input.principal,
      toolName: input.toolName,
      parameters: input.parameters,
      delegationChain: input.delegationChain,
    };
    const result = await gateway.call(request, input.runId);
    return jsonResult(result);
  },
);

server.registerTool(
  "decide_approval",
  {
    title: "Decide pending approval",
    description: "Resolve a hold_for_approval decision (approve or reject) and append the outcome to the ledger.",
    inputSchema: {
      approvalId: z.string(),
      approver: z.string(),
      approved: z.boolean(),
      reason: z.string().optional(),
      original: z.object({
        agentId: z.string(),
        principal: z.string(),
        toolName: z.string(),
        parameters: z.record(z.string(), z.unknown()),
      }),
      runId: z.string(),
    },
  },
  async (input) => {
    const event = gateway.resolveApproval(
      input.approvalId,
      input.approver,
      input.approved,
      input.reason,
      input.original,
      input.runId,
    );
    return jsonResult(event);
  },
);

server.registerTool(
  "list_agents",
  {
    title: "List agents",
    description: "List all registered agents and their lifecycle state.",
    inputSchema: {},
  },
  async () => jsonResult(registry.list()),
);

server.registerTool(
  "list_agent_events",
  {
    title: "List agent evidence events",
    description: "Return the hash-chained ledger events for one agent (newest-first audit view).",
    inputSchema: {
      agentId: z.string(),
    },
  },
  async ({ agentId }) => jsonResult(ledger.forAgent(agentId)),
);

server.registerTool(
  "verify_ledger",
  {
    title: "Verify ledger hash chain",
    description: "Tamper-check the append-only evidence ledger. Returns intact=true when every hash matches its predecessor.",
    inputSchema: {},
  },
  async () => {
    const brokenAt = ledger.verifyChain();
    return jsonResult({
      intact: brokenAt === -1,
      brokenAtIndex: brokenAt === -1 ? null : brokenAt,
    });
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Agent governance MCP gateway on stdio (ledger: ${DB_PATH})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
