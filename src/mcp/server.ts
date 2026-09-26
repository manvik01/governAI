#!/usr/bin/env node
// MCP server that exposes *business* tools (issue_refund) with governance
// applied server-side. An MCP-capable agent framework calls issue_refund
// like any other tool — it does not need to know about policies, ledgers,
// or approvals. That is the roadmap week 5-6 "MCP gateway" milestone.
//
// Transport: stdio. Run: npm run mcp

import { unlinkSync, existsSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createSeededControlPlane } from "../demo/setup.js";
import { StderrApprovalChannel } from "./approvals.js";

const DB_PATH = process.env.LEDGER_DB ?? "./mcp-ledger.db";
const FRESH = process.env.MCP_FRESH_LEDGER === "1";

if (FRESH && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
}

const { gateway, ledger, agent } = createSeededControlPlane({
  dbPath: DB_PATH,
  approvals: new StderrApprovalChannel(),
});

function jsonResult(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

const server = new McpServer({
  name: "agent-governance-gateway",
  version: "0.1.0",
});

server.registerTool(
  "issue_refund",
  {
    title: "Issue refund",
    description:
      "Issue a customer refund in SGD. Calls are policy-checked by the governance gateway (auto-allow under SGD 200, human approval above, daily cumulative cap SGD 1,000).",
    inputSchema: {
      amount: z.number().positive().describe("Refund amount in SGD"),
      principal: z.string().describe("Customer id this refund is for"),
      runId: z.string().optional().describe("Optional run id to correlate related calls"),
    },
  },
  async ({ amount, principal, runId }) => {
    const result = await gateway.call(
      {
        agentId: agent.id,
        principal,
        toolName: "issue_refund",
        parameters: { amount },
      },
      runId,
    );

    if (result.event.decision === "allow") {
      return jsonResult({
        status: "allowed",
        amount,
        principal,
        eventId: result.event.id,
        message: `Refund of SGD ${amount} allowed.`,
      });
    }

    if (result.event.decision === "hold_for_approval" && result.pendingApproval) {
      return jsonResult({
        status: "held_for_approval",
        amount,
        principal,
        approvalId: result.pendingApproval.id,
        eventId: result.event.id,
        ruleTriggered: result.event.ruleTriggered,
        message: `Refund of SGD ${amount} held for approval. Approval ID: ${result.pendingApproval.id}`,
        hint: `Resolve out-of-band: npm run mcp:approve -- decide ${result.pendingApproval.id} approve`,
      });
    }

    return jsonResult({
      status: "denied",
      amount,
      principal,
      eventId: result.event.id,
      ruleTriggered: result.event.ruleTriggered,
      message: `Refund of SGD ${amount} denied.`,
    });
  },
);

server.registerTool(
  "check_approval",
  {
    title: "Check approval status",
    description: "Poll the status of a pending hold_for_approval decision.",
    inputSchema: {
      approvalId: z.string(),
    },
  },
  async ({ approvalId }) => {
    const approval = ledger.getApproval(approvalId);
    if (!approval) {
      return jsonResult({ status: "unknown", approvalId });
    }
    return jsonResult({
      status: approval.status,
      approvalId: approval.id,
      approver: approval.approver ?? null,
      decidedAt: approval.decidedAt ?? null,
      reason: approval.reason ?? null,
    });
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `Governed MCP gateway on stdio (agent=${agent.id}, ledger=${DB_PATH})`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
