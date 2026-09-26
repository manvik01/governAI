// Governed MCP server: exposes the SupportRefundAgent's tools (issue_refund,
// check_approval) over the Model Context Protocol, so ANY MCP-capable agent
// framework — Claude Agent SDK, LangGraph, OpenAI Agents SDK, Google ADK —
// can call them the same way it calls any other tool server. Every call is
// evaluated by the same PolicyEngine and logged to the same hash-chained
// Ledger used by the in-process demo (src/demo/scenario.ts); this file only
// adds the MCP transport on top.
//
// This answers roadmap week 5-6 ("MCP gateway") and the "integrate with
// available MCP servers for all different agents" ask: the governance layer
// itself is now reachable as a standard MCP server, independent of which
// agent framework calls it.
//
// IMPORTANT: this process communicates over stdio. Nothing may write to
// stdout except the MCP SDK's own protocol frames — see StderrApprovalChannel
// in ../gateway/approvals.ts. All operator-facing logging here uses
// console.error for the same reason.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { StderrApprovalChannel } from "../gateway/approvals.js";
import { buildDemoWorld } from "../demo/setup.js";

const DB_PATH = process.env.GOVERNAI_DB_PATH ?? "./mcp-ledger.db";

async function main() {
  const world = buildDemoWorld(DB_PATH, new StderrApprovalChannel());

  console.error(`[governai-mcp] Agent ${world.agent.name} (${world.agent.id})`);
  console.error(`[governai-mcp] Risk tier: ${world.agent.riskTier} | Lifecycle: ${world.agent.lifecycleState}`);
  console.error(`[governai-mcp] Policy ${world.policy.id} v${world.policy.version} active for "issue_refund"`);
  console.error(`[governai-mcp] Ledger: ${DB_PATH}`);

  const server = new McpServer({
    name: "governai-refund-agent",
    version: "0.1.0",
  });

  server.registerTool(
    "issue_refund",
    {
      title: "Issue a customer refund",
      description:
        "Issues a refund to a customer. Every call is checked against the " +
        "governance policy for this agent before it takes effect: refunds " +
        "over SGD 200 require a human approval, and the agent's total " +
        "approved refunds are capped at SGD 1,000 per day.",
      inputSchema: {
        customerId: z.string().describe("The customer to refund, e.g. 'cust-002'"),
        amount: z.number().positive().describe("Refund amount in SGD"),
      },
    },
    async ({ customerId, amount }) => {
      const result = await world.gateway.call({
        agentId: world.agent.id,
        principal: customerId,
        toolName: "issue_refund",
        parameters: { amount },
      });

      if (result.allowed) {
        return {
          content: [
            {
              type: "text",
              text: `Refund of SGD ${amount} issued to ${customerId}. (event ${result.event.id}, decision: ${result.event.decision})`,
            },
          ],
        };
      }

      if (result.event.decision === "hold_for_approval" && result.pendingApproval) {
        return {
          content: [
            {
              type: "text",
              text:
                `This refund needs manager approval before it can be issued ` +
                `(policy rule: ${result.event.ruleTriggered ?? "threshold exceeded"}). ` +
                `Approval ID: ${result.pendingApproval.id}. ` +
                `Do not tell the customer the refund is complete yet — it is pending. ` +
                `You can check its status with the check_approval tool.`,
            },
          ],
        };
      }

      // Denied outright (e.g. cumulative cap, suspended agent, unknown agent).
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Refund denied. Reason logged in ledger event ${result.event.id}.`,
          },
        ],
      };
    },
  );

  server.registerTool(
    "check_approval",
    {
      title: "Check a pending refund approval",
      description: "Checks the current status of a refund that was held for approval.",
      inputSchema: {
        approvalId: z.string().describe("The approval ID returned by issue_refund"),
      },
    },
    async ({ approvalId }) => {
      const approval = world.ledger.getApproval(approvalId);
      if (!approval) {
        return {
          isError: true,
          content: [{ type: "text", text: `No approval found with id ${approvalId}.` }],
        };
      }
      return {
        content: [{ type: "text", text: `Approval ${approvalId} is currently: ${approval.status}` }],
      };
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[governai-mcp] Server ready on stdio.");
}

main().catch((err) => {
  console.error("[governai-mcp] Fatal error:", err);
  process.exit(1);
});
