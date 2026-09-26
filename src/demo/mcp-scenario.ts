// End-to-end demo of the same refund scenario as scenario.ts, but driven
// through the MCP protocol: this process is an MCP client that spawns the
// governance gateway as an MCP server over stdio.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { unlinkSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const DB_PATH = "./mcp-demo-ledger.db";

async function callTool(client: Client, name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as Array<{ type: string; text?: string }>)
    .filter((c) => c.type === "text" && c.text)
    .map((c) => c.text!)
    .join("\n");
  if (result.isError) {
    throw new Error(`MCP tool ${name} failed: ${text}`);
  }
  return text ? JSON.parse(text) : null;
}

async function main() {
  if (existsSync(DB_PATH)) unlinkSync(DB_PATH);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve("dist/gateway/mcp.js")],
    cwd: process.cwd(),
    env: {
      ...process.env,
      LEDGER_DB: resolve(DB_PATH),
    },
    stderr: "inherit",
  });

  const client = new Client({ name: "governai-mcp-demo", version: "0.1.0" });
  await client.connect(transport);

  section("0. Discover MCP tools");
  const tools = await client.listTools();
  console.log(
    "Tools exposed by gateway:",
    tools.tools.map((t) => t.name).join(", "),
  );

  section("1. Register the agent (via MCP)");
  const agent = await callTool(client, "register_agent", {
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
  console.log(`Registered agent ${agent.id} | risk=${agent.riskTier} | state=${agent.lifecycleState}`);

  await callTool(client, "approve_agent", { agentId: agent.id });
  console.log("Security approved the agent");

  section("2. Define the policy (via MCP)");
  await callTool(client, "set_policy", {
    policy: {
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
    },
  });
  console.log("Policy set for issue_refund");

  section("3. Governed refund calls (via MCP)");
  const runId = "mcp-run-" + Date.now();

  await printCall(client, agent.id, runId, 150, "cust-001");
  await printCall(client, agent.id, runId, 800, "cust-002");

  const held = await printCall(client, agent.id, runId, 900, "cust-003");
  if (held.pendingApproval) {
    section("3a. Manager approves SGD 900 (via MCP decide_approval)");
    await callTool(client, "decide_approval", {
      approvalId: held.pendingApproval.id,
      approver: "manager@example.com",
      approved: true,
      reason: "Verified against the original order; approved.",
      original: {
        agentId: agent.id,
        principal: "cust-003",
        toolName: "issue_refund",
        parameters: { amount: 900 },
      },
      runId,
    });
    console.log("Approval resolved: APPROVED");
  }

  await printCall(client, agent.id, runId, 100, "cust-004");

  section("4. Ledger audit + hash verify (via MCP)");
  const events = await callTool(client, "list_agent_events", { agentId: agent.id });
  console.log(`Events for agent: ${events.length}`);
  for (const e of events) {
    console.log(`  ${e.decision.padEnd(18)} ${e.ruleTriggered ?? "-"}`);
  }
  const verify = await callTool(client, "verify_ledger", {});
  console.log(`Hash chain intact: ${verify.intact}`);

  section("5. Kill switch (via MCP)");
  await callTool(client, "suspend_agent", {
    agentId: agent.id,
    reason: "Demo: showing kill switch over MCP",
  });
  const after = await callTool(client, "governed_call", {
    agentId: agent.id,
    principal: "cust-005",
    toolName: "issue_refund",
    parameters: { amount: 50 },
    runId,
  });
  console.log(`Call after suspend -> allowed: ${after.allowed} (decision=${after.event.decision})`);

  await client.close();
  console.log("\nMCP demo complete. Ledger written to " + DB_PATH);
}

async function printCall(
  client: Client,
  agentId: string,
  runId: string,
  amount: number,
  principal: string,
) {
  const result = await callTool(client, "governed_call", {
    agentId,
    principal,
    toolName: "issue_refund",
    parameters: { amount },
    runId,
  });
  console.log(
    `Refund SGD ${amount} for ${principal} -> ${result.event.decision.toUpperCase()}` +
      (result.event.ruleTriggered ? ` (${result.event.ruleTriggered})` : ""),
  );
  return result;
}

function section(title: string) {
  console.log("\n" + "=".repeat(70));
  console.log(title);
  console.log("=".repeat(70));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
