// Protocol-level MCP test client: connects to the governed MCP server the
// same way any MCP-capable agent would, over stdio, and calls its tools
// directly (no model in the loop). This is the proof that the MCP wiring
// itself works — that the transport, tool schemas, and governance decisions
// all function correctly — independent of which agent framework eventually
// drives it. It runs the same allow/hold/deny sequence as the in-process
// demo (src/demo/scenario.ts), but this time every call crosses a real
// MCP client/server boundary.
//
// This is also what you'd adapt to write an equivalent test client against
// LangGraph's MCP adapter, the OpenAI Agents SDK's MCP support, or Google
// ADK's MCP toolset — the server side (src/mcp/server.ts) doesn't change
// for any of them; only how a given framework connects to it does.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, unlinkSync } from "node:fs";

const DB_PATH = "./mcp-ledger.db";

async function main() {
  // Fresh ledger each run so the sequence below is repeatable.
  for (const suffix of ["", "-wal", "-shm"]) {
    const p = DB_PATH + suffix;
    if (existsSync(p)) unlinkSync(p);
  }

  const transport = new StdioClientTransport({
    command: "node",
    args: ["dist/mcp/server.js"],
    env: { ...process.env, GOVERNAI_DB_PATH: DB_PATH },
  });

  const client = new Client({ name: "governai-test-client", version: "0.1.0" });
  await client.connect(transport);

  section("1. Discover the server's tools");
  const { tools } = await client.listTools();
  for (const t of tools) {
    console.log(`  - ${t.name}: ${t.description}`);
  }

  section("2. Call issue_refund (SGD 150) — expect: auto-allowed");
  await callRefund(client, "cust-001", 150);

  section("3. Call issue_refund (SGD 800) — expect: held for approval");
  await callRefund(client, "cust-002", 800);

  section("4. Call issue_refund (SGD 900) — expect: held for approval");
  const held2 = await callRefund(client, "cust-003", 900);

  const approvalId = extractApprovalId(held2);
  if (approvalId) {
    console.log(
      `\nTo approve this from another terminal:\n  npm run mcp:approve -- decide ${approvalId} approve\n` +
        `Resolving it automatically now, to keep this test self-contained...`,
    );
    // In a real deployment this happens out of band (a manager clicking
    // Approve in Slack). For this test client we shell out to the same
    // approve script so the sequence completes without a human present.
    const { execSync } = await import("node:child_process");
    execSync(`node dist/mcp/approve.js decide ${approvalId} approve manager@example.com "Verified via test client"`, {
      env: { ...process.env, GOVERNAI_DB_PATH: DB_PATH },
      stdio: "inherit",
    });
  }

  section("5. Check approval status via the check_approval tool");
  if (approvalId) {
    const status = await client.callTool({
      name: "check_approval",
      arguments: { approvalId },
    });
    printResult(status);
  }

  section("6. Call issue_refund (SGD 100) — expect: DENY (cumulative cap)");
  // Running total so far: 150 (allowed) + 900 (approved above) = 1,050,
  // already over the SGD 1,000/day cap, so even this small refund is denied.
  await callRefund(client, "cust-004", 100);

  await client.close();
  console.log("\nMCP test client complete. Ledger written to " + DB_PATH);
}

async function callRefund(client: Client, customerId: string, amount: number) {
  const result = await client.callTool({
    name: "issue_refund",
    arguments: { customerId, amount },
  });
  printResult(result);
  return result;
}

function printResult(result: Awaited<ReturnType<Client["callTool"]>>) {
  const text = (result.content as Array<{ type: string; text?: string }> | undefined)
    ?.map((c) => c.text)
    .filter(Boolean)
    .join(" ");
  console.log(`  ${result.isError ? "[ERROR] " : ""}${text}`);
}

function extractApprovalId(result: Awaited<ReturnType<Client["callTool"]>>): string | undefined {
  const text = (result.content as Array<{ type: string; text?: string }> | undefined)
    ?.map((c) => c.text)
    .join(" ");
  // nanoid ids use [A-Za-z0-9_-]; excluding "." keeps us from swallowing the
  // sentence's trailing punctuation when the id is followed directly by one.
  return text?.match(/Approval ID: ([A-Za-z0-9_-]+)/)?.[1];
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
