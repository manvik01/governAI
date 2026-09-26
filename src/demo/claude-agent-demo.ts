// A real Claude agent, built on the Claude Agent SDK, calling our governed
// MCP server as its tool provider. This is the "Claude Agent SDK" example
// client from the roadmap: the agent framework doesn't know or care that
// issue_refund is policy-checked — from its side, it's just an MCP tool.
// The governance happens entirely on the server side (src/mcp/server.ts),
// so the same server would work identically behind LangGraph, the OpenAI
// Agents SDK, or Google ADK; only this file (how the framework is told
// about the server) would change.
//
// Requires ANTHROPIC_API_KEY to actually run — it makes real model calls.
// Without a key, this file still documents and type-checks the correct
// integration shape; see the guard at the top of main().

import { query } from "@anthropic-ai/claude-agent-sdk";
import { existsSync, unlinkSync } from "node:fs";

const DB_PATH = "./claude-agent-ledger.db";

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.log(
      "ANTHROPIC_API_KEY is not set, so this won't make a real model call.\n" +
        "The integration shape below is still correct and type-checked — set the\n" +
        "key and re-run (`npm run agent:claude`) to see a real Claude agent call\n" +
        "the governed issue_refund tool through the Claude Agent SDK's MCP support.",
    );
    return;
  }

  for (const suffix of ["", "-wal", "-shm"]) {
    const p = DB_PATH + suffix;
    if (existsSync(p)) unlinkSync(p);
  }

  const result = query({
    prompt:
      "A customer (cust-002) is asking for an SGD 800 refund for a damaged " +
      "item. Process it using the available tools, and tell me the outcome. " +
      "If it needs approval, say so clearly rather than telling the customer " +
      "it's done.",
    options: {
      // Points the agent at our governed MCP server over stdio — the exact
      // same server process the protocol-level test client in
      // src/mcp/test-client.ts talks to.
      mcpServers: {
        governai: {
          command: "node",
          args: ["dist/mcp/server.js"],
          env: { GOVERNAI_DB_PATH: DB_PATH },
        },
      },
      // Server-qualified tool names follow mcp__<serverName>__<toolName>.
      allowedTools: ["mcp__governai__issue_refund", "mcp__governai__check_approval"],
      maxTurns: 5,
    },
  });

  for await (const message of result) {
    if (message.type === "assistant") {
      for (const block of message.message.content) {
        if (block.type === "text") console.log("\n[Claude]", block.text);
        if (block.type === "tool_use") {
          console.log(`\n[Claude called tool] ${block.name}(${JSON.stringify(block.input)})`);
        }
      }
    }
    if (message.type === "result") {
      console.log(`\n[Run finished] ${message.subtype}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
