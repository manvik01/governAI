#!/usr/bin/env node
// Claude Agent SDK client wired to the governed MCP gateway.
// The model sees `issue_refund` as a normal tool — governance is entirely
// server-side. Requires ANTHROPIC_API_KEY.
//
// Run: export ANTHROPIC_API_KEY=... && npm run agent:claude

import { existsSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";

const DB_PATH = resolve("./mcp-agent-ledger.db");

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error(
      [
        "ANTHROPIC_API_KEY is not set.",
        "",
        "This demo needs a live Anthropic API key so Claude can decide to call",
        "the governed issue_refund tool over MCP.",
        "",
        "  export ANTHROPIC_API_KEY=sk-ant-...",
        "  npm run agent:claude",
        "",
        "Without a key, use the protocol test instead (no model required):",
        "  npm run mcp:test-client",
      ].join("\n"),
    );
    process.exit(1);
  }

  if (existsSync(DB_PATH)) unlinkSync(DB_PATH);

  const q = query({
    prompt:
      "You are a support agent. A customer cust-001 needs a refund of SGD 150. " +
      "Use the issue_refund tool to process it, then briefly confirm the outcome.",
    options: {
      model: "claude-sonnet-4-5",
      mcpServers: {
        governance: {
          command: process.execPath,
          args: [resolve("dist/mcp/server.js")],
          env: {
            LEDGER_DB: DB_PATH,
            MCP_FRESH_LEDGER: "0",
            PATH: process.env.PATH ?? "",
          },
        },
      },
      // Allow MCP tools without interactive permission prompts in this demo.
      permissionMode: "bypassPermissions",
    },
  });

  for await (const message of q) {
    if (message.type === "assistant") {
      const content = message.message?.content ?? [];
      for (const block of content) {
        if (block.type === "text") {
          console.log(block.text);
        } else if (block.type === "tool_use") {
          console.log(`\n→ tool_use ${block.name}(${JSON.stringify(block.input)})`);
        }
      }
    } else if (message.type === "result") {
      console.log("\n[result]", message.subtype ?? "ok");
    }
  }

  console.log(`\nLedger written to ${DB_PATH}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
