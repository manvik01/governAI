#!/usr/bin/env node
// Protocol-level MCP test client: spawns the governed MCP server as a real
// child process, drives issue_refund / check_approval over stdio, and
// resolves a hold via a *separate* approve.js process. Proves wiring without
// needing a model API key.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const DB_PATH = resolve("./mcp-test-ledger.db");

async function callTool(client: Client, name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as Array<{ type: string; text?: string }>)
    .filter((c) => c.type === "text" && c.text)
    .map((c) => c.text!)
    .join("\n");
  if (result.isError) throw new Error(`Tool ${name} failed: ${text}`);
  return text ? JSON.parse(text) : null;
}

function section(title: string) {
  console.log("\n" + "=".repeat(70));
  console.log(title);
  console.log("=".repeat(70));
}

function approveOutOfBand(approvalId: string) {
  const r = spawnSync(
    process.execPath,
    [resolve("dist/mcp/approve.js"), "decide", approvalId, "approve", "manager@example.com", "Verified order"],
    {
      cwd: process.cwd(),
      env: { ...process.env, LEDGER_DB: DB_PATH },
      encoding: "utf8",
    },
  );
  if (r.status !== 0) {
    throw new Error(`mcp:approve failed: ${r.stderr || r.stdout}`);
  }
  console.log(r.stdout.trim());
  return JSON.parse(r.stdout);
}

function verifyLedger() {
  const r = spawnSync(
    process.execPath,
    [resolve("dist/mcp/approve.js"), "verify"],
    {
      cwd: process.cwd(),
      env: { ...process.env, LEDGER_DB: DB_PATH },
      encoding: "utf8",
    },
  );
  console.log((r.stdout || r.stderr).trim());
  if (r.status !== 0) throw new Error("ledger verify failed");
}

async function main() {
  if (existsSync(DB_PATH)) unlinkSync(DB_PATH);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve("dist/mcp/server.js")],
    cwd: process.cwd(),
    env: {
      ...process.env,
      LEDGER_DB: DB_PATH,
      MCP_FRESH_LEDGER: "0",
    },
    stderr: "inherit",
  });

  const client = new Client({ name: "mcp-test-client", version: "0.1.0" });
  await client.connect(transport);

  section("0. Discover tools");
  const tools = await client.listTools();
  console.log(tools.tools.map((t) => t.name).join(", "));

  const runId = "mcp-test-" + Date.now();

  section("1. issue_refund(150) → expect ALLOW");
  const a150 = await callTool(client, "issue_refund", {
    amount: 150,
    principal: "cust-001",
    runId,
  });
  console.log(a150);
  if (a150.status !== "allowed") throw new Error("expected allowed");

  section("2. issue_refund(800) → expect HOLD");
  const a800 = await callTool(client, "issue_refund", {
    amount: 800,
    principal: "cust-002",
    runId,
  });
  console.log(a800);
  if (a800.status !== "held_for_approval") throw new Error("expected hold");

  section("3. issue_refund(900) → expect HOLD, then out-of-band approve");
  const a900 = await callTool(client, "issue_refund", {
    amount: 900,
    principal: "cust-003",
    runId,
  });
  console.log(a900);
  if (a900.status !== "held_for_approval" || !a900.approvalId) {
    throw new Error("expected hold with approvalId");
  }

  section("3a. Separate process: mcp:approve decide … approve");
  approveOutOfBand(a900.approvalId);

  section("3b. check_approval → approved");
  const status = await callTool(client, "check_approval", {
    approvalId: a900.approvalId,
  });
  console.log(status);
  if (status.status !== "approved") throw new Error("expected approved");

  section("4. issue_refund(100) → expect DENY (stateful cumulative cap)");
  const a100 = await callTool(client, "issue_refund", {
    amount: 100,
    principal: "cust-004",
    runId,
  });
  console.log(a100);
  if (a100.status !== "denied") throw new Error("expected denied");

  section("5. Hash chain across 3 OS processes");
  verifyLedger();

  await client.close();
  console.log("\nMCP protocol test passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
