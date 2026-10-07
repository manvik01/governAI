#!/usr/bin/env node
// MCP admin server: lets an MCP client (Claude Desktop, Cursor, ...) administer
// governAI by calling the SECURE gateway as an authenticated human.
//
// Replaces the earlier unauthenticated admin MCP server. It has no database
// access and no policy logic; the gateway decides who may do what and logs it.
// Config (env only): GOVERNAI_GATEWAY_URL, GOVERNAI_USER_TOKEN.
// Run: npm run mcp:admin

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { GatewayClient, GatewayError } from "./gateway-client.js";
import { policySchema } from "../policy/schema.js";

export function buildAdminServer(client: GatewayClient) {
  const server = new McpServer({ name: "governai-admin", version: "0.2.0" });

  const run = async (fn: () => Promise<unknown>) => {
    try {
      return { content: [{ type: "text" as const, text: JSON.stringify(await fn(), null, 2) }] };
    } catch (e) {
      const err = e instanceof GatewayError ? e : new GatewayError("unexpected error");
      return {
        isError: true,
        content: [{ type: "text" as const, text: JSON.stringify({ error: err.message, status: err.status, detail: err.body }) }],
      };
    }
  };

  server.registerTool("list_agents", { title: "List agents", description: "Agents visible to your role, with lifecycle state and risk tier.", inputSchema: {} },
    () => run(() => client.request("GET", "/v1/agents")));

  server.registerTool("register_agent", {
    title: "Register agent",
    description: "Submit a registration. The gateway verifies owner, sub-owner and access profile and refuses anything outside the profile. A credential is returned once, only if no security review is required.",
    inputSchema: { registration: z.record(z.string(), z.unknown()) },
  }, ({ registration }) => run(() => client.request("POST", "/v1/agents", registration)));

  server.registerTool("review_agent", {
    title: "Security review",
    description: "Approve or reject a pending agent. Requires the security_reviewer role, a complete checklist, and a reviewer who is not the owner, sub-owner or submitter.",
    inputSchema: { agentId: z.string(), decision: z.enum(["approve", "reject"]), checklist: z.record(z.string(), z.boolean()), notes: z.string().optional() },
  }, ({ agentId, ...body }) => run(() => client.request("POST", `/v1/agents/${encodeURIComponent(agentId)}/review`, body)));

  server.registerTool("suspend_agent", {
    title: "Suspend agent (kill switch)",
    description: "Suspend an agent and revoke all its credentials immediately.",
    inputSchema: { agentId: z.string(), reason: z.string().min(1) },
  }, ({ agentId, reason }) => run(() => client.request("POST", `/v1/agents/${encodeURIComponent(agentId)}/suspend`, { reason })));

  server.registerTool("set_policy", {
    title: "Set tool policy",
    description: "Install a new version of a tool policy (admin only). Versions must increase.",
    inputSchema: { policy: policySchema },
  }, ({ policy }) => run(() => client.request("PUT", "/v1/policies", policy)));

  server.registerTool("get_policy", { title: "Get policy", description: "Current policy for a tool.", inputSchema: { toolName: z.string() } },
    ({ toolName }) => run(() => client.request("GET", `/v1/policies/${encodeURIComponent(toolName)}`)));

  server.registerTool("list_audit_events", {
    title: "Query audit log",
    description: "Search the audit log (auditor or admin). Reading it is itself logged.",
    inputSchema: { stream: z.enum(["audit", "user"]).optional(), actor: z.string().optional(), action: z.string().optional(), target: z.string().optional(), limit: z.number().int().max(1000).optional() },
  }, (q) => run(() => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) if (v !== undefined) p.set(k, String(v));
    return client.request("GET", `/v1/audit?${p}`);
  }));

  server.registerTool("verify_audit_chain", { title: "Verify audit chain", description: "Tamper-check the audit log. Returns the first broken sequence number, if any.", inputSchema: {} },
    () => run(() => client.request("GET", "/v1/audit/verify")));

  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const client = new GatewayClient(process.env.GOVERNAI_GATEWAY_URL ?? "", process.env.GOVERNAI_USER_TOKEN ?? "");
  await buildAdminServer(client).connect(new StdioServerTransport());
  console.error("governAI admin MCP server on stdio");
}
