// Bare HTTP server exposing the gateway, registry and ledger. This is the
// "minimal web page lists agents, decisions and open approvals" milestone
// from the roadmap (weeks 9-10) — deliberately undesigned. It proves the
// gateway works as a real network service an agent (or MCP client) could
// call, ahead of building a proper console UI.
//
// Run: npm run server
// Then, in another terminal:
//   curl -X POST localhost:8787/agents -H 'content-type: application/json' -d '{...}'

import express from "express";
import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine, type Policy } from "../policy/engine.js";
import { Gateway } from "../gateway/gateway.js";
import { ConsoleApprovalChannel } from "./approvals.js";
import type { RegisterAgentInput } from "../registry/registry.js";
import type { ActionRequest } from "../types.js";

const PORT = process.env.PORT ?? 8787;

const registry = new AgentRegistry();
const ledger = new Ledger("./server-ledger.db");
const policyEngine = new PolicyEngine(registry, ledger);
const gateway = new Gateway(registry, policyEngine, ledger, new ConsoleApprovalChannel());

const app = express();
app.use(express.json());

app.post("/agents", (req, res) => {
  const input = req.body as RegisterAgentInput;
  const agent = registry.register(input);
  res.status(201).json(agent);
});

app.post("/agents/:id/approve", (req, res) => {
  const agent = registry.approve(req.params.id);
  res.json(agent);
});

app.post("/agents/:id/suspend", (req, res) => {
  const agent = registry.suspend(req.params.id, req.body?.reason ?? "manual suspend");
  res.json(agent);
});

app.post("/policies", (req, res) => {
  const policy = req.body as Policy;
  policyEngine.setPolicy(policy);
  res.status(201).json(policy);
});

app.get("/agents", (_req, res) => {
  res.json(registry.list());
});

app.get("/agents/:id/events", (req, res) => {
  res.json(ledger.forAgent(req.params.id));
});

app.get("/ledger/verify", (_req, res) => {
  const brokenAt = ledger.verifyChain();
  res.json({ intact: brokenAt === -1, brokenAtIndex: brokenAt === -1 ? null : brokenAt });
});

// The governed call endpoint: what an MCP gateway or SDK wrapper calls
// instead of invoking a tool directly.
app.post("/call", async (req, res) => {
  const request = req.body as ActionRequest;
  const result = await gateway.call(request);
  res.json(result);
});

app.post("/approvals/:id/decide", (req, res) => {
  const { approver, approved, reason, original, runId } = req.body as {
    approver: string;
    approved: boolean;
    reason?: string;
    original: ActionRequest;
    runId: string;
  };
  const event = gateway.resolveApproval(req.params.id, approver, approved, reason, original, runId);
  res.json(event);
});

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html><head><title>Agent Governance — bare console</title></head>
<body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
<h1>Agent Governance Control Plane (POC)</h1>
<p>Bare API console. No UI yet — see the roadmap for when a real console gets built.</p>
<ul>
  <li>GET <a href="/agents">/agents</a></li>
  <li>GET /agents/:id/events</li>
  <li>GET <a href="/ledger/verify">/ledger/verify</a></li>
  <li>POST /agents, /policies, /call, /approvals/:id/decide</li>
</ul>
</body></html>`);
});

app.listen(PORT, () => {
  console.log(`Gateway server listening on http://localhost:${PORT}`);
});
