# Agent Governance Control Plane — Proof of Concept

This is the week 1-8 vertical slice from the product roadmap: registry →
policy engine (with a stateful rule) → gateway → hash-chained evidence
ledger → approval flow → kill switch. It proves the differentiator — a
stateful policy engine and tamper-evident evidence — with real, runnable
code, not a mockup.

The gateway is also exposed as an **MCP server** (`npm run mcp`) so a real
agent framework can call it over the wire instead of only in-process.

## What this is not

Not the full MVP. No console UI, no real Slack integration (a console-log
stand-in plays that role), no Postgres. Those are later roadmap weeks. See the
"Roadmap to a demo-ready proof of concept" section of the product spec doc
for what comes next and in what order.

## Requirements

- Node.js 20 or later
- npm

## Setup

```bash
npm install
```

## Run the demo

```bash
npm run demo
```

This runs `src/demo/scenario.ts`: registers a refund-issuing agent, sets a
policy with an auto-allow threshold, a human-approval threshold, and a
stateful daily cumulative cap, then fires a sequence of refund calls that
exercise all three paths (allow, hold-for-approval, deny), resolves an
approval, queries the ledger, verifies the hash chain, and shows the kill
switch suspending the agent mid-flow.

Each run creates a fresh `demo-ledger.db` (SQLite) in this directory.

## Run it as an HTTP service

```bash
npm run server
```

Starts an HTTP server on port 8787 exposing the same registry, policy
engine, gateway and ledger over a plain REST API — see `src/gateway/server.ts`
for the routes.

## Run it as an MCP server

```bash
npm run mcp
```

Starts the same control plane as a Model Context Protocol server on **stdio**
(`src/gateway/mcp.ts`). Point an MCP client (Claude Agent SDK, LangGraph MCP
adapter, Cursor, etc.) at:

```json
{
  "command": "node",
  "args": ["dist/gateway/mcp.js"],
  "cwd": "/path/to/this/repo",
  "env": { "LEDGER_DB": "./mcp-ledger.db" }
}
```

Tools exposed: `register_agent`, `approve_agent`, `suspend_agent`,
`set_policy`, `governed_call`, `decide_approval`, `list_agents`,
`list_agent_events`, `verify_ledger`.

### MCP end-to-end smoke test

```bash
npm run demo:mcp
```

Spawns the MCP server as a child process and drives the same refund scenario
as `npm run demo`, entirely over MCP tool calls.

## Where the differentiator lives

- `src/policy/engine.ts` — the stateful velocity/cumulative rule evaluation.
  Most policy engines (OPA, Cedar) evaluate one request at a time; this adds
  a layer that looks back across the ledger to catch cumulative risk a
  single-call check would miss.
- `src/ledger/ledger.ts` — the hash-chained, append-only evidence log and
  its `verifyChain()` tamper check.

## Next steps toward the fuller MVP

1. Swap `ConsoleApprovalChannel` for a real Slack webhook implementation of
   the same `ApprovalChannel` interface (roadmap weeks 7-8).
2. Swap SQLite for Postgres by reimplementing the `Ledger` class against
   the same method signatures.
3. Add Streamable HTTP transport alongside stdio for remote MCP clients.
4. Add the bare console UI (a page listing agents, decisions, pending
   approvals) called for in roadmap weeks 9-10.
