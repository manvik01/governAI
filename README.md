# governAI

## Agent Governance Control Plane — Proof of Concept

This is the week 1-8 vertical slice from the product roadmap: registry →
policy engine (with a stateful rule) → gateway → hash-chained evidence
ledger → approval flow → kill switch. It proves the differentiator — a
stateful policy engine and tamper-evident evidence — with real, runnable
code, not a mockup.

## What this is not

Not the full MVP. No console UI, no real Slack integration (a console-log/
stderr stand-in plays that role), no Postgres, and only one agent framework
has a working example client so far (Claude Agent SDK). Those are later
roadmap weeks. See the "Roadmap to a demo-ready proof of concept" section
of the product spec doc for what comes next and in what order.

## Requirements

- Node.js 20 or later
- npm
- An `ANTHROPIC_API_KEY` only if you want to run the real Claude Agent SDK
  demo (`npm run agent:claude`) — everything else needs no API key.

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

## Run it as a plain HTTP service

```bash
npm run server
```

Starts an HTTP server on port 8787 exposing the same registry, policy
engine, gateway and ledger over a plain REST API — see `src/gateway/server.ts`
for the routes. Useful for testing from curl or a non-MCP caller; the real
agent-facing integration is the MCP server below.

## Govern real agents over MCP

The governance layer is also exposed as a standard MCP server, so any
MCP-capable agent framework can call it the same way it calls any other
tool server — the policy engine and ledger are identical to the in-process
demo above; only the transport is different.

**1. See it work without a model, over the real MCP protocol:**

```bash
npm run mcp:test-client
```

This starts `src/mcp/server.ts` as a child process (real stdio MCP
transport), connects a real MCP client to it, discovers its tools, and
runs the same allow/hold/deny sequence as the CLI demo — but this time an
approval is resolved by a *separate* process (`src/mcp/approve.ts`) reading
and writing the same SQLite ledger, proving the separation-of-duties model
holds across processes, not just across function calls.

**2. Resolve a held approval manually, from another terminal, while a
server is running:**

```bash
GOVERNAI_DB_PATH=./mcp-ledger.db npm run mcp:approve -- list
GOVERNAI_DB_PATH=./mcp-ledger.db npm run mcp:approve -- decide <approvalId> approve
```

**3. Run a real Claude agent against it:**

```bash
export ANTHROPIC_API_KEY=sk-...
npm run agent:claude
```

`src/demo/claude-agent-demo.ts` uses the Claude Agent SDK's `query()` with
`options.mcpServers` pointed at `dist/mcp/server.js`. Claude decides on its
own to call `issue_refund`, and the policy check happens entirely on the
server side — the agent framework has no idea governance is involved. This
is the pattern to copy for LangGraph, the OpenAI Agents SDK, or Google ADK:
none of `src/mcp/server.ts` changes, only how each framework is told to
connect to it.

## Where the differentiator lives

- `src/policy/engine.ts` — the stateful velocity/cumulative rule evaluation.
  Most policy engines (OPA, Cedar) evaluate one request at a time; this adds
  a layer that looks back across the ledger to catch cumulative risk a
  single-call check would miss.
- `src/ledger/ledger.ts` — the hash-chained, append-only evidence log and
  its `verifyChain()` tamper check, proven above to survive multi-process
  writes from three separate Node processes.
- `src/mcp/server.ts` — the same governance, reachable as a standard MCP
  server, independent of which agent framework calls it.

## Next steps toward the fuller MVP

1. Swap `ConsoleApprovalChannel`/`StderrApprovalChannel` for a real Slack
   webhook implementation of the same `ApprovalChannel` interface (roadmap
   weeks 7-8).
2. Swap SQLite for Postgres by reimplementing the `Ledger` class against
   the same method signatures.
3. Add example MCP clients for LangGraph, the OpenAI Agents SDK, and
   Google ADK, following the pattern in `src/demo/claude-agent-demo.ts` —
   the server needs no changes for any of them.
4. Add the bare console UI (a page listing agents, decisions, pending
   approvals) called for in roadmap weeks 9-10.

