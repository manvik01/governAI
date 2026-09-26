# Agent Governance Control Plane — Proof of Concept

This is the week 1-8 vertical slice from the product roadmap: registry →
policy engine (with a stateful rule) → gateway → hash-chained evidence
ledger → approval flow → kill switch. It proves the differentiator — a
stateful policy engine and tamper-evident evidence — with real, runnable
code, not a mockup.

The **MCP gateway** exposes business tools (`issue_refund`) with governance
applied server-side. Any MCP-capable agent framework (Claude Agent SDK,
LangGraph, OpenAI Agents SDK, …) calls the same tool; it does not need to
know about policies or the ledger.

## What this is not

Not the full MVP. No console UI, no real Slack integration (a console-log
stand-in plays that role), no Postgres. Those are later roadmap weeks.

## Requirements

- Node.js 20 or later
- npm

## Setup

```bash
npm install
```

## Run the in-process demo

```bash
npm run demo
```

Registers a refund agent, installs the policy (auto-allow ≤ SGD 200, human
approval above, stateful daily cap SGD 1,000), runs the allow / hold /
approve / deny sequence, verifies the hash chain, and demos the kill switch.

## Run as an HTTP service

```bash
npm run server
```

REST API on port 8787 — see `src/gateway/server.ts`.

## Run as an MCP gateway (roadmap week 5-6)

```bash
npm run mcp
```

Stdio MCP server (`src/mcp/server.ts`). Tools exposed to agents:

- `issue_refund` — governed business tool
- `check_approval` — poll a held call

Point any MCP client at:

```json
{
  "command": "node",
  "args": ["dist/mcp/server.js"],
  "env": { "LEDGER_DB": "./mcp-ledger.db" }
}
```

### Out-of-band approvals (separate OS process)

When a call is held, resolve it without the agent process touching the
decision — separation of duties across process boundaries:

```bash
LEDGER_DB=./mcp-ledger.db npm run mcp:approve -- decide <approvalId> approve
LEDGER_DB=./mcp-ledger.db npm run mcp:approve -- status <approvalId>
LEDGER_DB=./mcp-ledger.db npm run mcp:approve -- verify
```

### Protocol-level MCP test (no API key)

```bash
npm run mcp:test-client
```

Spawns the MCP server, drives the full refund sequence over real MCP stdio,
resolves a hold via a separate `mcp:approve` process, and verifies the hash
chain across three OS processes.

### Claude Agent SDK client

```bash
export ANTHROPIC_API_KEY=sk-ant-...
npm run agent:claude
```

Without a key the script exits with clear instructions; use `mcp:test-client`
to prove the gateway without a model.

### Admin MCP tools (optional)

`npm run mcp:admin` still exposes registry/policy/ledger admin tools from
`src/gateway/mcp.ts` for operators. Agents should use `npm run mcp` instead.

## Where the differentiator lives

- `src/policy/engine.ts` — stateful velocity/cumulative rule evaluation
- `src/ledger/ledger.ts` — hash-chained append-only evidence log + `verifyChain()`
- `src/mcp/server.ts` — same policy applied transparently to MCP tool calls

## Next steps toward the fuller MVP

1. Swap `ConsoleApprovalChannel` / `StderrApprovalChannel` for a real Slack webhook
2. Swap SQLite for Postgres (same `Ledger` method signatures)
3. Add Streamable HTTP MCP transport for remote clients
4. Bare console UI (roadmap weeks 9-10)
