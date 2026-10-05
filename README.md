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

## Context layer + multi-agent task graph (no LLM memory)

```bash
npm run context:demo
```

This is the piece that answers "govern a whole multi-agent ecosystem,
without any of the context or decisions living in an LLM's memory." Three
new modules, same append-only/versioned discipline as the ledger above:

- `src/context/store.ts` — **Context Store**. Every workflow, persona,
  condition, decision-matrix policy, goal, milestone and timeline event is
  a versioned row (`ContextStore.upsert`), never a value baked into a
  prompt. A write never overwrites — it closes the prior version and
  inserts a new one, so `ContextStore.asOf(entityId, timestamp)` can
  reconstruct exactly what was true when any past decision was made.
- `src/context/matrix.ts` — **Decision Matrix evaluator**. Reads
  `policy`-kind rows fresh from the Context Store and evaluates them
  against a structured fact bag, first-match-wins — the same pattern as
  `policy/engine.ts`, generalized beyond refund amounts to any domain
  (sales routing, ops triage, approval thresholds). An LLM is trusted to
  turn an ambiguous event into structured facts; it is never trusted to
  decide the outcome — that's this pure function.
- `src/orchestration/task-graph.ts` + `master-agent.ts` — **"every agent
  has its own sub-task, no one works in silos."** `decomposeGoal()` reads
  a Goal's Workflow out of the Context Store and expands it into one Task
  row per step, each owned by exactly one sub-agent role, wired by
  `dependsOn`. A sub-agent only ever sees its own task's scoped `input`;
  it writes its result back as that task's `output` — into the same
  storage every other agent and the Master Agent read, not into a private
  transcript. `summarizeGoal()` is the Master Agent's entire "read the
  same memory, give a summarized action and output" loop: a deterministic
  rollup query over tasks/milestones/timeline, never a re-explanation from
  conversational memory. Kill the process and re-run it from scratch — you
  get the identical summary, because nothing depended on continuity.

The demo seeds one workflow (qualify → quote → finance review → close, 4
steps across 3 roles), runs it end to end with simulated sub-agents, and
prints the Master Agent's rollup. To make a step "real," swap its
simulated `work()` callback in `src/orchestration/demo.ts` for an actual
Claude Agent SDK call scoped to that task's `input` — the task graph,
context store, and decision matrix don't change.

## Governed token consumption and cost management

```bash
npm test            # 16 acceptance tests, incl. a cross-process budget race
npm run budget:demo # parent task -> 3 child agents under one shared budget
```

Every model call goes through `GovernedModelGateway` (`src/budget/`), in a
fixed order: agent state -> permitted model -> policy/grant/approval ->
**budget** -> provider -> reconcile -> bill. Security checks run before the
budget is read, so available budget can never turn a deny or a human-approval
hold into an allow, and a denied call never reaches the provider.

- `budget-store.ts` — org/project/agent/root-task budgets, atomic reservation
  (one write-locked transaction across all levels), reconciliation idempotent
  on usage-event id, the append-only consumption ledger, authorised increases
  (separation of duties; touch no permissions), task cancellation.
- `billing.ts` — provider cost, governance-processing cost and platform fee
  stored separately; unique idempotency key per request attempt; explicit
  treatment of failed, retried, blocked and unresolved calls; `trace()` walks
  a bill back to its usage evidence and pricing snapshot.
- `pricing.ts` — versioned, snapshotted pricing; integer micro-USD throughout.

Missing usage stays `unresolved`: the estimate stays held, ledger values are
`NULL` (never 0) and nothing is billed until real usage arrives. The refined
PRD, with the decisions taken on each gap in the original, is in
[`docs/prd-governed-token-consumption.md`](docs/prd-governed-token-consumption.md).

## Agent onboarding, authenticated gateway, audit and security monitoring

```bash
npm test                       # 31 tests across budget and control plane
GOVERNAI_DB_PATH=./governai.db npm run server   # authenticated gateway on :8787
docker build -t governai-gateway .              # container (Dockerfile not yet built in CI)
```

- `src/control/registration.ts` — owner and sub-owner verified against an identity
  directory, request fitted to an administrator-defined access profile, human security
  review with a checklist and separation of duties, one-time per-agent credentials.
- `src/gateway/secure-server.ts` — every route authenticated; agent identity comes from
  its credential; identical 401 for every failure; rate limits; `/healthz` and `/readyz`;
  graceful shutdown.
- `src/control/audit-log.ts` — user and audit streams in one hash-chained log, secrets
  redacted at write time, JSON-lines SIEM sink, integrity check.
- `src/control/security-monitor.ts` — seven detection rules writing alerts into the chain.

`npm run server:dev` is the old unauthenticated server, for local experiments only.
Requirements: [`docs/PRD.md`](docs/PRD.md). Step-by-step prompts for building this in
Claude Code, Cursor or Google AI Studio: [`docs/build-prompts.md`](docs/build-prompts.md).

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

