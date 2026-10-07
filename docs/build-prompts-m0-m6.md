# governAI - build prompts for milestones M0 to M6

For Cursor (Agent mode) or Claude Code. These continue `docs/build-prompts.md` (A0-A10 built the
first slice) and follow the milestones in section 10 of `docs/PRD.md`.

## How to use

1. Work on branch `governai-control-plane` (or a branch cut from it), not the old `main`.
2. Do Prompt 0 once. Then one milestone per chat, one prompt per step, in order.
3. Every prompt starts with the same contract: plan first, wait for approval, tests with the code,
   show test output, stop at "Done when".
4. Commit after each green step. Review security-sensitive diffs yourself.
5. Replace anything in `[BRACKETS]` before pasting.

---

## Prompt 0. Project rules (create `AGENTS.md`, once)

```
Create AGENTS.md at the repo root with exactly these rules, then commit it.

# governAI project rules

Product: a control plane for AI agents. Every agent is registered, owned, reviewed and given its
own credential. Every call goes through one authenticated gateway that applies policy, reserves
budget, and writes a tamper-evident audit entry. Read docs/PRD.md before any task.

Invariants - never weaken these, never "fix" a test by relaxing one:
1. Order of checks on a model call: agent state -> permitted model -> policy/grant/approval ->
   budget -> provider -> reconcile -> bill. Budget can only add restriction. A denied call never
   reaches a provider.
2. Agent identity comes from its credential, never from the request body.
3. Every authentication failure returns the same 401. The reason goes to the audit log only.
4. Secrets (credentials, provider keys, tokens) are never logged, never stored in plaintext in
   the database, never printed except once at creation, never in error messages.
5. Money is integer micro-USD. No floating point for amounts.
6. Missing usage stays "unresolved" (NULL in the ledger), never zero.
7. The audit log is append-only and hash-chained. Nothing edits or deletes rows.
8. The gateway process keeps no durable state. Everything durable is in the database.
9. Separation of duties: owner, sub-owner and submitter cannot review their own agent; budget
   increases need a budget_admin who is not the requester.
10. Config only through environment variables. Container runs as non-root.

Working agreement:
- Before editing, post a plan: files to touch, tests to add, risks. Wait for approval.
- Write tests with the code. Run `npm test` and show the full output. Do not claim done on red.
- Do not add dependencies without saying why. Prefer the standard library.
- Do not touch files outside the task. If you find a bug elsewhere, report it, do not fix it.
- Stop at the "Done when" list and report what you did not do.
- Never put real keys in code, tests, fixtures, docs or commits. Use env vars and fakes.
```

---

## M0. Baseline

### M0.1 Reconcile with the other `main`

```
Context: origin/main contains a separate import of an earlier POC (commits 2405277, 5a3dbe5,
67358e2) from another tool. This branch has the superset. The only thing there that this branch
lacks is the transparent MCP gateway: src/gateway/mcp.ts and src/gateway/controlPlane.ts.

Task:
1. Run `git fetch origin` and `git diff HEAD...origin/main -- src/gateway/mcp.ts
   src/gateway/controlPlane.ts`. Read both files fully.
2. Plan how to bring that capability into this codebase on top of the secure gateway and the
   audit log, NOT the old gateway. Anything it does must go through authentication and write
   audit events. Show the plan and wait.
3. After approval: port it, add tests, run `npm test`.
Do NOT merge origin/main. Do NOT push. Do NOT touch main.
Done when: the capability works through the secure gateway, tests pass, no unauthenticated
route was added.
```

### M0.2 CI and container

```
Task:
1. Add .github/workflows/ci.yml: on push and pull request, Node 20, `npm ci`, `npm test`.
   Cache npm. Fail on any warning from `npm audit --audit-level=high --omit=dev`.
2. Build the Dockerfile for real: `docker build -t governai-gateway .`. Fix whatever breaks
   (native module better-sqlite3 build, missing files, permissions on /data).
3. Run it: `docker run -d -p 8787:8787 -v governai-data:/data -e GOVERNAI_DB_PATH=/data/governai.db
   governai-gateway`. Prove: GET /healthz and /readyz return 200 without credentials; any other
   route returns 401; `docker stop` exits within 10 seconds and logs a graceful shutdown; the
   process runs as a non-root user (`docker exec ... id`).
4. Scan the image with trivy or grype if available; list high/critical findings, do not fix
   silently.
Done when: CI file exists, image builds, the four proofs above are pasted as command output.
```

---

## M1. Deployable single node

### M1.1 Bootstrap admin CLI

```
Problem: a freshly deployed container has no users, no access profiles and no tokens, so nobody
can call any route. Build src/control/admin-cli.ts, exposed as `governai-admin` (bin in
package.json) and `npm run admin -- <command>`.

Commands (all read GOVERNAI_DB_PATH):
  init --admin-email <e> --admin-name <n>
      Create the schema, the default access profiles, and the first admin user. REFUSE if any
      admin already exists. Print one admin token ONCE to stdout, nothing else secret.
  user add|deactivate|list   (roles: admin, security_reviewer, budget_admin, auditor, agent_owner)
  token issue --email <e> --ttl-hours <n>   (admin only; prints once)
  profile list|add|show      (JSON file input; validate with the existing profile types)
  audit verify               (runs verifyChain, exit code 1 and the sequence number if broken)
  audit export --out <file>  (JSON lines)

Rules:
- Every CLI action writes to the USER stream with actor "cli:<os username>" and the command.
- Tokens are shown once and stored only as hashes, using the existing CredentialService.
- No secret in argv history: accept the admin email on argv but never a token or key; read any
  secret from stdin or an env var.
- Exit codes: 0 ok, 1 failure, 2 usage error. Errors never print stack traces by default.

Tests: init twice (second refused), init then issue token then call GET /v1/agents through the
secure gateway, deactivated user's token stops working, audit verify detects a tampered row.
Done when: from an empty volume, `docker run ... governai-admin init ...` followed by a curl with
the printed token succeeds, and the init is visible in the user stream.
```

### M1.2 Provider keys held by the gateway

```
Goal: agents must never hold a provider key. The gateway holds them.

Build src/providers/:
- types.ts: interface ModelProvider { name; invoke(req): Promise<ProviderResult> } where
  ProviderResult has text, stopReason, and usage {inputTokens, outputTokens, cachedInputTokens?}
  or usage: null when the provider did not report it.
- anthropic.ts and openai-compatible.ts (covers OpenAI, Azure OpenAI, vLLM, Ollama). Use fetch,
  no SDK unless you justify it. Non-streaming only for now.
- mock.ts: deterministic provider for tests, with a call counter and the ability to fail, time
  out, or omit usage.
- registry.ts: loads providers from env. Keys come from env var NAMES configured in
  GOVERNAI_PROVIDERS (JSON: [{"name":"anthropic","type":"anthropic","keyEnv":"ANTHROPIC_API_KEY",
  "baseUrl":"..."}]). The key value is read from process.env at call time. Never stored in the
  database, never logged, never in an error message, never returned by any route.

Wire the existing GovernedModelGateway to these providers. Map ProviderError categories to retry
vs fallback vs fail exactly as it does today.

Tests: a provider spy proves that a policy-denied call, a budget-blocked call, a suspended agent
and a non-permitted model each leave the call counter at 0. A thrown provider error containing
the key string is redacted before logging. Missing usage ends as unresolved.
Done when: the full existing budget test suite still passes and the new provider tests pass.
```

### M1.3 Model-call route on the secure gateway

```
Add to src/gateway/secure-server.ts, behind the same authentication, body limit and rate limits:

POST /v1/models/invoke   (agent credential only; human tokens get 403)
  body: { requestId, taskId, parentTaskId?, projectId, model, messages[], maxOutputTokens,
          fallbackModels?[] }
  - agentId comes from the credential. Reject a body that names a different agent and raise
    the identity_spoofing alert.
  - maxOutputTokens is REQUIRED (worst-case reservation needs it). 400 if missing or above the
    agent's configured ceiling.
  - requestId is the idempotency key: the same requestId returns the same result, never a
    second provider call or a second charge.
  - Responses: 200 with result and usage; 403 policy denied (with reason code, no policy
    internals); 202 held for human approval with approvalId; 402 budget exhausted with the
    standard exhaustion notice; 502 provider failure after retries.
  - Every outcome writes an audit event linked to the consumption-ledger row.

Budget administration (human tokens):
  POST /v1/budgets                      (admin or budget_admin)
  POST /v1/budgets/:scope/:id/increase  (budget_admin who is not the requester; changes no
                                         permissions - assert this in a test)
  POST /v1/tasks/:id/cancel             (task owner, owner of the agent, or admin)
  GET  /v1/budgets/:scope/:id, GET /v1/consumption?taskId=...

Tests: each response code; idempotent replay; spoofed agent id; human token on the agent route;
increase by the requester refused; 20 concurrent invokes against a budget that fits 12 -> exactly
12 succeed, 8 get 402, ledger totals reconcile to the micro-USD.
Done when: curl can run a model call end to end using the mock provider, and the denied-call and
over-allocation acceptance tests pass over HTTP, not just in-process.
```

### M1.4 Drop-in compatibility endpoint (integration surface)

```
Goal: let an existing agent adopt governAI by changing only its base URL and API key.

Add POST /v1/chat/completions (OpenAI-compatible request and response shape, non-streaming) and
POST /v1/messages (Anthropic-compatible shape, non-streaming). The "API key" the client sends is
the agent's governAI credential in the Authorization or x-api-key header.
- Map the compatible request onto the same code path as /v1/models/invoke. No second
  implementation of the control order.
- Extra governance fields travel in headers: X-Governai-Task, X-Governai-Parent-Task,
  X-Governai-Project, X-Governai-Request-Id. If task or project is missing, use the agent's
  default project and open a root task automatically, and record that in the audit event.
- Errors use the compatible error envelope so SDKs raise normal exceptions. Map 402 and 403 to
  the closest status the SDKs understand and put the governAI reason code in the message.
- Streaming requests (stream:true) return 400 "streaming not supported yet" - do not silently
  buffer.

Tests: use the official OpenAI and Anthropic SDKs pointed at the gateway with the mock provider
(devDependency only). A denied call surfaces as a normal SDK error.
Add docs/integration.md with a 10-line example for each SDK.
Done when: both SDK examples run against a local gateway and the calls appear in the audit log.
```

### M1.5 MCP proxy mode

```
Extend src/mcp/server.ts so a stdio MCP server forwards each governed tool call to the secure
gateway over HTTP using GOVERNAI_GATEWAY_URL and GOVERNAI_AGENT_TOKEN (env only). The MCP
server holds no policy logic and no database access of its own. If the gateway is unreachable
the tool call FAILS CLOSED with a clear error; it never falls back to calling the tool directly.
Tests: protocol-level test client; denied, held and allowed paths; gateway down -> fail closed.
Update README with a Claude Desktop / Cursor MCP config snippet using placeholders for the token.
Done when: the MCP test client passes against a real running secure gateway.
```

### M1.6 Backup, restore and the egress guide

```
1. `governai-admin backup --out <file>`: use better-sqlite3 `db.backup()` (online, consistent),
   then encrypt with AES-256-GCM using a key from env GOVERNAI_BACKUP_KEY (32 bytes, base64).
   `restore --in <file> --to <path>` decrypts, then runs verifyChain and refuses to finish if the
   chain is broken. Test: backup while writes are happening, restore, chain intact, row counts
   match a snapshot taken at backup start.
2. Write docs/deployment/egress.md: the customer must (a) give the gateway the only route to
   model providers, (b) block direct provider domains from agent hosts, (c) keep provider keys
   only in the gateway's secret store. Include sample rules for Docker network policy, a
   Kubernetes NetworkPolicy and a cloud security group, all with placeholders. State plainly that
   without (a) and (b) governance is advisory.
3. Add a startup warning when GOVERNAI_PROVIDERS is empty or when running without TLS in front.
Done when: restore test passes and the egress doc reads as a checklist a platform engineer can
follow.
```

### M1 independent review (fresh session or different model)

```
Review the changes since the last tag as a hostile security reviewer. Read AGENTS.md first.
Try to find: a path where a denied call reaches a provider; a response or log containing a
secret; a way an agent acts as another agent; a route missing authentication or a body limit;
a place money is a float; an audit event that can be skipped on an error path; a race in budget
reservation. For each finding give file, line, a failing test, and severity. Do not fix anything.
```

---

## M2. Human loop and visibility

### M2.1 Shadow mode and policy staging

```
Add a mode to every policy rule and to the budget controls: "enforce" (default) or "shadow".
In shadow mode the decision is computed and recorded as would_deny / would_hold /
would_block_budget, and the call proceeds.
Hard limits: authentication, agent lifecycle state, permitted-model and credential checks are
NEVER shadowed. Shadow applies only to policy rules, approval requirements and budget limits.
Add GET /v1/shadow/report?from=&to= grouped by agent and rule, with counts and sample request
ids, and POST /v1/policies/:id/promote to flip shadow to enforce (admin; audited with who/why).
Tests: a shadow deny proceeds and is logged as would_deny; promote then denies; authentication
failures are never shadowed.
Done when: the report shows what a week of traffic WOULD have blocked.
```

### M2.2 Discovery of unregistered agents

```
Build discovery from what the gateway already sees: credentials that fail authentication,
unknown agent ids, and (optionally) a CSV import of egress logs [FORMAT: source host, destination
domain, count, first and last seen].
Create a table discovered_agents (fingerprint, first_seen, last_seen, source, count, status:
new|registered|ignored). Fingerprint a source from non-secret attributes only (source address,
user agent, credential key id prefix). Never store a presented secret.
Routes: GET /v1/discovery, POST /v1/discovery/:id/ignore, POST /v1/discovery/:id/start-registration
(prefills a registration draft). Every transition is audited.
Done when: a test that sends calls with an unknown credential produces a discovery row, and
starting registration creates a draft owned by the caller.
```

### M2.3 Console UI

```
Build the console as a static single-page app in console/ (React + Vite + TypeScript), built to
console/dist and served by the gateway at /console. No server-side rendering, no third-party
analytics, no external fonts or CDNs (customers run this offline).

Auth: paste a user token; keep it in memory only (not localStorage); send it as a bearer header.
Roles hide screens, but the server remains the authority - never rely on the UI for security.

Screens:
1. Agents: table (name, owner, sub-owner, state, risk tier, last call, spend this month) with
   filters; agent detail with timeline, credentials (key id, expiry, never the secret), buttons
   for rotate and suspend with a mandatory reason field.
2. Register an agent: form that shows the access-profile ceiling next to each field and the
   server's refusal reason inline.
3. Review queue: the checklist, with approve/reject disabled until complete; shows why the current
   user may not review (separation of duties) rather than hiding the button.
4. Audit: search by actor, action, target, outcome, time; user vs audit stream toggle; "Verify
   chain" button showing the result; export.
5. Alerts: list with rule name, subject, count, first/last seen.
6. Budgets: org/project/agent/task tree with reserved, spent, unresolved; increase request.
7. Shadow report and Discovery.

Quality bar: keyboard accessible, readable at 1280px and 400px, empty/loading/error states on
every screen, no secret ever rendered after creation except the one-time reveal dialog with a
copy button and a warning.
Tests: component tests for the review-queue rules and the one-time reveal; one Playwright flow:
register -> review -> approve -> see credential once -> suspend.
Done when: that Playwright flow passes against a gateway started with a fresh volume.
```

### M2.4 Slack / Teams approvals

```
Implement SlackApprovalChannel behind the existing ApprovalChannel interface.
- On a held action, post a message to [CHANNEL] with approve/reject buttons and an expiry.
- Receive interactions at POST /v1/integrations/slack/interact. VERIFY the Slack signing secret
  and reject timestamps older than 5 minutes (replay). Constant-time compare.
- Map the Slack user to a governAI user by verified email; reject unmapped users and users
  without the required role.
- Separation of duties is enforced server-side: the requester, owner and sub-owner cannot
  approve, even if Slack lets them click.
- Update the Slack message with the outcome; write both the user-stream and audit-stream events.
- Expired approvals resolve as denied and are logged.
Secrets via env (SLACK_SIGNING_SECRET, SLACK_BOT_TOKEN). Teams can follow the same interface later.
Tests: bad signature, old timestamp, unmapped user, requester clicking approve, double click,
expiry. Use recorded fixtures; no network in tests.
Done when: all negative cases are refused and logged.
```

---

## M3. Design-partner pilot

### M3.1 Metering and pilot readiness

```
1. Add GET /v1/billing/summary?month= and GET /v1/billing/export?month= (CSV: provider cost,
   governance cost, platform fee, separately, per agent and project; each line carries the usage
   event id and pricing version). Test that every line traces to usage evidence.
2. Make the pricing book configurable by file (GOVERNAI_PRICING_FILE), versioned, with the
   active version recorded on every ledger row. Changing prices creates a new version; it never
   rewrites history.
3. Write scripts/weekly-findings.ts: prints, for the last 7 days, agents registered, calls
   governed, denials by rule, shadow would-denies, alerts, unresolved usage count, budget stops,
   audit chain status. Output Markdown for the partner review meeting.
4. Write docs/pilot-runbook.md: install, bootstrap, register the first agents, shadow for a week,
   promote rules, daily checks (chain verify, backup success), rollback, who to call. Include an
   exit checklist matching the M3 exit test in the PRD.
Done when: the findings script runs on a day of mock traffic and the billing export reconciles
to the ledger to the micro-USD.
```

---

## M4. Scale-out (large; do in stages, commit between each)

### M4.1 Repository interfaces

```
Goal: remove the dependency on synchronous SQLite without changing behaviour.
1. For each store (AgentRegistry, CredentialService, SqliteDirectory, AccessProfileStore,
   AuditLog, Ledger, ContextStore, BudgetStore, Billing, SecurityMonitor state) define an
   interface with ASYNC methods in src/repo/*.ts.
2. Re-implement the current SQLite code behind those interfaces (still better-sqlite3 inside,
   wrapped in async). Change every caller to await.
3. Do not change any behaviour. All 31+ tests must pass unchanged except for adding await.
Stage it: one store per commit, tests green after each. Show the plan and the order first.
Done when: no module outside src/repo/sqlite/ imports better-sqlite3.
```

### M4.2 Postgres

```
Implement the interfaces on Postgres with `pg` and a migration tool [node-pg-migrate or
drizzle - justify]. Requirements:
- Budget reservation: one transaction, SELECT ... FOR UPDATE on every budget row in the chain in
  a fixed order (org, project, agent, root task) to avoid deadlocks.
- Idempotency keys via unique constraints and INSERT ... ON CONFLICT.
- Audit hash chain: a single serialised write path using pg_advisory_xact_lock; document the
  throughput ceiling and measure it.
- Same test suite runs against both backends (matrix: sqlite, postgres via testcontainers).
- Migrations are forward-only and reviewed; include a data-copy script from SQLite and verify
  the audit chain after copy.
Done when: the full suite passes on Postgres and the cross-process race test is replaced by a
multi-connection race test with the same assertions.
```

### M4.3 Redis and the scale-out test

```
Move rate-limit counters and security-monitor windows to Redis (atomic INCR with TTL, or a
sorted-set window). Keep an in-memory fallback ONLY for single-node mode, selected by config,
never silently. If Redis is down in multi-replica mode, fail closed for authentication-failure
counting (stricter) and report not-ready on /readyz.
Add deploy/compose.scale.yml (3 gateway replicas, Postgres, Redis, a load balancer) and
scripts/scale-test.ts: N clients, M replicas, shared budget that fits K calls.
Pass criteria: exactly K succeed, no over-allocation, audit chain intact, rate limits enforced
globally, SIGTERM on a replica drops zero in-flight calls.
Add Kubernetes manifests with an HPA on CPU and request latency [CLOUD/CLUSTER details].
Done when: scale-test passes three times in a row.
```

---

## M5. Enterprise identity and evidence

### M5.1 OIDC login and SCIM

```
Replace the stand-in user tokens for humans with OIDC authorisation-code + PKCE against [IdP:
Entra ID / Okta / Google]. Validate issuer, audience, expiry, signature (JWKS with caching and
rotation), nonce. Roles come from the directory (SCIM-synced), not from token claims alone.
Implement SCIM 2.0 /Users and /Groups (bearer-protected, separate credential): create, update,
deactivate. Deactivation must revoke that user's sessions and block them as owner immediately.
Tests with a local mock IdP: expired token, wrong audience, key rotation, deactivated user,
group-to-role mapping. Keep the old tokens only behind an explicit GOVERNAI_ALLOW_LOCAL_TOKENS
flag, off by default, logged at startup.
```

### M5.2 Short-lived agent credentials

```
Add OAuth2 client-credentials style issuance: the long-lived agent secret is exchanged at
POST /v1/oauth/token for a signed token valid [5-15] minutes, carrying agent id, key id and
scopes. The gateway verifies signature and checks revocation. Suspension must still take effect
within the revocation-cache TTL (state it, test it, make it configurable, default 30 seconds).
Optional: mTLS client certificate binding behind a flag. Do not invent crypto: use `jose`.
```

### M5.3 Retention, export and tenancy

```
1. Retention: per-stream retention policy and legal hold. Expired rows are archived to signed,
   hash-linked segment files before removal; the chain keeps a checkpoint so verifyChain still
   works across archived segments. Nothing is deleted while a hold is active.
2. OTel / OCSF export: map audit events to OCSF classes, emit via OTLP; keep the JSON-lines sink.
3. Tenancy: add tenant_id to every table and every query via a repository-level guard (not
   per-route). Row-level security in Postgres as defence in depth. Separate hash chain per
   tenant. A test suite proves tenant A cannot read, write, approve, spend from, or alert on
   tenant B, including via IDs guessed in URLs.
```

---

## M6. Assurance and launch

```
1. Threat model: write docs/threat-model.md using STRIDE across the gateway, admin CLI, console,
   Slack integration, SCIM and backups. For each threat: control, test that proves it, residual
   risk. Flag anything without a test.
2. Fuzz and abuse tests: malformed JSON, oversize bodies, header injection, unicode in ids,
   SQL-metacharacters, very long tokens, concurrent rotate/suspend.
3. Supply chain: lockfile review, `npm audit`, SBOM (CycloneDX), image signing, pinned base image
   digest, Dependabot or Renovate.
4. Standards mapping: for each row in PRD section 6 and each control you claim, fetch the CURRENT
   published text and cite the exact clause. Mark every claim "verified" or "unverified".
   Do not write a clause number from memory.
5. SLOs and runbooks: p95 added latency, availability, RPO/RTO; alerts and the on-call steps.
6. Prepare the penetration-test brief: scope, credentials, test accounts, out-of-scope items.
Done when: a customer security questionnaire can be answered with links into the repo.
```

---

## Recovery prompts (use when Cursor drifts)

```
Stop. List every file you changed that is not in the approved plan, and revert those changes.
```

```
Tests are red. Do not edit any test. Explain the cause in two sentences, then fix the code.
If you believe the test itself is wrong, show me the evidence and wait.
```

```
Before you say it is done: list each "Done when" item and the command output that proves it.
```

```
Review your own diff against AGENTS.md invariants 1 to 10. For each, say pass or fail with a
file and line. Fix failures.
```
