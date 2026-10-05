# Build prompts for governAI

How to build the product with Claude Code, Cursor or Google AI Studio, one stage at a time.
Each prompt is self-contained and ends with a "done when" check. Paste them in order; do not
start the next until the previous one's tests pass.

Product requirements: `docs/PRD.md` (and `docs/prd-governed-token-consumption.md`).
A working reference implementation of every stage is in `src/` of this repository.

---

## 1. Which tool for what

| Tool | Use it for | Notes (from each vendor's documentation) |
|---|---|---|
| **Claude Code** | The backend: control plane, gateway, tests, refactors | Runs in the terminal, VS Code and JetBrains extensions, a desktop app and the web. The VS Code extension also installs into Cursor. Reads `CLAUDE.md` for standing instructions; supports sub-agents, hooks and MCP. The Agent SDK (Python, TypeScript) is the library for building your own agents. |
| **Cursor** | The same backend, if you prefer an IDE | Standing instructions go in `.cursor/rules/*.mdc` (always-apply, file-scoped, or manual), or in an `AGENTS.md`. Use plan-then-implement for each prompt below. |
| **Google AI Studio (Build mode)** | The console UI prototype | Generates a React front end with a Node server runtime; supports secrets, Firestore and Auth; deploys to Cloud Run; two-way GitHub sync or ZIP export. Its storage is limited to network-accessible databases, so do not try to host the SQLite control plane in it. Point the UI at the gateway's REST API instead. |

Suggested split: **backend in Claude Code or Cursor** (prompts A0-A10), **console UI in AI Studio**
(prompts U0-U3) calling the backend over HTTPS. Product details of these tools change quickly;
check each vendor's current documentation before relying on a specific feature.

---

## 2. Standing instructions (paste once)

Save as `AGENTS.md` (Cursor, and read by Claude Code alongside `CLAUDE.md`) or as a Cursor always-apply rule.

    # governAI - standing instructions

    Product: a governance control plane for AI agents across providers and platforms. Registration,
    identity, policy, budget, audit. Language: TypeScript on Node 22, ESM (NodeNext), strict mode.
    Storage: SQLite via better-sqlite3 for the prototype, written so it can move to Postgres.
    HTTP: Express. Tests: node:test. Money: integer micro-USD only, never floats.

    Invariants - never break these, and add a test whenever you touch code near them:
    1. Security before budget. A denied or approval-held call never reserves budget and never reaches a provider. No code path lets budget turn a deny into an allow.
    2. No state in model memory. Policy, context and decisions are stored rows evaluated in code. A model call is stateless.
    3. Every event is logged, including failures, denials and attacks. Two streams: "user" (human actions) and "audit" (system). Hash-chained. Secrets are never logged; redact sensitive keys at write time.
    4. Credentials are shown once and stored only as SHA-256 hashes. Compare in constant time. Every authentication failure returns the same 401; the real reason goes only to the audit log.
    5. An agent's identity comes from its credential, never from the request body.
    6. Separation of duties: owners, sub-owners and submitters cannot review their own agent or approve their own budget increase.
    7. Reservations are atomic (one write-locked transaction). Missing usage stays unresolved, never zero. Billing is idempotent.
    8. The gateway process is stateless apart from short-lived counters; everything durable is in the database.

    Working rules: write the tests first or alongside; run the full suite before saying you are done;
    keep functions small; comment WHY, not what; no new dependencies without saying why; commit after each green stage.

---

## 3. Backend prompts (Claude Code or Cursor)

In Cursor, switch to Plan mode, paste the prompt, review the plan, then run it. In Claude Code, ask for a plan first.

### A0. Scaffold

    Create a TypeScript project for "governAI": Node 22, ESM with NodeNext module resolution, strict mode,
    outDir dist, rootDir src. Dependencies: better-sqlite3, express, nanoid, zod. Dev dependencies: typescript,
    @types/node, @types/express, @types/better-sqlite3. npm scripts: build (tsc), test (build, then
    node --test --test-force-exit on the compiled test files). Add .gitignore (node_modules, dist, *.db, *.db-*).
    Create src/types.ts with these types: Agent, ToolGrant, ActionRequest, Decision ("allow"|"deny"|"hold_for_approval"),
    LifecycleState ("draft"|"pending_approval"|"active"|"suspended"|"rejected"|"retired"), RiskTier,
    AutonomyLevel ("A0".."A4"), SecurityReview, BudgetPolicy.
    Done when: npm run build and npm test both succeed on an empty test.

### A1. Audit and user logs

    Implement src/control/audit-log.ts. One append-only table audit_events with two streams, "audit" (system,
    agents, anonymous) and "user" (humans). Fields: id, seq (unique, increasing), ts, stream, actorType
    (user|agent|system|anonymous), actorId, action (dotted verb), targetType, targetId, outcome
    (success|denied|failure), sourceIp, requestId, details (JSON), prevHash, hash.
    - hash = SHA-256 over all fields plus prevHash; the first event chains to 64 zeros.
    - append() runs in one write-locked transaction (read last row, insert) so concurrent writers cannot fork the chain.
    - Any event whose actorType is "user" is forced into the "user" stream.
    - details is redacted at write time: any key matching secret|token|password|api key|authorization becomes "[redacted]", recursively.
    - query(filter), exportJsonl(), verifyChain() returning -1 if intact or the seq of the first bad row.
    - Pluggable sinks (interface AuditSink) and listeners; a failing sink or listener must never fail append().
    - A JsonLinesSink that appends each event to a file (the SIEM tail target).
    Tests: chain verifies; editing a row is detected at that row; deleting a middle row is detected at the next row;
    redaction works for nested keys; a throwing sink does not break append; user actor forced into user stream.
    Done when: all tests pass.

### A2. Identity, credentials, access profiles

    Implement three modules under src/control/.
    1. identity.ts: an IdentityDirectory interface (lookup(email) -> {email, displayName, active, roles}) and a
       SQLite implementation. Roles: admin, security_reviewer, budget_admin, auditor, agent_owner. Comment that the
       production version is an OIDC/SCIM-backed lookup.
    2. credentials.ts: token format "gai.<a|u>.<keyId>.<secret>"; secret is 32 random bytes base64url; store only
       the SHA-256 hash; verify() uses timingSafeEqual and returns {ok, kind, subject} or {ok:false, reason} where
       reason is malformed|unknown_key|bad_secret|revoked|expired. Provide issueAgentCredential (default 90 days),
       issueUserToken, rotateAgentCredential (revokes all earlier ones), revokeAll.
    3. access-profiles.ts: AccessProfile {id, name, allowedTools (or "*"), allowedDataClasses, allowedModels,
       maxAutonomy, requiresSecurityReview} with a store, and profileViolations(profile, request) returning
       human-readable reasons (tool, data class, model, autonomy).
    Tests: secrets are never stored in plaintext; constant-time compare path exercised; expiry and revocation honoured;
    each profile violation type is reported with a specific message.
    Done when: all tests pass.

### A3. Persistent registry and registration workflow

    Make the agent registry persistent in SQLite (agents and agent_grants tables) with the same API as an in-memory
    registry: register, approve, reject, suspend, get, grantsFor, isActive, list. Registry.register refuses a missing
    owner, purpose, permitted models or budget policy. Risk tier: critical if autonomy A4 with money or irreversible
    tools; high if money and irreversible; medium if money or PII; else low. High and critical start pending_approval.
    Add a setChangeListener so that EVERY state change emits an event (action, agentId, actor, details); the control
    plane writes each as an audit-log entry, human actors to the user stream.
    Then implement src/control/registration.ts, a RegistrationService:
    - submit(request, submittedBy): verify submitter, owner and sub-owner are active directory users; owner and
      sub-owner hold agent_owner and are different people; submitter is owner, sub-owner or admin; the access profile
      exists and the requested tools, data classes, models and autonomy fit inside it. Collect ALL violations. On any
      violation: log a denied "agent.register" event in the user stream and return the list. Otherwise register; if no
      review is needed, issue a credential immediately, else issue none.
    - review(agentId, reviewer, decision, checklist, notes): agent must be pending_approval; reviewer holds
      security_reviewer and is not the owner, sub-owner or submitter; approval needs every checklist item true
      (identity_verified, least_privilege_reviewed, data_classification_confirmed, logging_enabled, kill_switch_tested).
      Approve -> activate and issue a credential; reject -> rejected.
    - suspend(agentId, by, reason): admin, security reviewer, owner or sub-owner; also revokes all credentials.
    - rotateCredential(agentId, by): owner, sub-owner or admin; active agents only.
    Tests: every refusal case above, each producing a user-log entry; no credential before review; separation of duties
    (a reviewer who is also the sub-owner is refused); registry state survives closing and reopening the database.
    Done when: all tests pass.

### A4. Policy engine, governance ledger, approvals

    Implement a policy engine that decides allow, deny or hold_for_approval for one tool call.
    Order: agent exists -> agent is active -> agent holds a grant for the tool (default deny) -> the tool's policy rules
    in order, first match wins -> default decision. Two rule kinds:
    - parameter_threshold: fires when a numeric parameter exceeds a limit.
    - velocity (the stateful differentiator): looks back N minutes in the ledger and fires on call count or on the
      cumulative value of a numeric field. Per-call rules must be evaluated before velocity rules.
    Implement a governance ledger (SQLite, append-only, hash-chained like the audit log) recording every decision with
    policy id and version, and an approvals table. A Gateway class wraps evaluate -> ledger append -> (for holds)
    record approval and notify an ApprovalChannel interface (console and stderr implementations).
    Approvals are resolved from a separate process or route, never by the agent itself.
    Tests: default deny without a grant; suspended agent denied; threshold hold; cumulative cap denies a small call once
    the day's total would be exceeded; chain verification; an approval cannot be resolved twice.
    Done when: all tests pass.

### A5. Secure gateway

    Implement src/gateway/secure-server.ts exporting createSecureGateway(controlPlane, options) returning an Express app.
    Middleware order: request id and source IP (honour X-Forwarded-For only when trustProxy is set) -> /healthz and
    /readyz (no auth; readyz checks the database) -> JSON body parser with a size limit (413 on too large, 400 on
    malformed, both audit-logged as request.malformed) -> per-IP rate limit before authentication -> authentication
    (Bearer token; every failure returns the identical 401 {"error":"unauthorized"}; the precise reason goes to the
    audit log as auth.failed) -> per-subject rate limit -> auth.success audit event.
    Agents must still be active; users must still be active in the directory (a leaver loses access immediately).
    Routes:
      POST /v1/call                         agent only. Identity from the credential; a different agentId in the body ->
                                            403 plus an identity.mismatch event. Runs the gateway, logs gateway.call with
                                            a link to the ledger event id.
      POST /v1/agents                       roles agent_owner or admin; runs submit(); 201 with the one-time credential if
                                            activated, or 422 with the list of violations.
      GET  /v1/agents                       admin, auditor, security_reviewer see all; owners see only their own.
      POST /v1/agents/:id/review            security_reviewer.
      POST /v1/agents/:id/suspend           via the service rules.
      POST /v1/agents/:id/credentials/rotate
      GET  /v1/audit                        auditor or admin; reading it is itself logged in the user stream.
      GET  /v1/audit/verify                 {intact, firstBrokenSeq}.
      GET  /v1/security/alerts
    The process entry reads GOVERNAI_DB_PATH, GOVERNAI_SIEM_PATH, PORT, TRUST_PROXY, RATE_LIMIT_PER_MIN and drains
    gracefully on SIGTERM.
    Tests (start the app on port 0 and use fetch): the identical-401 property across missing/garbage/wrong-secret;
    human token refused on /v1/call; suspension and rotation kill credentials immediately; agent-impersonation refused;
    role checks; owners see only their agents; every route produces its log entry.
    Done when: all tests pass.

### A6. Security monitor

    Implement src/control/security-monitor.ts. It subscribes to the audit log and raises alerts. Rules:
    auth_failure_burst (N failures from one source in a window), dead_credential_used (revoked or expired credential
    presented), identity_spoofing (identity.mismatch), credential_new_source (a known agent credential seen from a
    never-before-seen address; the first address is the silent baseline), policy_probing (N denied gateway calls by one
    agent in a window), rate_limit_abuse, malformed_request_burst.
    Alerts: stored in security_alerts, written back to the audit log as security.alert (and ignored by the monitor
    itself to avoid loops), forwarded to sinks, de-duplicated per rule and subject during a cooldown.
    Use event timestamps, not the wall clock, so tests are deterministic. Comment that windows are per-process and must
    move to shared state before running several replicas.
    Tests: 12 failures from one address give exactly one alert; new-source alert on the second address only; policy
    probing; alerts appear in the API, the audit chain and the SIEM file.
    Done when: all tests pass.

### A7. Token consumption and cost management

    Implement src/budget/ per docs/prd-governed-token-consumption.md.
    - pricing.ts: versioned pricing books (per-model input and output micro-USD per million tokens, governance cost per
      call, platform fee in basis points, chargeGovernanceOnBlocked flag). Round up. Snapshot the book into a table on
      first use so any bill can be recomputed.
    - budget-store.ts: budgets at org, project, agent and root-task level. reserve() runs in one write-locked
      transaction: if any configured level cannot admit the estimate, refuse and reserve nothing; otherwise hold the
      estimate at every level. Idempotent on request id. reconcile() is idempotent on the usage-event id (a replay is
      ignored and logged; a different usage event for a settled request is rejected). release() only when the provider
      confirmed no usage. markUnresolved() keeps the estimate held and leaves tokens and cost NULL in the ledger.
      Expired reservations become unresolved, never released. increaseBudget() needs an authorised approver who is not
      the requester and touches nothing but the limit. cancelTask() blocks new reservations only.
      An append-only consumption ledger records tenant, project, agent, task, parent task, root task, request id,
      provider, model, tokens, estimated and reconciled cost, policy version, approval reference, status, pricing version.
    - billing.ts: provider, governance and platform fee stored separately; unique idempotency key per request attempt;
      treatments for completed, failed with usage, failed without usage, blocked, unresolved; trace() walks a bill to its
      usage evidence and pricing snapshot.
    - model-gateway.ts: control order agent state -> permitted model -> policy -> budget -> provider -> reconcile -> bill.
      maxOutputTokens is mandatory and the worst case is reserved. Retries and fallback models re-run every check and charge
      the root task. A fallback model not in the agent's permitted list is blocked.
    Tests (name them after the PRD criteria): denied call never reaches the provider; parallel children cannot
    over-allocate, in one process and across several OS processes sharing the database file; duplicate usage creates one
    charge; budget increase leaves grants and policy unchanged; every bill traces to usage and pricing.
    Done when: all tests pass.

### A8. Context layer and orchestration

    Implement a context store: one table of versioned entities (workflow, persona, condition, policy, goal, milestone,
    timeline, fact). A write never overwrites; it closes the current version and inserts the next. Provide upsert,
    getCurrent, listCurrent(kind, domain), history and asOf(entityId, timestamp).
    Implement a decision-matrix evaluator that reads policy rows from the store and evaluates structured conditions
    (eq, neq, gt, gte, lt, lte, in, exists on dotted paths), first match wins.
    Implement a task graph: decomposeGoal() expands a goal's workflow into one task per step, each owned by one role,
    with dependsOn; readyForRole(), claim(), complete() (promotes dependants), fail(). summarizeGoal() builds the master
    agent's summary purely by reading the store and graph.
    Tests: asOf returns what was true at a past time; dependency order is enforced; a restarted process produces an
    identical summary; no sub-agent can claim another role's task.
    Done when: all tests pass.

### A9. Connect real agents (MCP)

    Expose the gateway as an MCP server over stdio using @modelcontextprotocol/sdk (McpServer.registerTool with zod
    schemas). Write operator logs to stderr only; stdout is reserved for the protocol. Add a protocol-level test client
    that lists tools and runs allow, hold and deny cases, and a CLI that resolves approvals from a separate process.
    Then add an example using the Claude Agent SDK query() with options.mcpServers pointing at the server and
    allowedTools in the form mcp__<server>__<tool>. Guard cleanly when ANTHROPIC_API_KEY is unset.
    Done when: the test client passes without an API key.

### A10. Container and deployment

    Add a multi-stage Dockerfile (build stage compiles and prunes dev dependencies; runtime stage is node slim, non-root,
    a /data volume, HEALTHCHECK on /readyz, CMD running the secure gateway). Add docker-compose.yml with the gateway plus
    a volume. Document the environment variables. Then write docs/scale-out.md describing the move to several replicas:
    Postgres instead of SQLite (SELECT ... FOR UPDATE on budget rows), Redis for rate limits and monitor windows, an
    advisory lock for the audit chain writer, OIDC for human tokens, SCIM for the directory, and a horizontal autoscaler
    keyed on request rate and latency using /healthz and /readyz.
    Done when: docker build and docker run succeed locally and /readyz returns 200.

### A-final. Independent review (use a fresh session or a different model)

    Review this repository as a security engineer. Without being told what the code is meant to do beyond docs/PRD.md,
    try to break these properties and report each with a failing test where you can: (1) a denied call reaches a provider
    or reserves budget; (2) two concurrent callers over-allocate a budget; (3) a secret appears in the database, audit
    log, SIEM file or an error response; (4) an agent acts as another agent; (5) an owner approves or reviews their own
    agent; (6) an audit entry can be edited or removed without detection; (7) authentication failures reveal why they failed;
    (8) a deactivated user or suspended agent keeps working. List anything the PRD requires that the code does not do.

---

## 4. Console UI prompts (Google AI Studio Build mode)

First give AI Studio the API contract so it does not invent endpoints. The gateway base URL and a human user token are
entered in a settings screen and kept only in memory (never in local storage or in the generated source).

### U0. API contract (paste first)

    Build against exactly this REST API. Base URL comes from a settings field. Every request sends
    "Authorization: Bearer <token>". Errors: 401 {"error":"unauthorized"}, 403 {"error":"forbidden"},
    422 {"error":"validation_failed","violations":[string]}, 429 {"error":"rate_limited"}.
      GET  /v1/agents                          -> {agents:[{id,name,owner,subOwner,lifecycleState,riskTier,accessProfileId}]}
      POST /v1/agents                          body: name, purpose, ownerEmail, subOwnerEmail, accessProfileId, businessUnit,
                                               platform, modelProvider, modelVersion, autonomyDefault, mode, tools:[{toolName,
                                               reversible,dataClasses:[string]}], permittedModels?:[string], budgetPolicy:{agentLimitMicro?,
                                               defaultTaskLimitMicro?}
                                               -> 201 {agentId, lifecycleState, riskTier, needsReview, credential?:{token,expiresAt}}
      POST /v1/agents/:id/review               body: decision ("approve"|"reject"), checklist:{identity_verified,
                                               least_privilege_reviewed, data_classification_confirmed, logging_enabled,
                                               kill_switch_tested: boolean}, notes?
      POST /v1/agents/:id/suspend              body: reason
      POST /v1/agents/:id/credentials/rotate   -> {credential:{token,expiresAt}}   (token is shown once)
      GET  /v1/audit?stream=&actor=&action=&target=&limit=   -> {events:[{seq,ts,stream,actorType,actorId,action,targetType,
                                               targetId,outcome,sourceIp,requestId,details,hash}]}
      GET  /v1/audit/verify                    -> {intact:boolean, firstBrokenSeq:number|null}
      GET  /v1/security/alerts                 -> {alerts:[{id,ts,rule,severity,subject,details,status}]}
    Money fields are integer micro-USD (1,000,000 = 1 USD); always display as dollars.
    Do not add any other endpoint. If a screen needs data this API does not provide, show a clearly labelled placeholder.

### U1. Shell and agent registry screens

    Build a React console for governAI. Left navigation: Agents, Review queue, Audit log, Security alerts, Settings.
    Settings: base URL and token fields, held in memory only, with a "Test connection" button calling GET /v1/agents.
    Agents screen: a table (name, owner, sub-owner, lifecycle state as a coloured badge, risk tier) with a "Register agent"
    button. The registration form validates on the client (required fields, owner and sub-owner differ) but ALWAYS shows
    the server's violations list verbatim on a 422, grouped as a readable list. After a 201 with a credential, show the token
    once in a modal with a copy button and the warning "This is the only time it will be shown".
    Agent detail drawer: owners, access profile, status, buttons Suspend (asks for a reason) and Rotate credential
    (asks for confirmation, shows the new token once). Disable buttons the signed-in role cannot use, but rely on the server
    for enforcement and display 403s clearly.
    Design: calm, dense, enterprise; clear status colours that work in light and dark mode; keyboard accessible.
    Done when: every flow works against a mock server that returns the documented shapes.

### U2. Review queue

    Review queue screen: lists agents in pending_approval with risk tier, requested tools and data classes, and access
    profile. Opening one shows the five checklist items as required checkboxes, a notes field, and Approve / Reject buttons.
    Approve is disabled until all five are ticked. If the server returns a separation-of-duties violation, show it prominently.
    After approval show the one-time credential modal with the instruction to hand it to the owner securely.

### U3. Audit log and security alerts

    Audit log screen: filters for stream (all, audit, user), actor, action, target; a table with time, stream, actor, action,
    target, outcome (colour-coded), source address; clicking a row opens the full JSON. A prominent "Verify integrity" button
    calls GET /v1/audit/verify and shows either "Chain intact" or "Chain broken at entry N" with a link to that entry.
    Include a "Copy as JSON lines" export of the filtered rows. Security alerts screen: a list sorted by severity then time with
    rule, subject and details, and a count badge in the navigation for open high-severity alerts.

---

## 5. Habits that keep the build honest

- One prompt at a time; commit after each green stage.
- Always end a stage by running the full test suite yourself; do not accept "it should work".
- Keep the standing instructions file open; if a generated change violates an invariant, say which one and ask for a fix.
- Ask for a plan first on A5, A7 and A8; they have the most design choices.
- After A10, run the independent review prompt in a fresh session.
