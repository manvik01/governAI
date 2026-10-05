# governAI - Product Requirements Document (refined)

Version 1.0 - the governance control plane for AI agents across providers and platforms.

How to read this: sections 1-4 say what the product is and for whom; section 5 is the
requirement set, one feature at a time, each with acceptance criteria; section 6 maps to
industry standards; section 7 is deployment; section 8 is build status against the repo.
`docs/prd-governed-token-consumption.md` holds the detailed decisions for feature F5.

---

## 1. Problem

Organisations now run many AI agents on several providers and platforms. Most cannot say
which agents exist, who owns them, what they may touch, what they cost, or prove what they
did. Surveys cited in our market research put adoption near 96% of enterprises but
centralised governance near 12%. Existing tools are quote-only enterprise suites; none
combines identity, enforcement, cost control and tamper-evident evidence in one layer that
sits in front of whatever agent framework a customer already uses.

## 2. Product in one paragraph

One control plane. Every agent is registered, owned, reviewed and issued its own credential.
Every call an agent makes goes through one authenticated gateway that applies policy
(including stateful rules such as cumulative limits), reserves budget before spending it,
and writes an audit entry whether the call succeeds, is denied or is attacked. Context
(workflows, personas, goals, conditions, decisions) lives in a database, never in model
memory, so decisions are repeatable and provable.

## 3. Users

| User | Needs |
|---|---|
| Agent owner / sub-owner | Register an agent, see its status, rotate its credential, suspend it |
| Security reviewer | Review and approve or reject agents before they go live |
| Admin | Define access profiles, manage budgets, manage users and roles |
| Auditor | Read audit and user logs, verify integrity, see security alerts |
| Platform engineer | Deploy and scale the gateway; connect SIEM and identity provider |
| The agent itself | Authenticate, call tools and models through the gateway |

## 4. Principles

1. **Security before cost.** Budget can only add restriction; it never overrides a permission, data rule or required human approval.
2. **No model memory for state.** Context, policy and decisions are stored, versioned and queryable. A model call is stateless.
3. **Evidence by default.** Every event is logged, including failures and attacks; logs are tamper-evident; secrets never enter them.
4. **Separation of duties.** The people accountable for an agent cannot be the ones who clear it or raise its budget.
5. **Stateless edge.** The gateway holds no state of its own, so it scales up and down freely.

## 5. Requirements

### F1. Agent registration, identity and review

**F1.1 Required registration data.** Name; approved purpose; owner; **sub-owner**; **access profile**; business unit; platform; model provider; permitted models; requested tools with data classes and reversibility; default autonomy level; budget policy. A request missing any item is refused.

**F1.2 Identity verification.** Submitter, owner and sub-owner must be active users in the identity directory (OIDC/SCIM-backed in production). Owner and sub-owner must hold the `agent_owner` role and be different people. The submitter must be the owner, the sub-owner or an admin. A leaver (deactivated user) cannot own or register an agent.

**F1.3 Access profiles.** An administrator-defined ceiling: allowed tools (or any), allowed data classes, allowed models, maximum autonomy level, and whether security review is mandatory. Requested access outside the profile is refused with a reason (least privilege enforced at the door).

**F1.4 Risk tier.** Computed from tools and autonomy (money, PII, irreversibility, A4). High and critical always require review.

**F1.5 Security review.** Required for profiles that demand it and for high/critical risk. The reviewer must hold `security_reviewer`, must not be the owner, sub-owner or submitter, and must complete the checklist: identity verified, least privilege reviewed, data classification confirmed, logging enabled, kill switch tested. Approval activates the agent; rejection ends the request. An agent cannot be approved twice.

**F1.6 Credentials.** On activation each agent receives its own credential, shown once and stored only as a hash; it has an expiry (default 90 days) and can be rotated (old one revoked immediately) or revoked. Suspension revokes all credentials at once. Production target: short-lived tokens via mTLS / SPIFFE-style workload identity or OAuth2 client credentials.

**F1.7 Lifecycle.** draft, pending_approval, active, suspended, rejected, retired. Every transition is logged with who and why.

*Acceptance criteria*
- An unknown, inactive or wrong-role owner or sub-owner is refused. Owner equal to sub-owner is refused.
- A request outside its access profile (tool, data class, model, autonomy) is refused with the specific reason.
- Every refused registration appears in the user log.
- An owner, sub-owner or submitter cannot review their own agent; incomplete checklists cannot approve.
- No credential exists before approval (where review is required).
- Plaintext credentials never appear in the database, audit log or SIEM stream.
- Agents, credentials and the audit chain survive a restart.

### F2. Central gateway

**F2.1 Single entry point.** Agents reach tools and models only through the gateway using their own credential. Unregistered, suspended, revoked or expired credentials are rejected at the edge.

**F2.2 Identity from the credential.** The agent's identity is taken from its credential, never from the request body. An agent naming a different agent is refused and raises an alert.

**F2.3 Human access.** Humans authenticate with a user token (OIDC in production); roles come from the directory, so removing a person removes access at once.

**F2.4 Uniform failure.** Every authentication failure returns the same response; the precise reason is in the audit log only.

**F2.5 Abuse controls.** Request size limit; rate limits per source address (before authentication) and per subject (after).

**F2.6 Policy and budget.** Each governed call is evaluated by the policy engine (grants, rules, stateful limits, human approval) and, for model calls, by the budget controls in F5.

*Acceptance criteria*
- No, malformed, wrong-secret, revoked, expired and inactive-user credentials all receive an identical 401.
- A human token cannot use the agent call path; an agent token cannot use human routes.
- A suspended agent's credential stops working immediately.
- A rotated credential's predecessor stops working immediately.
- A denied call is logged and linked to the governance ledger event.

### F3. Deployment and scaling

**F3.1 Footprint.** Runs as one container (on-premises or any container host) or on a small cloud VM. Configuration only through environment variables. Non-root user, health checks, graceful shutdown on SIGTERM.

**F3.2 Stateless gateway.** No state in the process other than short-lived rate and detection windows; everything durable is in the database.

**F3.3 Scale up and down.** Replicas added or removed behind a load balancer using `/healthz` (liveness) and `/readyz` (readiness, checks the database). Autoscaling on request rate and latency.

**F3.4 Prerequisites for more than one replica** (see section 7): shared database (Postgres), shared rate-limit and detection counters (Redis or a stream processor), a defined write path for the hash chain.

*Acceptance criteria*
- `/healthz` and `/readyz` need no credential and expose no data.
- A replica can be stopped with SIGTERM without dropping in-flight calls.
- A scale-out test (N replicas, shared database) shows no over-allocation of budget and an intact audit chain. *(Not yet met - needs Postgres.)*

### F4. Security monitoring and logging

**F4.1 Two log streams, one tamper-evident chain.** *Audit log:* what the system decided or saw (authentication outcomes, gateway decisions, state changes, alerts). *User log:* what a human did (registration, review, rotation, suspension, login, reading the audit log). Every event carries actor, action, target, outcome, source address, request id and details, and is hash-chained to its predecessor.

**F4.2 Every event is logged**, including failures, denials and attacks. Reading the audit log is itself logged.

**F4.3 Secrets never logged.** Sensitive field names are redacted at write time.

**F4.4 Integrity.** An integrity check detects edited and deleted entries and reports where the chain breaks.

**F4.5 Export.** Every event is mirrored as a JSON line to a SIEM sink (OpenTelemetry / OCSF forwarders in production).

**F4.6 Detection rules.** auth_failure_burst, dead_credential_used, identity_spoofing, credential_new_source, policy_probing, rate_limit_abuse, malformed_request_burst. Alerts are stored, exposed by API, written to the audit chain, forwarded to the SIEM sink and de-duplicated during a cooldown.

*Acceptance criteria*
- Each of: register, refuse, review, approve, reject, issue, rotate, revoke, suspend, login, auth failure, gateway call, rate limit, malformed request, audit read produces a log entry in the right stream.
- The user stream contains only human actions.
- Editing or deleting any entry is detected and located.
- Credential stuffing from one address raises exactly one alert per cooldown.
- Use of a known credential from a new address raises an alert.
- Repeated denials by one agent raise a policy-probing alert.

### F5. Governed token consumption and cost management

Budgets at organisation, project, agent and task level; atomic reservation before each model call; shared task budgets across child agents, retries and fallbacks; consumption ledger where missing usage stays unresolved; itemised idempotent billing (provider cost, governance cost, platform fee); budget exhaustion handling. Security controls run before budget. Full decisions and acceptance criteria: `docs/prd-governed-token-consumption.md`.

### F6. Context layer and multi-agent orchestration

Workflows, personas, conditions, policies, goals, milestones and timelines stored as versioned rows; a decision matrix evaluated in code; a master agent that decomposes a goal into per-role sub-tasks and summarises by reading the shared store. No agent keeps private memory.

*Acceptance criteria:* restarting the process and re-running the summary returns an identical result; each sub-task is owned by exactly one role; dependencies are enforced by the graph.

## 6. Standards mapping

A starting map for design and customer conversations. Confirm each control reference against the current published text before using it in an audit or customer-facing document.

| Area | Framework | Where this product contributes |
|---|---|---|
| AI risk management | NIST AI RMF (Govern, Map, Measure, Manage) | Registry and risk tier (Map), policy and budget enforcement (Manage), evidence ledger (Measure) |
| AI management system | ISO/IEC 42001 | Roles and ownership, lifecycle control, review records, audit trail |
| Security controls | SOC 2 (Security, Availability, Confidentiality criteria) | Access control, change records, logging and monitoring, credential handling |
| Digital identity | NIST SP 800-63 and OAuth 2.0 / OIDC | User authentication via OIDC; short-lived agent credentials |
| LLM and agent threats | OWASP Top 10 for LLM Applications and for agentic AI | Excessive agency (profiles, grants, approval), identity abuse, logging |
| Event format | OpenTelemetry, OCSF | SIEM export format |

## 7. Deployment architecture

```
agents / MCP clients ──► [ load balancer / ingress ] ──► N x governAI gateway (stateless container)
humans (console, API) ──►                                   │   authN, authZ, rate limit, policy, budget, audit
                                                            ▼
                                  Postgres: registry, credentials, directory cache, audit log,
                                            governance ledger, budgets, billing
                                  Redis:    rate-limit counters, detection windows
                                  SIEM:     JSON lines / OTel from the audit sink
                                  IdP:      OIDC for humans, SCIM for the directory
```

Options: on-premises container (Docker or Kubernetes with a horizontal autoscaler), or a
small cloud VM running the same container (managed instance group / scale set behind a
load balancer). The container is stateless; only the database and Redis hold state.

Production gaps between the POC and this architecture: SQLite to Postgres (row locks keep
the budget reservation atomic); rate limits and monitor windows to Redis; a single
serialised writer or advisory lock for the audit hash chain; OIDC and SCIM instead of the
stand-in user tokens and directory; short-lived workload identity instead of long-lived
keys; TLS terminated at the ingress with mTLS to agents where required.

## 8. Build status (this repository)

| Feature | Status | Evidence |
|---|---|---|
| F1 Registration, identity, review, credentials | Built (first slice) | `src/control/registration.ts`, `credentials.ts`, `access-profiles.ts`; tests in `control.test.ts` |
| F2 Authenticated gateway | Built (first slice) | `src/gateway/secure-server.ts` |
| F3 Container and scaling | Dockerfile, health checks, graceful shutdown written; **Dockerfile not yet built or run**; multi-replica needs Postgres and Redis | `Dockerfile` |
| F4 Monitoring and logging | Built | `audit-log.ts`, `security-monitor.ts` |
| F5 Token consumption | Built | `src/budget/`; 16 tests |
| F6 Context and orchestration | Built (demo-level) | `src/context/`, `src/orchestration/` |
| Console UI | Not built | see `docs/build-prompts.md` |
| Model-call route on the secure gateway | Not built (budget gateway exists as a library) | next slice |
| OIDC / SCIM, Postgres, Redis | Not built | section 7 |

## 9. Open questions

1. Which identity provider(s) first: Entra ID, Okta or Google Workspace?
2. Agent credentials: are long-lived keys acceptable for the first design partners, or is mTLS required from day one?
3. Review depth by tier: should medium-risk agents require review, or only high and critical?
4. On-premises customers: Kubernetes only, or plain Docker hosts too?
5. Retention: how long must audit and user logs be kept, and who may export them?
6. Should the console be a separate product surface or part of the gateway?
