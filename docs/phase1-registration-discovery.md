# Phase 1: registration and discovery

Every agent has one record in the Agent Registry before it may act, whether a person
registered it or discovery found it. This document covers what was built, the routes and
CLI commands, the environment variables per connector, the design decisions, and known
limitations.

Branch: `phase1-registration-discovery` (cut from `supabase-schema`).

## What was built

| Spec item | Where | Notes |
|---|---|---|
| 1. Manual registration (console/API/CLI) | `POST /v1/agents`, `zenai4-admin agent register` | Every field, including an explicit `expiresAt` (at most 90 days out). `draft: true` creates a draft. |
| 2. Registration as code | `src/control/manifest.ts`, `POST /v1/agents/apply`, `zenai4-admin apply -f` | Strict zod schema, idempotent apply keyed by `metadata.id`. Examples in `examples/agent.yaml` and `examples/ci/register-agent.yml`. |
| 3. Discovery connectors | `src/discovery/connectors.ts`, `http.ts`, `scheduler.ts` | Entra ID, Okta, Copilot Studio, Gemini Enterprise and GitHub. Read-only. Every 6 hours by default. |
| 4. Gateway and egress discovery | `src/gateway/secure-server.ts`, `src/discovery/discovery.ts` | Failed agent credentials and imported egress CSV rows become `discovered_agents` rows. |
| 5. Shadow agent queue | `DiscoveryService` claim, assign-owner, ignore and disable | Each claim creates a draft owned by the claimer. Every transition is audited. |
| 6. Risk tier | `calculateRiskTier`, `RegistrationService.setRiskTier` | Stores the computed tier, the override (who, why, direction) and the effective tier. |
| 7. Lifecycle | `LIFECYCLE_TRANSITIONS` in `src/registry/registry.ts` | Draft → Pending approval → Active → Suspended → Retired, plus Rejected. Illegal moves are refused and audited. |
| 8. Expiry and recertification | `recertify`, `expirySweep`, `expiringWithin` | 90-day default. The gateway refuses an expired agent even before the sweep runs. |
| Storage | SQLite (running code) and `supabase/migrations/20261016120000_registration_discovery.sql` | The migration was not applied anywhere. It was syntax- and constraint-checked on a throwaway local PostgreSQL 16. |

## Lifecycle

```
            submit (checks)              security review (high/critical or profile)
  draft ─────────────────────► pending_approval ─────────────► active ──► suspended ──► retired
    ▲                               │      │                    │  ▲          │  (expiry: recertify
    │ reopen                        │      └─► rejected ──┐     │  └──────────┘   within 30 days)
    └───────────────────────────────┴─────────────────────┘     └─► pending_approval (widened access
                                                                     or raised tier: re-review)
  any non-retired state ──► retired   (terminal; credentials revoked)
```

* High and Critical agents need security approval before they go Active. This was already
  enforced and still is.
* `POST /v1/agents/:id/transition {to}` checks the transition table first. It then hands
  the move to the operation that owns the rules for it: suspend, retire, submit draft,
  request re-review or reopen. "Active" and "rejected" can only be reached through review
  or recertification.
* `suspended → active` is allowed only through recertification of an agent the expiry
  sweep suspended. Any other suspended agent goes back through security review.

## Risk tier

The tier is computed from four signals: money (`financial`, `payments`, ...), personal data
(`customer_pii`, `pii`, `health`, ...), irreversible tools and autonomy.

| Tier | Rule |
|---|---|
| critical | A4 with money or irreversible tools; or A3+ with money **and** irreversible tools |
| high | money and irreversible; personal data and irreversible; or A4 |
| medium | any one of: money, personal data, irreversible tool, A3 |
| low | none of the above |

* **Owners** (owner or sub-owner) may **raise** the tier. The effective tier is
  `max(computed, raised)`.
* Only a **security reviewer** may **lower** it, and never on an agent they own, sub-own or
  submitted. Admins cannot lower. Going below the computed floor requires a written reason.
* Raising a never-reviewed Active agent into High or Critical sends it to
  `pending_approval` and revokes its credentials.
* If a later update raises the computed tier, a "lower" override is dropped, because it
  was granted against narrower access.
* The agent stores `computedRiskTier`, `riskOverride {tier, direction, by, reason, at}` and
  the effective `riskTier`. Postgres mirrors these as columns, with CHECK constraints for
  "raise ≥ computed" and "lower below floor ⇒ reason", plus an append-only
  `prove.risk_tier_decision`.

## Registration as code

```yaml
apiVersion: zenai4/v1
kind: Agent
metadata: { id: customer-success.refund-assistant, name: Refund Assistant }
spec: { purpose, owner, subOwner, businessUnit, platform, model: {provider, version, permitted},
        accessProfile, autonomy, mode, tools: [{name, reversible, dataClasses}], budget, expiresAt }
```

The full example is in `examples/agent.yaml`.

| Situation | Result |
|---|---|
| Unknown `metadata.id`, manifest complete | `created`: full registration checks run. Active, or Pending approval for high/critical or profiles that need review. |
| Unknown id, required fields missing | `drafted`: a Draft owned by `spec.owner`. The response lists what is missing. |
| Known id, same spec hash | `unchanged`: a no-op that is still audited, so CI runs are evidence. |
| Known id, changed | `updated`: every check runs again. **Widening** (new tool, new data class, a tool becoming irreversible, higher autonomy, new model or provider) on an Active agent that ends up High/Critical, or whose profile needs review, goes back to `pending_approval` and its credentials are revoked. |
| Draft completed by a later manifest | The draft is submitted automatically. |
| Retired agent | Refused. A successor needs a new `metadata.id`. |

* The idempotency key is `metadata.id`, never the name, so a rename is an update. The
  spec hash is SHA-256 over canonical JSON of `name` and `spec` (labels excluded).
* The schema is strict. An unknown or misspelt key is rejected, so a typo cannot silently
  drop a restriction.
* **Apply never issues a credential.** A CI log is the worst place for a one-time secret.
  The owner fetches one with `POST /v1/agents/:id/credentials/rotate`.
* The CI identity is a directory user with the new **`ci_registrar`** role. It may apply
  manifests on behalf of the owners named in them. It cannot own, claim or review an agent,
  and it can never be the owner. Even a no-op apply is refused for anyone who cannot manage
  the agent.
* The body can be sent as `application/yaml` (raw YAML), as JSON `{ "manifest": "<yaml>" }`,
  or as a JSON object in manifest form.

## Discovery

### `discovered_agents`

The table has these columns: `id`, `fingerprint` (unique), `source`, `kind`,
`display_name`, `first_seen`, `last_seen`, `count`,
`status (new|claimed|registered|ignored|disabled)`, `owner_email`, `agent_id`,
`attributes` (JSON), and `status_by`, `status_reason`, `status_at`.

* **Fingerprint:** SHA-256 over the source plus non-secret identity only. Repeated
  sightings update `count`, `first_seen` and `last_seen` on the same row. Only the first
  sighting is audited (`discovery.sighted`), so the log is not flooded. Every status change
  is audited.

| Source | Identity used in the fingerprint |
|---|---|
| gateway | source address, user agent, credential scheme, ZenAi4 key-id prefix (6 chars) or provider name |
| egress_import | source host, provider |
| entra_id | tenant id, object id |
| okta | Okta domain, app id |
| copilot_studio | Dataverse URL, bot id |
| gemini_enterprise | agent resource name |
| github | repo, path, server name; or repo, path, provider, key fingerprint |

* **Secrets are never stored.** A token presented to the gateway is reduced to
  `{scheme, keyIdPrefix | provider}` before anything is recorded. Every attribute is passed
  through `scrubSecrets` (provider key patterns, ZenAi4 tokens, Bearer/Basic/SSWS values)
  before it is written. The audit log now applies the same scrub to string values, on top
  of its existing redaction of sensitive keys. Tests assert that the raw key strings appear
  nowhere in any table or in the audit export.

### Gateway (Step 1)

A request that fails authentication with an agent-shaped credential becomes a discovery
sighting. This covers unknown key, bad secret, revoked, expired, agent not active and
agent expired. So does a provider API key or an opaque token sent to the gateway, and a
missing credential on `/v1/call`. Failed **human** tokens are not discovery sightings.
If the credential belonged to a registered agent (for example revoked), the row is linked
to that agent. The 401 response is unchanged and identical for every reason.

### Egress import

`POST /v1/discovery/import-egress` (`text/csv` or `{csv}`), or
`zenai4-admin discovery import-egress`. Security reviewers and admins only.

```
source_host,destination_domain,count,first_seen,last_seen
build-07.corp,api.openai.com,120,2026-10-01T00:00:00Z,2026-10-10T00:00:00Z
```

* Only rows whose destination is a known LLM provider domain are kept. The list is in
  `LLM_PROVIDER_DOMAINS`: OpenAI, Azure OpenAI, Anthropic, Google AI and Vertex, Bedrock,
  Mistral, Cohere, Groq, xAI, DeepSeek, Together, OpenRouter and Hugging Face.
* One discovery row per (host, provider). Re-imports accumulate counts.
* Quoted CSV fields are supported. Bad rows are reported, not fatal. The limit is 100,000
  rows and 5 MiB per import.

### Shadow agent queue and triage

The triage queue is every row with status `new`, no owner and no linked agent:
`GET /v1/discovery?queue=triage`.

| Action | Who | Effect |
|---|---|---|
| claim | an active `agent_owner` | `new → claimed`. Creates a **Draft** agent prefilled from the discovery (name, platform, provider), owned by the caller and linked both ways. |
| assign-owner | `security_reviewer` or `admin` | `new → claimed`. The draft is owned by the named `agent_owner`. |
| (submit the draft) | owner | `claimed → registered`, automatically. |
| ignore | security or admin, reason required | `new/claimed → ignored` (a false positive). `ignored → new` is allowed in the table but has no route yet. |
| disable | security or admin | `→ disabled` (terminal). A linked Active agent is suspended. A linked draft, pending or rejected agent is retired. Credentials are revoked either way. Connectors are read-only, so the response includes `manualActionRequired` for vendor-side identities and leaked keys. |

Illegal transitions (for example claiming twice) are refused with a reason and audited.

## Connectors

Every connector implements `DiscoveryConnector { id, kind, run(): Promise<DiscoveredItem[]> }`.
The scheduler records items through `DiscoveryService`. Connectors never write to the
database.

* **Read-only:** every connector's fetch is wrapped by `readOnlyFetch`, which rejects any
  method other than GET. The one exception is a POST to the exact Microsoft identity
  platform token URL for the configured tenant, which only obtains a read token.
* **Credentials:** read from environment variables whose names are configurable (defaults
  below). Values are read inside `run()` and never stored. A missing variable fails the
  run with the variable's **name**.
* **Tests:** every connector runs against fixture responses through the injected fetch.
  There are no live calls.

Turn connectors on with `ZENAI4_DISCOVERY_CONNECTORS=entra_id,okta,copilot_studio,gemini_enterprise,github`
and `ZENAI4_SCHEDULER=1`.

| Connector | API | Permissions | Env vars |
|---|---|---|---|
| `entra_id` | Microsoft Graph. **beta** `GET /servicePrincipals/microsoft.graph.agentIdentity` (Entra Agent ID). Optionally v1.0 `GET /servicePrincipals?$filter=servicePrincipalType eq 'Application'`, keeping the tenant's own apps only. | App-only: `Application.Read.All`, plus `AgentIdentity.Read.All` where available | `ZENAI4_ENTRA_TENANT_ID`, `ZENAI4_ENTRA_CLIENT_ID`, `ZENAI4_ENTRA_CLIENT_SECRET`, optional `ZENAI4_ENTRA_INCLUDE_SERVICE_PRINCIPALS=1` |
| `okta` | `GET https://{domain}/api/v1/apps?limit=200` with `Link` paging (on-tenant links only). Keeps service apps: `application_type=service` or the `client_credentials` grant. | Read-only API token (`okta.apps.read`) | `ZENAI4_OKTA_DOMAIN`, `ZENAI4_OKTA_API_TOKEN` |
| `copilot_studio` | Dataverse Web API `GET {env}/api/data/v9.2/bots?$select=...`. Copilot Studio agents are rows in `bots`. One instance per Power Platform environment. | App registration plus an application user in the environment with read on `bot` | `ZENAI4_DATAVERSE_URL`, `ZENAI4_ENTRA_TENANT_ID`, `ZENAI4_ENTRA_CLIENT_ID`, `ZENAI4_ENTRA_CLIENT_SECRET` |
| `gemini_enterprise` | Discovery Engine **v1alpha** `GET .../engines/{app}/assistants/default_assistant/agents` with `pageToken` paging. Regional hosts for `us`/`eu`. | OAuth access token with `cloud-platform` scope (Discovery Engine Viewer) | `ZENAI4_GEMINI_PROJECT`, `ZENAI4_GEMINI_APP_IDS` (comma list), `ZENAI4_GEMINI_ACCESS_TOKEN`, optional `ZENAI4_GEMINI_LOCATION` (global/us/eu) |
| `github` | REST code search `GET /search/code` for `filename:mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `mcp_config.json` and `.vscode/mcp.json`, and for literal key prefixes (`sk-ant-`, `sk-proj-`, `T3BlbkFJ`, `AIza`, `gsk_`, `hf_`, `xai-`). Then `GET /repos/{repo}/contents/{path}` (raw), once per file, at most 200 files per run. | Fine-grained token: Contents read and Metadata read on the org's repos | `ZENAI4_GITHUB_TOKEN`, `ZENAI4_GITHUB_ORG` |

What the GitHub connector stores:

* **MCP servers:** server name, transport, the command basename, the npm package name
  from args, the URL host, and the env var **names** it is given. It never stores env
  values, args (which can hold connection strings) or headers.
* **API keys:** repo, path, line, provider and `keyFingerprint` (the first 4 hex characters
  of SHA-256 of the key). The key text never leaves the function that read the file.

### Scheduler

`src/discovery/scheduler.ts`:

* Connectors run every 6 hours by default (`ZENAI4_DISCOVERY_INTERVAL_HOURS`). The expiry
  sweep runs hourly.
* One run at a time per job. A tick that lands during a run is recorded as `skipped`
  (audited), never stacked.
* Each run is recorded in `discovery_runs` (status, item count, new count, error) and
  audited. Error text is scrubbed.
* Timers are unref'd. Status is at `GET /v1/discovery/connectors`. An on-demand run is
  `POST /v1/discovery/connectors/:id/run` or `zenai4-admin discovery run`.

## Expiry and recertification

* Every agent expires 90 days after registration by default
  (`ControlPlaneOptions.certificationDays`). An explicit expiry may be shorter, never longer.
* **The gateway refuses an expired agent before the sweep runs.** `AgentRegistry.isActive()`
  is false once `expiresAt` has passed. The gateway authentication step, the policy engine
  and the model gateway all use it. The audit reason is `agent_expired`.
* **Sweep:** suspends every Active agent past expiry (`suspendedReason = "expired"`),
  revokes its credentials and audits `agent.expired`. It is idempotent.
* **Recertify:** owner or sub-owner only, and the owner must still be active. It works on
  an Active agent, or on one the sweep suspended for expiry no more than 30 days ago.
  * New expiry = now + 90 days.
  * Active agent: its live credentials are extended to the new expiry, with no forced
    rotation.
  * Expiry-suspended agent: it is reactivated and gets a new one-time credential. The old
    one stays revoked.
  * An agent suspended for any other reason cannot be recertified back on.
* **Expiring soon:** `GET /v1/agents/expiring?days=14` lists them (owners see their own),
  as does `zenai4-admin agent expiring`, and the Postgres view `report.agent_expiring`.

## HTTP routes (new or changed)

| Method and path | Who | Purpose |
|---|---|---|
| `POST /v1/agents` | agent_owner, admin | Register (now with `expiresAt`). `{"draft": true, ...}` creates a draft. |
| `POST /v1/agents/apply` | agent_owner, admin, ci_registrar | Apply an agent.yaml (YAML or JSON). |
| `GET /v1/agents/:id` | owner, sub-owner, admin, auditor, security | Full record plus tools. |
| `PATCH /v1/agents/:id` | owner, sub-owner, admin | Update. Same checks and widening re-review as apply. |
| `POST /v1/agents/:id/submit` | owner, sub-owner, admin | Draft → pending approval (→ active if no review is needed). |
| `POST /v1/agents/:id/transition` `{to, reason}` | depends on the move | Generic lifecycle move, enforced by the transition table. |
| `POST /v1/agents/:id/retire` | owner, sub-owner, security, admin | Terminal. Revokes credentials. |
| `POST /v1/agents/:id/risk-tier` `{tier, reason}` | owners raise; security lowers | Risk tier override. |
| `POST /v1/agents/:id/recertify` | owner, sub-owner | Extend expiry by 90 days. |
| `GET /v1/agents/expiring?days=14` | owners (their own), admin, auditor, security | Expiring soon. |
| `GET /v1/discovery?status=&source=&queue=triage` | security, admin, auditor, agent_owner | Discovery list and triage queue. |
| `POST /v1/discovery/:id/claim` | agent_owner | Claim and create a draft owned by the caller. |
| `POST /v1/discovery/:id/assign-owner` `{ownerEmail}` | security, admin | Name an owner and create their draft. |
| `POST /v1/discovery/:id/ignore` `{reason}` | security, admin | Mark as a false positive. |
| `POST /v1/discovery/:id/disable` `{reason}` | security, admin | Disable. Suspends or retires a linked agent and revokes credentials. |
| `POST /v1/discovery/import-egress` | security, admin | Egress CSV import. |
| `GET /v1/discovery/connectors` | security, admin, auditor | Scheduler jobs and last run. |
| `POST /v1/discovery/connectors/:id/run` | security, admin | Run a job now. |

Refusals return 403 for permission, 404 for an unknown id and 422 for rules. They carry
`violations: string[]` and are written to the user audit stream.

## CLI (`zenai4-admin`)

Commands that act for a person take `--as <email>`. That directory user's roles and
separation-of-duties rules apply exactly as on the API. The audit records both the person
and the OS operator (`cli:<user>`).

```
apply -f agent.yaml --as ci@acme.com           # or remote: ZENAI4_URL + ZENAI4_TOKEN (POSTs to the gateway)
agent register --as <e> --name --purpose --owner --sub-owner --profile --business-unit --platform
               --model-provider --model-version [--models a,b] --autonomy A0-A4
               --tools name:reversible|irreversible[:dc1+dc2],... [--data-classes dc,..]
               [--expires-at 2027-01-01] [--mode enforcement|posture] [--agent-limit-micro N] [--task-limit-micro N] [--draft]
agent list | show --id | expiring [--days 14]
agent submit --id --as | transition --id --to <state> [--reason] --as | retire --id [--reason] --as
agent risk-tier --id --tier <t> [--reason] --as | recertify --id --as
discovery list [--status s] [--triage] [--source s]
discovery claim --id --as | assign-owner --id --owner --as | ignore --id --reason --as | disable --id [--reason] --as
discovery import-egress --file egress.csv --as
discovery run [--connector id] | discovery status
sweep
user add ... --roles ci_registrar              # new role for CI pipelines
```

Agent credentials are printed once, on stdout only.

## Postgres migration

`supabase/migrations/20261016120000_registration_discovery.sql`. It has not been run
against any Supabase project.

* **`control.agent`:**
  * The lifecycle CHECK now includes `rejected`. Migration 0002 had omitted it.
  * New columns: computed tier, override (tier, direction, by, reason, at), `manifest_id`
    (unique), `manifest_hash`, `discovery_id`, suspension, retirement and recertification
    fields.
  * CHECKs for override recording, "raise ≥ computed", "lower below floor ⇒ reason",
    "retired ⇒ retired_at" and "active ⇒ expires_at".
  * A trigger enforces the lifecycle transition table and blocks edits to retired agents.
* **`control.discovered_agent`:** CHECKs on status and source. Claimed/registered rows need
  an owner and an agent; ignored rows need a reason. A trigger enforces discovery
  transitions. There is a partial index for the triage queue.
* **`control.discovery_run`:** scheduler history.
* **`prove.owner_claim`, `prove.recertification`, `prove.risk_tier_decision`:** append-only
  via `control.refuse_change()`. Recertification is capped at 90 days by CHECK.
* **`report.shadow_agent_queue`, `report.agent_expiring`:** views granted to `zenai4_report`.
* No Data API exposure. Grants come from 0001's default privileges.

Validation: all six migrations were applied in order to a throwaway local PostgreSQL 16
instance, and the triggers and CHECKs were exercised (illegal transition, lower without
reason, retired edit, discovery skip, append-only delete). Supabase runs 17. Nothing here
is version-specific.

## Design decisions (made without sign-off; revisit if needed)

1. **Draft creation checks only the owner.** The full checks run on submit. This lets
   discovery claims and partial manifests exist without guessing access.
2. **Apply never issues credentials** (see above). The owner rotates to get one.
3. **New `ci_registrar` role** rather than letting CI use an owner's token.
4. **Explicit expiry is capped at 90 days.** "Every agent expires after 90 days unless
   recertified" is read as a maximum, not just a default.
5. **Credential lifetime follows certification.** Recertifying an active agent extends its
   live credentials instead of forcing a rotation. A reactivated (expired) agent gets a new
   credential.
6. **The recertification grace window is 30 days after expiry.** After that, the agent
   needs a fresh security review (`transition → pending_approval`).
7. **Risk scoring was extended** from the old rules. Personal data plus irreversible is
   now high, A3 alone is medium, A4 alone is high, and A3+ with money and irreversible is
   critical. The data-class lists live in `MONEY_CLASSES` and `PERSONAL_CLASSES`. No
   existing test depended on the old edge cases.
8. **Admins cannot lower a risk tier.** Only security reviewers can (spec: "only security
   can lower").
9. **Discovery `disable` stops the ZenAi4 side only.** Vendor identities need manual action
   because connectors are read-only. The response says so.
10. **Gateway discovery ignores failed human tokens** and unauthenticated requests to
    non-agent routes, to keep noise out of the queue.
11. **A 4-hex key fingerprint** (16 bits) correlates the same key across repos within one
    org, and is useless for confirming a guess.
12. **The audit log scrubs string values** for secret-shaped content. Before, it only
    redacted sensitive key names.

## Known limitations and open items

* **Vendor APIs that are preview or best-effort:**
  * Entra Agent ID is on the Graph **beta** endpoint. A tenant without it answers 400/404,
    which is treated as "no agents".
  * Gemini Enterprise agent listing is **v1alpha**.
  * The Copilot Studio `bots` table is stable, but needs one connector instance per Power
    Platform environment. There is no tenant-wide enumeration yet; that needs the Power
    Platform admin API.
  * Field names were taken from vendor docs and samples and verified only against
    fixtures, never live tenants. Run each connector against a real tenant before relying
    on it.
* **Gemini access token:** the connector takes a ready-made access token from the
  environment. Minting one from a service account or workload identity is out of scope.
  Use a sidecar or `gcloud auth print-access-token` in the runner.
* **GitHub code search** is rate-limited (about 10 requests a minute) and indexes only
  default branches. It does not search archived or forked repos the token cannot see.
  Secret scanning alerts (`GET /orgs/{org}/secret-scanning/alerts`) would be a better
  source for keys where GitHub Advanced Security is available; not yet used.
* **Scheduler lock is in-process.** Run `ZENAI4_SCHEDULER=1` in one replica only, or move
  the lock to Postgres (an advisory lock) when the Postgres store lands.
* **The running code still uses SQLite.** The Postgres migration mirrors the design, but
  no Postgres-backed store exists yet. The `prove.*` evidence tables are written only by
  that future store; today the same evidence is in the hash-chained audit log
  (`discovery.claim`, `agent.recertify`, `agent.risk_tier.set`).
* **No "un-ignore" route.** `ignored → new` is allowed in the transition table but has no
  route yet.
* **Owner notifications** (for example "expiring in 14 days" sent to owners) are not sent.
  The list exists; delivery (email, Slack) is phase 2.
* **Leaver handling is not automated:** an agent whose owner deactivates is not
  reassigned. Recertification refuses while the owner is inactive.
* **The old `src/gateway/server.ts` demo** (unauthenticated) uses the same registry and
  inherits the transition table. It is not part of the secure surface.
