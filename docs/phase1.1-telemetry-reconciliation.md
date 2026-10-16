# Phase 1.1: telemetry intake and reconciliation

Phase 1 made the Agent Registry the record of what each agent is **allowed** to do. Phase 1.1
adds what each agent was **seen** doing, and compares the two. Telemetry flows through the
registry: an unknown agent becomes a discovery row, a registered agent's observed tools and
models are checked against its grants, and the results come back to the owner at
recertification.

Branch: `phase1.1-telemetry-reconciliation` (cut from `phase1-registration-discovery`).

## Background: what was adopted from the external proposal, and what was changed

An external design was reviewed: self-hosted Supabase, a Python collector, and an agent
interceptor writing `agent_sessions`, `agent_steps` and `policy_violations`.

| Adopted | Changed |
|---|---|
| A per-step record of tool, model, tokens, latency and status | Stored as `telemetry_steps` (SQLite) / `events.event` (Postgres), extending the existing schema rather than adding a parallel `agent_sessions`/`agent_steps` model |
| A policy-violation table | Append-only and hash-chained, linked to agent, session, policy id/version and rule. No cascade deletes. |
| Sessions | Linked to the registry (`agent_id`), and scoped to the sender so one source cannot write into another's sessions |
| Supabase Studio for looking at the data | Trimmed stack (Postgres + postgres-meta + Studio), loopback only, reached through an SSH tunnel |
| A collector in front of the store | The standard OpenTelemetry Collector instead of a bespoke Python service. Intake runs on the existing TypeScript gateway, behind the existing Caddy TLS front. |
| Capturing prompts and tool I/O | Off by default (`metadata`). When on, everything is secret-scrubbed, PII-redacted and truncated. Reasoning text is never kept unless switched on. |
| An agent-side interceptor | Replaced by OpenTelemetry GenAI instrumentation (see below), plus a small reference sender for agents that cannot use OTel |

## What was built

| Spec item | Where |
|---|---|
| Intake endpoints | `POST /v1/intake/steps`, `POST /v1/intake/otlp` in `src/gateway/secure-server.ts` |
| Source tokens | `zenai4-admin source add / revoke / list`; `intake_sources` holds hashes only |
| Mapping (OTLP GenAI, steps API) | `src/telemetry/mapping.ts` |
| Redaction (secrets, PII, truncation) | `src/telemetry/redact.ts`, reusing `src/control/secret-patterns.ts` |
| Storage, append-only rules, violation chain | `src/telemetry/store.ts` |
| Intake service (identity, capture modes, batches, audit) | `src/telemetry/intake.ts` |
| Reconciliation, retention, activity summary | `src/telemetry/reconcile.ts`; scheduler jobs `telemetry-reconcile` (hourly) and `telemetry-retention` (daily) |
| Configuration | `src/telemetry/config.ts` (`ZENAI4_*` variables, listed in `.env.example`) |
| Postgres mirror | `supabase/migrations/20261016140000_telemetry_reconciliation.sql` |
| VM deployment | `deploy/vm/` and `docs/deployment/vm.md` |
| Reference sender | `examples/intake/send-steps.ts` |
| Tests | `src/telemetry/telemetry.test.ts` (29) and one CLI test in `src/control/admin-cli.test.ts` |

## Instrumenting agents: OpenTelemetry first

The default path is **OpenTelemetry GenAI instrumentation → OpenTelemetry Collector →
ZenAi4**. No ZenAi4 code runs inside the agent.

1. Instrument the agent with an OpenTelemetry GenAI instrumentation for its framework or SDK.
   Options include the official `opentelemetry-instrumentation-openai-v2` and other
   `opentelemetry-python-contrib` GenAI packages, OpenLLMetry, OpenInference (Arize), or a
   framework's built-in OTel support. Leave message-content capture **off** unless the source
   will be set to `redacted`. For the OTel Python packages that switch is
   `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`.
2. Identify the agent. Set `gen_ai.agent.id` on spans (newer conventions), or set the resource
   attribute `service.name`, to the agent's **ZenAi4 agent id or its manifest `metadata.id`**.
   That is how a span is linked to the registry. Anything else is stored as an unregistered
   agent and goes to discovery. You can also set `zenai4.agent.key` explicitly.
3. Point the SDK's OTLP exporter at a Collector, and the Collector at ZenAi4 using
   `deploy/vm/otel-collector.yaml`. It sends OTLP/HTTP **JSON** with a source token, uses a
   file-backed queue, and retries.
4. Optional ZenAi4 span attributes:
   * `zenai4.step.seq`: a per-session step number. It enables gap detection; without it,
     OTLP spans are deduplicated by span id only.
   * `zenai4.policy.id`, `.version`, `.rule`, `.decision`: lets an external guardrail report a
     policy decision, which becomes a violation if it is `deny` or `hold_for_approval`.

For agents that cannot use OpenTelemetry, `examples/intake/send-steps.ts` shows the contract
for `POST /v1/intake/steps`. It spools to disk before acknowledging, assigns `seq` per
session, retries with backoff and jitter, and dead-letters permanent refusals. Every flush
reports what was sent, what is pending and what was dropped, and the demo exits non-zero if
anything was dropped.

### Attribute generations mapped

The GenAI semantic conventions renamed attributes between releases. The mapper reads the
newest name first and falls back to older ones. Tests cover all three generations plus
OpenInference.

| Field | ≥ 1.37 | 1.27–1.36 | Legacy / OpenLLMetry / OpenInference |
|---|---|---|---|
| provider | `gen_ai.provider.name` | `gen_ai.system` | `llm.vendor`, `llm.provider`, `llm.system` |
| model | `gen_ai.request.model` | same | `llm.request.model`, `llm.model_name` |
| tokens | `gen_ai.usage.input_tokens` / `output_tokens` | same | `gen_ai.usage.prompt_tokens` / `completion_tokens`, `llm.usage.*`, `llm.token_count.*` |
| tool | `gen_ai.tool.name` | same | `tool.name` |
| operation | `gen_ai.operation.name` | same | `llm.request.type`, `openinference.span.kind` |
| prompt / output | `gen_ai.input.messages` / `gen_ai.output.messages` (+ `gen_ai.system_instructions`) | events `gen_ai.*.message`, `gen_ai.choice` | `gen_ai.prompt[.N.content]`, `gen_ai.completion[.N.content]`, `input.value`, `output.value` |
| tool I/O | `gen_ai.tool.call.arguments` / `.result` | | `tool.parameters`, `input.value` / `output.value` on tool spans |
| session | `gen_ai.conversation.id` | same | `session.id`, else the trace id |
| reasoning | message parts of type `reasoning` / `thinking` | | `gen_ai.reasoning.content` |

Spans with no GenAI, LLM or tool attributes (for example plain HTTP spans) are counted as
`ignored`, not stored. Status code 2 (error) is classified by `error.type`, the status message
and the HTTP status: `rate_limit`, `timeout`, `auth`, `policy_denial`, `tool_failure`, or
`other`.

## Intake

| | |
|---|---|
| Endpoints | `POST /v1/intake/steps` with `{"steps":[{session_id, seq, ts, agent_key?, type?, tool_name?, model?, provider?, usage?, latency_ms?, status?, error_class?, prompt?, input?, output?, reasoning?, policy?}]}`; `POST /v1/intake/otlp` (OTLP/HTTP JSON `ExportTraceServiceRequest`, gzip accepted) |
| Who may send | An **intake source** (`Authorization: Bearer zsrc.<id>.<secret>`), or an **active agent** with its Phase 1 credential. Human tokens get 403. |
| Unauthenticated | 401 `{"error":"unauthorized"}`. Authentication runs **before the body is read**, so nothing from the batch is stored. Only the `auth.failed` audit event is written. |
| Failed credentials | Same 401 for every reason. Unknown, bad or revoked agent credentials, source tokens and provider keys become gateway discovery sightings, fingerprinted from source address, user agent and the public key-id or source-id prefix. The presented secret is never stored. |
| Limits | `ZENAI4_INTAKE_MAX_BYTES` (1 MiB, after decompression) and `ZENAI4_INTAKE_MAX_STEPS` (1000 steps or spans) give 413. Caddy allows up to 8 MB on `/v1/intake/*` so the gateway's own limit is the one that applies. There is a per-source or per-agent rate limit (600 a minute). |
| Batch record | Every batch, including refused ones, gets an `intake_batches` row (counts: items, accepted, duplicates, rejected, ignored; status; body SHA-256) and an `intake.batch` audit event. The batch row stores the audit `seq`. |
| Partial batches | Steps are validated one by one. Bad steps are rejected with a reason and good ones are stored. The steps API returns 200 with per-index `errors`, or 422 if nothing was accepted. OTLP returns `partialSuccess.rejectedSpans`. |
| Errors | Callers see `bad_request`, `batch_too_large`, `unsupported_media_type`, `unauthorized`, `forbidden` or `internal_error` + `requestId`. No exception text, SQL or stack is ever sent. Details go to stderr with the request id, and a `request.error` audit event is written. A final Express error handler covers **every** route, not only intake. |

### Identity

* **Agent credential:** the agent is the credential's subject. A step whose `agent_key` names
  a different agent is rejected and audited as `identity.mismatch`.
* **Source:** each step's agent key (`agent_key`, `gen_ai.agent.id`, `zenai4.agent.key`, or
  `service.name`) is looked up by agent id, then by manifest id.
  * Match: `agent_id` is set, and the agent's lifecycle state on arrival is stored on the step
    (`expired` if it is active but past expiry).
  * No match: the step is stored with `agent_id = NULL` and `observed_agent_key` set, which
    marks it unregistered.
* Sessions are keyed by `(sender scope, session key)`. The scope is `source:<id>` or
  `agent:<id>`, so two senders cannot collide or inject into each other's sessions.

### Capture mode and redaction

| Mode | Stored |
|---|---|
| `none` | No payload information at all, not even sizes. |
| `metadata` (default) | Payload sizes (`promptChars`, `inputChars`, `outputChars`), whether reasoning was present (`dropped`) and which conventions were seen. No text. |
| `redacted` | Prompt, tool input and output text after **(1)** the secret scrubber (provider keys, ZenAi4 agent, user and source tokens, Bearer/Basic values) plus replacement of values under sensitive keys (`password`, `token`, `api_key`, ...); **(2)** the PII redactor (email, phone, card numbers with a Luhn check, Singapore NRIC/FIN and US SSN), configurable with `ZENAI4_PII_REDACT`; **(3)** truncation to `ZENAI4_PAYLOAD_MAX_CHARS`, applied after redaction so a cut can never expose part of a secret. `redaction_counts` records how many of each kind were replaced, never what. |

* Sources set their own mode (`source add --capture`). Agent credentials use
  `ZENAI4_INTAKE_CAPTURE_MODE` (default `metadata`).
* **Reasoning / chain of thought** is dropped unless `ZENAI4_CAPTURE_REASONING=1`, and is kept
  only in `redacted` mode, redacted like everything else. In OTLP, reasoning and thinking
  message parts are split out of the prompt and output first, so they cannot slip through
  inside the messages.
* Identifiers (agent key, session key, tool, model, operation) are scrubbed and length-capped
  in every mode.

## Storage

SQLite (running code) in the control-plane database:

| Table | Rule |
|---|---|
| `intake_sources` | Token hash only. No delete (revocation is recorded state). |
| `intake_batches` | Append-only: no update, no delete. |
| `telemetry_sessions` | No delete. `max_seq` and `gap_checked_seq` support gap checks. |
| `telemetry_steps` | Append-only. **The only permitted update** clears the four `*_redacted` payload columns and stamps `payload_purged_at`. Every other column is immutable, enforced by trigger. Unique `(session_id, step_key)`: `step_key` is `seq:<n>` or `span:<id>`, and the first write wins. |
| `policy_violations` | Append-only, hash-chained (`prev_hash`, `hash` over every field, the same construction as the audit log and ledger). |
| `telemetry_alerts` | No delete. Acknowledging requires who, why and when (CHECK). |

* There are no foreign keys with `ON DELETE CASCADE` anywhere, in SQLite or Postgres.
* `TelemetryStore` exposes no method that updates or deletes a step or violation. Tests
  assert this, and assert that the database refuses direct `UPDATE` and `DELETE`.
* Violations come from two places:
  * steps carrying a `deny` or `hold_for_approval` policy decision (intake);
  * `/v1/call` calls the policy engine denies or holds (gateway).

  Each records the agent, session, step, policy id and version, rule, decision, and the
  blocked action: tool or operation, plus the redacted input only when the source captures
  `redacted`. Gateway parameters are always redacted and truncated to 512 characters.
* Retention: `telemetry-retention` runs daily (or `zenai4-admin telemetry retention`). It
  nulls the payload columns of steps received more than `ZENAI4_PAYLOAD_RETENTION_DAYS` (30)
  ago. Metadata rows, violations, alerts, batches and the audit log are never touched. Each
  run is audited.

## Reconciliation

The `telemetry-reconcile` scheduler job runs hourly by default
(`ZENAI4_RECONCILE_INTERVAL_HOURS`). It can also be run with `POST /v1/telemetry/reconcile`
or `zenai4-admin telemetry reconcile`. It processes steps stored since its last run (a cursor
on the append-only table), then runs the time-based checks. Every finding goes through Phase 1
services and is audited.

| Finding | Effect |
|---|---|
| **Unregistered agent** (a source reported an agent key that is not in the registry) | `discovered_agents` row with source `telemetry` and kind `observed_agent`. Deduplicated per (source, key), with counts accumulating. Tools, models and providers seen are merged into the attributes. It appears in the triage queue and can be claimed, assigned, ignored or disabled like any other discovery. (Failed credentials at intake are gateway sightings, as in Phase 1.) |
| **Drift** (an active agent used a tool not in its grants, or a model not in `permittedModels`) | `drift` alert, one per agent and drifted set. A version or date suffix on a permitted model counts as permitted (`claude-sonnet-5-20261001` matches `claude-sonnet-5`). The tier is recomputed from registered plus observed tools, with unknown tools assumed **irreversible**. If the result is high or critical, or the access profile requires review, the agent needs re-review. What happens next depends on the mode (see below). |
| **Bypass** (activity from an agent that was suspended, retired or expired when the step arrived) | `bypass` alert, **high** severity. Draft, pending or rejected agents give **medium**. |
| **Telemetry gap** (a session's numbered steps have holes once it has been quiet for `ZENAI4_GAP_GRACE_MINUTES`, default 10) | `telemetry_gap` alert listing the missing numbers. Each session is checked up to its current maximum `seq`, so a later gap raises a new check. |
| **Dormant** (an active agent with no telemetry **and** no gateway call for `ZENAI4_DORMANT_DAYS`, default 30) | `dormant` alert, `GET /v1/telemetry/dormant`, `zenai4-admin telemetry dormant`, and `dormant: true` in the recertification summary. |
| **Violation threshold** (deny decisions in the last `ZENAI4_VIOLATION_WINDOW_DAYS` (30) ≥ `ZENAI4_VIOLATION_THRESHOLD` (5)) | The effective tier is raised to `ZENAI4_VIOLATION_RAISE_TIER` (high) by a **system-recorded raise override** (`by: system:telemetry-reconcile`), plus a `violation_threshold` alert. Under the Phase 1 rules an owner cannot lower it; only a security reviewer who is not an owner can, with a reason if going below the computed tier. |

### Drift handling: `alert_only` (default) or `enforce_review`

Set with `ZENAI4_DRIFT_MODE`.

* **`alert_only` (default):** the registry is never changed by telemetry. The drift alert says
  whether re-review is needed (`needsReview`, `observedTier`, `action`). Security decides
  what to do.
* **`enforce_review`:** when re-review is needed, the agent:
  * gets a system-recorded tier raise (if the observed tier is higher);
  * moves to `pending_approval`, with the drifted tools and models in the pending review
    notes;
  * has its credentials revoked (`observed_drift_pending_review`).

  This uses the same `sendToReReview` path as a widening Phase 1 update. Low-risk drift still
  only alerts. In this mode a violation-threshold raise into high or critical on an agent
  that was never security-approved also goes to review (the Phase 1 rule for raised tiers).

`alert_only` is the default because telemetry is attacker-influenced input. Anyone holding a
source token can report arbitrary agent keys and tools. Demoting a production agent on that
basis should be a deliberate choice, made once source tokens are tightly held. See the open
decisions below.

### Recertification and the agent record

* `POST /v1/agents/:id/recertify` now returns `activity`, the 90-day summary. It is evidence
  attached to the decision; it does not block recertification.
* `GET /v1/agents/:id/activity?days=90` (owner, sub-owner, admin, auditor, security) and
  `zenai4-admin agent activity --id` return the same summary:
  * tools (with `registered` true or false) and models (with `permitted`), with call counts;
  * providers, sessions, steps, errors and tokens;
  * gateway calls by decision;
  * violations (total, denied, in window, the 10 most recent);
  * open alerts and last seen (telemetry and gateway);
  * the dormant flag;
  * the drifted tools and models.
* `GET /v1/agents/:id` now includes `telemetry: {violationsLast30d, lastSeen, dormant,
  openAlerts, ...}`.

## Routes and CLI

| Method and path | Who | Purpose |
|---|---|---|
| `POST /v1/intake/steps` | source token or active agent | Steps batch |
| `POST /v1/intake/otlp` | source token or active agent | OTLP/HTTP JSON traces |
| `GET /v1/intake/sources`, `GET /v1/intake/batches` | admin, security, auditor | Sources (no hashes shown), recent batches |
| `GET /v1/telemetry/alerts?status=&kind=&agent=` | security, admin, auditor; owners see their own agents | Alerts |
| `POST /v1/telemetry/alerts/:id/ack` `{reason}` | security, admin | Acknowledge. A reason is required. Audited (`telemetry.alert.ack`, success and denied). |
| `GET /v1/telemetry/dormant` | security, admin, auditor; owners see their own agents | Dormant agents |
| `GET /v1/telemetry/violations?agent=&days=`, `GET /v1/telemetry/violations/verify` | security, admin, auditor | Violation log and chain check |
| `POST /v1/telemetry/reconcile` | security, admin | Run reconciliation now |
| `GET /v1/agents/:id/activity?days=90` | owner, sub-owner, admin, auditor, security | Activity summary |

```
source add --name <n> [--kind otlp|steps] [--capture none|metadata|redacted] --as <e>   # security/admin; token printed once
source revoke --id <id> --reason <r> --as <e> | source list
telemetry alerts [--status open|acknowledged] [--kind k] [--agent id]
telemetry ack --id <alert> --reason <r> --as <e>
telemetry reconcile | retention | dormant | violations [--agent id] | verify
agent activity --id <id> [--days 90]
```

## Postgres migration

The migration is `supabase/migrations/20261016140000_telemetry_reconciliation.sql`. It extends
the existing tables; it does not add a parallel model.

* **`intake.source`:**
  * new columns `name`, `capture_mode`, `created_by`, revocation fields;
  * new kind `steps`;
  * a revocation needs who and why;
  * no delete.
* **`intake.batch`:**
  * `source_id` or `agent_id`;
  * counts, status, reasons and body SHA-256;
  * append-only.
  * `batch_id` is now a random id per request. Replays are absorbed per step, not per batch.
    The 0003 comment called it "SHA-256 of the payload".
* **`events.observed_agent`:** new key kind `agent_key`, plus `source_id`.
* **`events.run`:**
  * becomes the session, with `agent_id` (registry link), `observed_agent_key`, `scope`,
    `session_key` (unique together), `max_seq` and `gap_checked_seq`;
  * no delete.
* **`events.event`:**
  * becomes the step;
  * new columns:
    * `step_key`, `seq`, `span_id`, `agent_id` (foreign key), `agent_state`,
      `observed_agent_key`, `received_at`;
    * `capture_mode` and the four `*_redacted` columns, which are allowed only in `redacted`
      mode (CHECK);
    * `payload_meta`, `redaction_counts`, `payload_purged_at`.
  * Step type and error class are extended (`other`, `auth`).
  * A row trigger allows only the retention update. Row triggers propagate to every
    partition.
  * `events.purge_payloads(keep_days)` does the retention update. `events.drop_partitions`
    remains the coarse metadata retention.
* **`events.event_key`:** primary key `(run_id, step_key)`. It deduplicates across
  partitions, which a partitioned table cannot enforce itself.
* **`control.policy_violation`:**
  * append-only through `control.refuse_change()`;
  * hash-chained, with `prev_hash UNIQUE` so the chain cannot fork;
  * the documented writer takes an advisory lock.
* **`control.telemetry_alert`:**
  * an acknowledgement needs who, why and when;
  * an acknowledged alert cannot be reopened or rewritten;
  * no delete.
* **`control.discovered_agent`:** source `telemetry` added.
* **Report views** (`zenai4_report`): `agent_activity_30d`, `dormant_agent`,
  `policy_violation_30d`, `telemetry_alert_open`, `intake_batch_daily`.
* Grants come from 0001's default privileges. Nothing is exposed on the Data API, and no
  cascades are introduced.

**Validation:** all seven migrations were applied in order to a throwaway local PostgreSQL 16
(Supabase runs 17; nothing used is version-specific). The test exercised:

* revocation without a reason, and source delete;
* batch without a sender, batch update and delete;
* payload text in `metadata` mode;
* a duplicate `(run, step_key)`;
* step metadata update, a payload rewrite and a step delete;
* `events.purge_payloads` clearing only the payload columns;
* a forked violation chain, violation update and delete;
* an acknowledgement without a reason, reopening an acknowledged alert, and alert delete;
* every report view;
* `zenai4_report` able to read report views and refused on `control.*`;
* `zenai4_app` able to write;
* zero cascading foreign keys in the catalogue.

The instance was then removed.

## Design decisions (made without sign-off; revisit if needed)

1. **Intake lives on the gateway**, not in a separate service. It authenticates before reading
   the body, and Caddy stays the only TLS front. The PRD's disk queue is the Collector's
   file-backed sending queue (plus the reference sender's spool), not a queue inside ZenAi4.
2. **Two credential types for intake:** a per-source `zsrc` token (Collector, shipper) or the
   agent's own credential. Source tokens work only on `/v1/intake/*`. Creating and revoking
   them requires security or admin. Revoking takes effect immediately.
3. **Unknown agent key from a source: accept, store as unregistered, discover.** Unknown
   *credentials* are refused (401) and fingerprinted, as in Phase 1. The difference: a valid
   source vouches for its data; an unknown credential vouches for nothing.
4. **The default capture mode is `metadata`.** Reasoning is off by default even in
   `redacted` mode.
5. **Unknown tools are treated as irreversible** when recomputing the observed tier. That
   is conservative, and it is what turns "a money-touching agent started calling
   `wire_transfer`" into high.
6. **Drift defaults to `alert_only`** (see above).
7. **Violation threshold counts `deny` only.** `hold_for_approval` is recorded as a violation
   but not counted toward the threshold, because holds are the policy working as designed.
   The default threshold is 5 denies in 30 days, raising the tier to high.
8. **Dormancy counts gateway calls as activity** as well as telemetry. Otherwise an agent that
   only uses `/v1/call` would look dormant.
9. **Gap checks wait for a quiet period** (10 minutes) so out-of-order delivery inside a
   batch window is not reported as loss.
10. **OTLP is JSON only.** Protobuf is refused with 415 and a hint. The Collector example uses
    `encoding: json`.
11. **The recertification summary is informational.** It does not block recertifying a
    dormant or drifting agent. The owner sees the evidence, and the audit records that they
    saw it.
12. **The final Express error handler applies to all routes.** No response body anywhere can
    carry exception text.

## Known limits and open items

* **Postgres is not wired.** The gateway, the CLI and every test use SQLite. The migration
  mirrors the design; a Postgres-backed store is future work. `deploy/vm` runs Postgres and
  Studio for the schema only.
* **The VM stack has not been started.** Images could not be pulled in the build environment.
  Tags are pinned but unverified. Only `docker compose config` was validated.
* **Single-writer chains.** The violation chain, like the audit chain, assumes one writer
  (SQLite transaction; in Postgres, an advisory lock as documented on the table).
* **Rate limiter and reconcile cursor are per process.** Run the scheduler
  (`ZENAI4_SCHEDULER=1`) in one replica, as in Phase 1.
* **Redaction is pattern-based.** It catches common shapes and errs toward over-redaction
  (for example a Luhn-valid 16-digit order number). It does not detect names, addresses or
  free-text PII. Use `metadata` where that matters.
* **Agent keys from a source are trusted as reported.** A source can claim to be any agent.
  Mitigations: tokens are per source, revocation is immediate, the source id is on every
  step and alert, and drift defaults to `alert_only`. Binding sources to an allow-list of
  agent keys is a sensible next step.
* **Cost is not computed at intake.** Tokens are stored; pricing against
  `events.price_book` belongs to phase 2 (Decipher).
* **No protobuf OTLP, logs or metrics signals.** Only traces are accepted.
* **No deduplication across senders.** The same span sent by two sources is stored twice
  (once per scope).
* **No route to un-acknowledge an alert.** By design, an acknowledged alert cannot be
  reopened. A recurrence bumps its count; it does not reopen it.

## Decisions needing confirmation

1. Keep `alert_only` as the default drift mode, or switch pilots to `enforce_review`?
2. Violation threshold: 5 denies in 30 days raising to `high`. Is that the right sensitivity
   for MAS-style reporting?
3. Should a source be restricted to a declared set of agent keys (an allow-list on the
   source)?
4. Should payload retention be 30 days, given MAS evidence needs (metadata is kept
   indefinitely)?
