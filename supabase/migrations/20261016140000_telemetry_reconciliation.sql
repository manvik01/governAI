-- ZenAi4 0007: phase 1.1 - telemetry intake and reconciliation.
-- Mirrors the SQLite stores in src/telemetry/store.ts. EXTENDS the existing
-- intake.* and events.* tables (0003, 0004) instead of adding a parallel
-- sessions/steps model:
--   intake.source       + name, capture mode, revocation, 'steps' kind
--   intake.batch        + accepted/duplicate/rejected/ignored counts, status,
--                         agent-credential batches (source_id OR agent_id)
--   events.run          = a session: + agent_id (registry link), scope,
--                         session key, sequence bookkeeping for gap checks
--   events.event        = a step: + seq/step_key, agent link and state at
--                         arrival, capture mode, REDACTED payload columns
--   events.event_key    dedupe index: (run_id, step_key) is unique across
--                         all partitions (a partitioned table cannot do it)
--   control.policy_violation  append-only, hash-chained
--   control.telemetry_alert   drift | bypass | dormant | telemetry_gap | ...
--   report.*            telemetry views for BI (zenai4_report)
--
-- Evidence rules, as in SQLite: steps are append-only except that the
-- retention job may clear the redacted payload columns; violations and
-- batches are append-only (control.refuse_change()); alerts and sources are
-- never deleted. No foreign key cascades.
--
-- Grants: tables come from 0001's default privileges (zenai4_app read/write;
-- nothing for anon/authenticated; schemas are not on the Data API). Views in
-- report are granted to zenai4_report explicitly at the end.
--
-- Secrets: intake.source keeps SHA-256 of the token secret only. Payload
-- columns hold text that already passed the secret scrubber and PII redactor.

-- ---------------------------------------------------------------- intake

ALTER TABLE intake.source DROP CONSTRAINT IF EXISTS source_kind_check;
ALTER TABLE intake.source
  ADD CONSTRAINT source_kind_check CHECK (kind IN ('otlp','steps','litellm','file','syslog')),
  ADD COLUMN name           text,
  ADD COLUMN capture_mode   text NOT NULL DEFAULT 'metadata' CHECK (capture_mode IN ('none','metadata','redacted')),
  ADD COLUMN created_by     text REFERENCES control.directory_user(user_id),
  ADD COLUMN revoked_at     timestamptz,
  ADD COLUMN revoked_by     text REFERENCES control.directory_user(user_id),
  ADD COLUMN revoked_reason text,
  ADD CONSTRAINT source_revoked_recorded CHECK (
    revoked_at IS NULL OR (enabled = false AND revoked_by IS NOT NULL AND coalesce(btrim(revoked_reason), '') <> ''));
UPDATE intake.source SET name = source_id WHERE name IS NULL;
ALTER TABLE intake.source ALTER COLUMN name SET NOT NULL;
CREATE TRIGGER source_no_delete BEFORE DELETE ON intake.source
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- A batch comes from a source token OR an agent credential. Refused batches
-- are recorded too (status 'rejected'), so byte/record counts may be zero.
ALTER TABLE intake.batch
  ALTER COLUMN source_id DROP NOT NULL,
  ADD COLUMN agent_id     text REFERENCES control.agent(agent_id),
  ADD COLUMN endpoint     text NOT NULL DEFAULT 'otlp' CHECK (endpoint IN ('steps','otlp')),
  ADD COLUMN payload_sha256 text,                  -- of the received body; batch_id stays a random id per request
  ADD COLUMN accepted     integer NOT NULL DEFAULT 0 CHECK (accepted >= 0),
  ADD COLUMN duplicates   integer NOT NULL DEFAULT 0 CHECK (duplicates >= 0),
  ADD COLUMN rejected     integer NOT NULL DEFAULT 0 CHECK (rejected >= 0),
  ADD COLUMN ignored      integer NOT NULL DEFAULT 0 CHECK (ignored >= 0),
  ADD COLUMN status       text NOT NULL DEFAULT 'accepted' CHECK (status IN ('accepted','partial','rejected')),
  ADD COLUMN reasons      jsonb NOT NULL DEFAULT '[]',
  ADD CONSTRAINT batch_principal CHECK (source_id IS NOT NULL OR agent_id IS NOT NULL);
COMMENT ON COLUMN intake.batch.batch_id IS
  'Phase 1.1: random id per received request. Replays are absorbed per step by events.event_key, not per batch.';
CREATE INDEX batch_received ON intake.batch (received_at DESC);
CREATE TRIGGER batch_append_only BEFORE UPDATE OR DELETE ON intake.batch
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- ---------------------------------------------------------------- runs (sessions)

-- observed_agent gains the 'agent_key' kind (gen_ai.agent.id, steps API agent_key)
-- and the source that reported it.
ALTER TABLE events.observed_agent DROP CONSTRAINT IF EXISTS observed_agent_key_kind_check;
ALTER TABLE events.observed_agent
  ADD CONSTRAINT observed_agent_key_kind_check
    CHECK (key_kind IN ('credential','agent_name','service_name','api_key_fingerprint','agent_key')),
  ADD COLUMN source_id text REFERENCES intake.source(source_id);

ALTER TABLE events.run
  ADD COLUMN agent_id           text REFERENCES control.agent(agent_id),   -- NULL = unregistered
  ADD COLUMN observed_agent_key text,                                      -- non-secret key as reported
  ADD COLUMN scope              text,                                      -- 'source:<id>' | 'agent:<id>'
  ADD COLUMN session_key        text,                                      -- conversation id / session_id / trace id
  ADD COLUMN max_seq            bigint CHECK (max_seq >= 0),
  ADD COLUMN gap_checked_seq    bigint CHECK (gap_checked_seq >= 0),
  ADD CONSTRAINT run_scope_session UNIQUE (scope, session_key);
CREATE INDEX run_agent ON events.run (agent_id, started_at DESC);
CREATE TRIGGER run_no_delete BEFORE DELETE ON events.run
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- ---------------------------------------------------------------- events (steps)

ALTER TABLE events.event DROP CONSTRAINT IF EXISTS event_step_type_check;
ALTER TABLE events.event DROP CONSTRAINT IF EXISTS event_error_class_check;
ALTER TABLE events.event
  ADD CONSTRAINT event_step_type_check CHECK (step_type IN ('model_call','tool_call','handoff','approval','error','other')),
  ADD CONSTRAINT event_error_class_check CHECK (error_class IN
    ('rate_limit','timeout','tool_failure','policy_denial','runaway_loop','cost_spike','auth','other')),
  ADD COLUMN step_key           text,              -- 'seq:<n>' (steps API) | 'span:<id>' (OTLP)
  ADD COLUMN seq                bigint CHECK (seq >= 0),
  ADD COLUMN span_id            text,
  ADD COLUMN parent_span_id     text,
  ADD COLUMN source_id          text,
  ADD COLUMN agent_id           text,              -- registry link (NULL = unregistered); FK below
  ADD COLUMN agent_state        text CHECK (agent_state IN ('draft','pending_approval','active','suspended','rejected','retired','expired')),
  ADD COLUMN observed_agent_key text,
  ADD COLUMN received_at        timestamptz,
  ADD COLUMN operation          text,
  ADD COLUMN total_tokens       bigint CHECK (total_tokens >= 0),
  ADD COLUMN capture_mode       text NOT NULL DEFAULT 'metadata' CHECK (capture_mode IN ('none','metadata','redacted')),
  ADD COLUMN prompt_redacted    text,              -- secret-scrubbed + PII-redacted + truncated; NULL unless 'redacted'
  ADD COLUMN input_redacted     text,
  ADD COLUMN output_redacted    text,
  ADD COLUMN reasoning_redacted text,              -- only when reasoning capture is switched on
  ADD COLUMN payload_meta       jsonb NOT NULL DEFAULT '{}',   -- sizes, truncation flags, conventions
  ADD COLUMN redaction_counts   jsonb NOT NULL DEFAULT '{}',   -- how many of each kind were replaced, never what
  ADD COLUMN payload_purged_at  timestamptz,
  ADD CONSTRAINT event_agent_fk FOREIGN KEY (agent_id) REFERENCES control.agent(agent_id),
  ADD CONSTRAINT event_payload_only_when_redacted CHECK (
    capture_mode = 'redacted'
    OR (prompt_redacted IS NULL AND input_redacted IS NULL AND output_redacted IS NULL AND reasoning_redacted IS NULL));
CREATE INDEX event_registry_agent ON events.event (agent_id, event_time);
CREATE INDEX event_received ON events.event (received_at) WHERE payload_purged_at IS NULL;

-- Dedupe across partitions: the first (run, step_key) wins; a resend is a no-op.
CREATE TABLE events.event_key (
  run_id     text NOT NULL REFERENCES events.run(run_id),
  step_key   text NOT NULL,
  event_time timestamptz NOT NULL,
  event_id   text NOT NULL,
  PRIMARY KEY (run_id, step_key)
);
CREATE TRIGGER event_key_append_only BEFORE UPDATE OR DELETE ON events.event_key
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- Steps are append-only. The single permitted UPDATE is retention clearing
-- the redacted payload columns and stamping payload_purged_at; every other
-- column must be unchanged. Row triggers on a partitioned table apply to
-- every partition (PostgreSQL 13+).
CREATE OR REPLACE FUNCTION events.event_retention_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'events.event is append-only (expire whole days with events.drop_partitions)';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['prompt_redacted','input_redacted','output_redacted','reasoning_redacted','payload_purged_at'])
     IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['prompt_redacted','input_redacted','output_redacted','reasoning_redacted','payload_purged_at'])
     OR NEW.prompt_redacted IS NOT NULL OR NEW.input_redacted IS NOT NULL
     OR NEW.output_redacted IS NOT NULL OR NEW.reasoning_redacted IS NOT NULL
     OR NEW.payload_purged_at IS NULL THEN
    RAISE EXCEPTION 'events.event is append-only (only retention may clear payloads)';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON events.event
  FOR EACH ROW EXECUTE FUNCTION events.event_retention_only();

-- events.drop_partitions (0004) deletes whole days via DROP TABLE, which row
-- triggers do not see. It stays the coarse retention for METADATA (set
-- keep_days well beyond payload retention); payloads are cleared earlier by:
CREATE OR REPLACE FUNCTION events.purge_payloads(keep_days integer)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  UPDATE events.event
     SET prompt_redacted = NULL, input_redacted = NULL, output_redacted = NULL, reasoning_redacted = NULL,
         payload_purged_at = now()
   WHERE received_at < now() - make_interval(days => keep_days)
     AND payload_purged_at IS NULL
     AND (prompt_redacted IS NOT NULL OR input_redacted IS NOT NULL OR output_redacted IS NOT NULL OR reasoning_redacted IS NOT NULL);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

-- ---------------------------------------------------------------- discovery

ALTER TABLE control.discovered_agent DROP CONSTRAINT IF EXISTS discovered_agent_source_check;
ALTER TABLE control.discovered_agent ADD CONSTRAINT discovered_agent_source_check
  CHECK (source IN ('gateway','egress_import','entra_id','okta','copilot_studio','gemini_enterprise','github','telemetry'));

-- ---------------------------------------------------------------- policy violations (append-only, chained)

CREATE TABLE control.policy_violation (
  seq                bigint PRIMARY KEY CHECK (seq > 0),        -- assigned by the writer under an advisory lock
  violation_id       text NOT NULL UNIQUE,
  at                 timestamptz NOT NULL,
  agent_id           text REFERENCES control.agent(agent_id),   -- NULL = unregistered agent
  observed_agent_key text,
  run_id             text REFERENCES events.run(run_id),
  event_id           text,                                      -- events.event is partitioned: (event_time, event_id)
  event_time         timestamptz,
  policy_id          text NOT NULL,
  policy_version     integer,
  rule               text,
  decision           text NOT NULL CHECK (decision IN ('allow','deny','hold_for_approval')),
  blocked_action     text,                                      -- redacted before insert
  source             text NOT NULL CHECK (source IN ('gateway','intake')),
  details            jsonb NOT NULL DEFAULT '{}',
  prev_hash          text NOT NULL UNIQUE,                      -- one successor per row: no forks in the chain
  hash               text NOT NULL UNIQUE,
  CHECK (agent_id IS NOT NULL OR observed_agent_key IS NOT NULL),
  CHECK (prev_hash ~ '^[0-9a-f]{64}$' AND hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX policy_violation_agent ON control.policy_violation (agent_id, at DESC);
CREATE TRIGGER policy_violation_append_only BEFORE UPDATE OR DELETE ON control.policy_violation
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();
COMMENT ON TABLE control.policy_violation IS
  'hash = sha256(id|seq|ts|agent|observed key|session|step|policy|version|rule|decision|blocked action|source|details|prev_hash), as in src/telemetry/store.ts. Writers take pg_advisory_xact_lock(hashtext(''control.policy_violation'')) before reading the last hash.';

-- ---------------------------------------------------------------- telemetry alerts

CREATE TABLE control.telemetry_alert (
  alert_id   text PRIMARY KEY,
  kind       text NOT NULL CHECK (kind IN ('drift','bypass','dormant','telemetry_gap','violation_threshold','review_required')),
  severity   text NOT NULL CHECK (severity IN ('low','medium','high')),
  agent_id   text REFERENCES control.agent(agent_id),
  run_id     text REFERENCES events.run(run_id),
  dedupe_key text NOT NULL UNIQUE,
  details    jsonb NOT NULL DEFAULT '{}',
  status     text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged')),
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  count      integer NOT NULL DEFAULT 1 CHECK (count > 0),
  ack_by     text REFERENCES control.directory_user(user_id),
  ack_reason text,
  ack_at     timestamptz,
  CHECK (last_seen >= first_seen),
  CHECK (status = 'open' OR (ack_by IS NOT NULL AND coalesce(btrim(ack_reason), '') <> '' AND ack_at IS NOT NULL))
);
CREATE INDEX telemetry_alert_open ON control.telemetry_alert (last_seen DESC) WHERE status = 'open';
CREATE INDEX telemetry_alert_agent ON control.telemetry_alert (agent_id, last_seen DESC);

-- Alerts are never deleted; an acknowledgement cannot be undone or rewritten.
CREATE OR REPLACE FUNCTION control.enforce_alert_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'control.telemetry_alert rows cannot be deleted'; END IF;
  IF NEW.alert_id <> OLD.alert_id OR NEW.kind <> OLD.kind OR NEW.dedupe_key <> OLD.dedupe_key
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id OR NEW.first_seen <> OLD.first_seen THEN
    RAISE EXCEPTION 'telemetry alert identity cannot change';
  END IF;
  IF OLD.status = 'acknowledged' AND (NEW.status <> 'acknowledged' OR NEW.ack_by IS DISTINCT FROM OLD.ack_by
     OR NEW.ack_reason IS DISTINCT FROM OLD.ack_reason OR NEW.ack_at IS DISTINCT FROM OLD.ack_at) THEN
    RAISE EXCEPTION 'an acknowledged alert cannot be re-opened or re-acknowledged';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER telemetry_alert_change BEFORE UPDATE OR DELETE ON control.telemetry_alert
  FOR EACH ROW EXECUTE FUNCTION control.enforce_alert_change();

-- ---------------------------------------------------------------- report views

-- What each registered agent actually did in the last 30 days.
CREATE VIEW report.agent_activity_30d AS
SELECT a.agent_id, a.name, a.owner_id, a.business_unit, a.lifecycle_state, a.risk_tier,
       count(e.event_id)                                  AS steps,
       count(DISTINCT e.run_id)                           AS sessions,
       count(*) FILTER (WHERE e.status = 'error')         AS errors,
       count(DISTINCT e.tool)                             AS distinct_tools,
       count(DISTINCT e.model)                            AS distinct_models,
       coalesce(sum(e.input_tokens), 0)                   AS input_tokens,
       coalesce(sum(e.output_tokens), 0)                  AS output_tokens,
       max(e.event_time)                                  AS last_seen
FROM control.agent a
LEFT JOIN events.event e ON e.agent_id = a.agent_id AND e.event_time >= now() - interval '30 days'
GROUP BY a.agent_id, a.name, a.owner_id, a.business_unit, a.lifecycle_state, a.risk_tier;

-- Active agents with no telemetry for 30 days (the default dormancy threshold).
CREATE VIEW report.dormant_agent AS
SELECT a.agent_id, a.name, a.owner_id, a.expires_at, max(e.event_time) AS last_seen
FROM control.agent a
LEFT JOIN events.event e ON e.agent_id = a.agent_id
WHERE a.lifecycle_state = 'active'
GROUP BY a.agent_id, a.name, a.owner_id, a.expires_at
HAVING coalesce(max(e.event_time), min(a.created_at)) < now() - interval '30 days';

CREATE VIEW report.policy_violation_30d AS
SELECT coalesce(a.name, 'unregistered: ' || v.observed_agent_key) AS agent,
       v.agent_id, v.policy_id, v.policy_version, v.rule, v.decision, v.source,
       count(*) AS violations, max(v.at) AS last_at
FROM control.policy_violation v
LEFT JOIN control.agent a ON a.agent_id = v.agent_id
WHERE v.at >= now() - interval '30 days'
GROUP BY 1, v.agent_id, v.policy_id, v.policy_version, v.rule, v.decision, v.source;

CREATE VIEW report.telemetry_alert_open AS
SELECT t.alert_id, t.kind, t.severity, t.agent_id, a.name AS agent_name, a.owner_id,
       t.first_seen, t.last_seen, t.count, t.details
FROM control.telemetry_alert t
LEFT JOIN control.agent a ON a.agent_id = t.agent_id
WHERE t.status = 'open';

CREATE VIEW report.intake_batch_daily AS
SELECT date_trunc('day', received_at)::date AS day, coalesce(source_id, 'agent:' || agent_id) AS sender, endpoint,
       count(*) AS batches, sum(accepted) AS accepted, sum(duplicates) AS duplicates,
       sum(rejected) AS rejected, sum(ignored) AS ignored,
       count(*) FILTER (WHERE status = 'rejected') AS rejected_batches
FROM intake.batch
GROUP BY 1, 2, 3;

GRANT SELECT ON report.agent_activity_30d, report.dormant_agent, report.policy_violation_30d,
                report.telemetry_alert_open, report.intake_batch_daily TO zenai4_report;
