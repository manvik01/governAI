-- ZenAi4 0006: phase 1 - registration and discovery.
-- Mirrors the SQLite stores in src/registry/registry.ts, src/discovery/discovery.ts
-- and src/discovery/scheduler.ts. Grants come from the default privileges set in
-- 0001 (zenai4_app read/write; nothing for anon/authenticated; not on the Data API).
-- Append-only evidence (owner claims, recertifications, risk-tier decisions) lives
-- in `prove` and is guarded by control.refuse_change().
--
-- Secrets: no column here holds a credential, API key or token. Discovery rows carry
-- non-secret attributes only; a leaked key is represented by provider, repo, path,
-- line and a 4-hex SHA-256 prefix (attributes->>'keyFingerprint').

-- ---------------------------------------------------------------- lifecycle

-- 0002 omitted 'rejected'. Full lifecycle: draft -> pending_approval -> active ->
-- suspended -> retired, plus rejected.
ALTER TABLE control.agent DROP CONSTRAINT IF EXISTS agent_lifecycle_state_check;
ALTER TABLE control.agent ADD CONSTRAINT agent_lifecycle_state_check
  CHECK (lifecycle_state IN ('draft','pending_approval','active','suspended','rejected','retired'));

CREATE OR REPLACE FUNCTION control.risk_rank(tier text) RETURNS integer
LANGUAGE sql IMMUTABLE AS $$ SELECT array_position(ARRAY['low','medium','high','critical'], tier) $$;

ALTER TABLE control.agent
  ADD COLUMN computed_risk_tier      text CHECK (computed_risk_tier IN ('low','medium','high','critical')),
  ADD COLUMN risk_override_tier      text CHECK (risk_override_tier IN ('low','medium','high','critical')),
  ADD COLUMN risk_override_direction text CHECK (risk_override_direction IN ('raise','lower')),
  ADD COLUMN risk_override_by        text REFERENCES control.directory_user(user_id),
  ADD COLUMN risk_override_reason    text,
  ADD COLUMN risk_override_at        timestamptz,
  ADD COLUMN manifest_id             text UNIQUE,      -- agent.yaml metadata.id (apply idempotency key)
  ADD COLUMN manifest_hash           text,             -- sha256 of the last applied spec
  ADD COLUMN discovery_id            text,             -- FK added below, after the table exists
  ADD COLUMN suspended_reason        text,
  ADD COLUMN suspended_at            timestamptz,
  ADD COLUMN retired_at              timestamptz,
  ADD COLUMN last_recertified_at     timestamptz,
  ADD COLUMN recertified_by          text REFERENCES control.directory_user(user_id),
  -- an override is a recorded human decision: who and when, always
  ADD CONSTRAINT agent_risk_override_recorded CHECK (
    (risk_override_tier IS NULL AND risk_override_direction IS NULL)
    OR (risk_override_tier IS NOT NULL AND risk_override_direction IS NOT NULL
        AND risk_override_by IS NOT NULL AND risk_override_at IS NOT NULL)),
  -- an owner raise can only add risk; effective tier = max(computed, raised)
  ADD CONSTRAINT agent_risk_raise_not_below CHECK (
    risk_override_direction IS DISTINCT FROM 'raise'
    OR control.risk_rank(risk_tier) >= control.risk_rank(computed_risk_tier)),
  -- lowering below the computed floor needs a written reason
  ADD CONSTRAINT agent_risk_lower_reason CHECK (
    risk_override_direction IS DISTINCT FROM 'lower'
    OR control.risk_rank(risk_override_tier) >= control.risk_rank(computed_risk_tier)
    OR coalesce(btrim(risk_override_reason), '') <> ''),
  ADD CONSTRAINT agent_retired_at CHECK (lifecycle_state <> 'retired' OR retired_at IS NOT NULL),
  ADD CONSTRAINT agent_active_has_expiry CHECK (lifecycle_state <> 'active' OR expires_at IS NOT NULL);

CREATE INDEX agent_expiry ON control.agent (expires_at) WHERE lifecycle_state = 'active';

-- Defence in depth: the database refuses lifecycle moves the application would refuse.
CREATE OR REPLACE FUNCTION control.enforce_lifecycle_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.lifecycle_state = OLD.lifecycle_state THEN
    IF OLD.lifecycle_state = 'retired' THEN
      RAISE EXCEPTION 'agent % is retired; retired agents cannot be changed', OLD.agent_id;
    END IF;
    RETURN NEW;
  END IF;
  IF NOT (
       (OLD.lifecycle_state = 'draft'            AND NEW.lifecycle_state IN ('pending_approval','active','retired'))
    OR (OLD.lifecycle_state = 'pending_approval' AND NEW.lifecycle_state IN ('active','rejected','retired'))
    OR (OLD.lifecycle_state = 'active'           AND NEW.lifecycle_state IN ('suspended','retired','pending_approval'))
    OR (OLD.lifecycle_state = 'suspended'        AND NEW.lifecycle_state IN ('active','retired','pending_approval'))
    OR (OLD.lifecycle_state = 'rejected'         AND NEW.lifecycle_state IN ('draft','retired'))
  ) THEN
    RAISE EXCEPTION 'illegal lifecycle transition: % -> %', OLD.lifecycle_state, NEW.lifecycle_state;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER agent_lifecycle_transition BEFORE UPDATE ON control.agent
  FOR EACH ROW EXECUTE FUNCTION control.enforce_lifecycle_transition();

-- ---------------------------------------------------------------- discovery

CREATE TABLE control.discovered_agent (
  discovery_id  text PRIMARY KEY,
  fingerprint   text NOT NULL UNIQUE,              -- sha256 of source + non-secret identity
  source        text NOT NULL CHECK (source IN ('gateway','egress_import','entra_id','okta','copilot_studio','gemini_enterprise','github')),
  kind          text NOT NULL,                     -- failed_credential, direct_provider_traffic, agent_identity, service_app, mcp_server, llm_api_key, ...
  display_name  text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  count         bigint NOT NULL CHECK (count > 0),
  status        text NOT NULL DEFAULT 'new' CHECK (status IN ('new','claimed','registered','ignored','disabled')),
  owner_id      text REFERENCES control.directory_user(user_id),
  agent_id      text REFERENCES control.agent(agent_id),
  attributes    jsonb NOT NULL DEFAULT '{}',       -- scrubbed of secret-shaped values before insert
  status_by     text,
  status_reason text,
  status_at     timestamptz,
  CHECK (last_seen >= first_seen),
  CHECK (status NOT IN ('claimed','registered') OR (owner_id IS NOT NULL AND agent_id IS NOT NULL)),
  CHECK (status <> 'ignored' OR coalesce(btrim(status_reason), '') <> ''),
  CHECK (status = 'new' OR (status_by IS NOT NULL AND status_at IS NOT NULL))
);
CREATE INDEX discovered_agent_triage ON control.discovered_agent (last_seen DESC)
  WHERE status = 'new' AND owner_id IS NULL AND agent_id IS NULL;
CREATE INDEX discovered_agent_status ON control.discovered_agent (status, last_seen DESC);

ALTER TABLE control.agent ADD CONSTRAINT agent_discovery_fk
  FOREIGN KEY (discovery_id) REFERENCES control.discovered_agent(discovery_id);

CREATE OR REPLACE FUNCTION control.enforce_discovery_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  IF NOT (
       (OLD.status = 'new'        AND NEW.status IN ('claimed','ignored','disabled'))
    OR (OLD.status = 'claimed'    AND NEW.status IN ('registered','ignored','disabled'))
    OR (OLD.status = 'registered' AND NEW.status = 'disabled')
    OR (OLD.status = 'ignored'    AND NEW.status IN ('new','disabled'))
  ) THEN
    RAISE EXCEPTION 'illegal discovery transition: % -> %', OLD.status, NEW.status;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER discovered_agent_transition BEFORE UPDATE ON control.discovered_agent
  FOR EACH ROW EXECUTE FUNCTION control.enforce_discovery_transition();

-- Scheduler run history (connectors every 6h by default, expiry sweep hourly).
CREATE TABLE control.discovery_run (
  run_id      text PRIMARY KEY,
  job_id      text NOT NULL,                       -- connector:<id> | expiry-sweep
  started_at  timestamptz NOT NULL,
  finished_at timestamptz,
  status      text NOT NULL CHECK (status IN ('running','ok','error','skipped')),
  items       integer NOT NULL DEFAULT 0 CHECK (items >= 0),
  created     integer NOT NULL DEFAULT 0 CHECK (created >= 0),
  error       text,                                -- scrubbed; never contains credentials
  CHECK (status = 'running' OR finished_at IS NOT NULL),
  CHECK (status NOT IN ('error','skipped') OR error IS NOT NULL)
);
CREATE INDEX discovery_run_job ON control.discovery_run (job_id, started_at DESC);

-- ---------------------------------------------------------------- evidence (append-only)

-- Who took ownership of a discovered agent, and how.
CREATE TABLE prove.owner_claim (
  claim_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  discovery_id text NOT NULL REFERENCES control.discovered_agent(discovery_id),
  agent_id     text NOT NULL REFERENCES control.agent(agent_id),  -- the draft created by the claim
  owner_id     text NOT NULL REFERENCES control.directory_user(user_id),
  claimed_by   text NOT NULL REFERENCES control.directory_user(user_id),
  method       text NOT NULL CHECK (method IN ('claim','assign_owner')),
  at           timestamptz NOT NULL DEFAULT now(),
  CHECK (method <> 'claim' OR owner_id = claimed_by)
);
CREATE TRIGGER owner_claim_append_only BEFORE UPDATE OR DELETE ON prove.owner_claim
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- Every recertification: the owner confirms the agent is still needed.
CREATE TABLE prove.recertification (
  recert_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  agent_id            text NOT NULL REFERENCES control.agent(agent_id),
  recertified_by      text NOT NULL REFERENCES control.directory_user(user_id),
  previous_expires_at timestamptz NOT NULL,
  new_expires_at      timestamptz NOT NULL,
  reactivated         boolean NOT NULL DEFAULT false,   -- true when it revived an expiry-suspended agent
  at                  timestamptz NOT NULL DEFAULT now(),
  CHECK (new_expires_at > at),
  CHECK (new_expires_at <= at + interval '90 days' + interval '1 minute')
);
CREATE INDEX recertification_agent ON prove.recertification (agent_id, at DESC);
CREATE TRIGGER recertification_append_only BEFORE UPDATE OR DELETE ON prove.recertification
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- Every human risk-tier decision (raise by an owner, lower by security).
CREATE TABLE prove.risk_tier_decision (
  decision_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  agent_id      text NOT NULL REFERENCES control.agent(agent_id),
  decided_by    text NOT NULL REFERENCES control.directory_user(user_id),
  direction     text NOT NULL CHECK (direction IN ('raise','lower')),
  from_tier     text NOT NULL CHECK (from_tier IN ('low','medium','high','critical')),
  to_tier       text NOT NULL CHECK (to_tier IN ('low','medium','high','critical')),
  computed_tier text NOT NULL CHECK (computed_tier IN ('low','medium','high','critical')),
  reason        text,
  at            timestamptz NOT NULL DEFAULT now(),
  CHECK ((direction = 'raise') = (control.risk_rank(to_tier) > control.risk_rank(from_tier))),
  CHECK (direction = 'raise' OR control.risk_rank(to_tier) >= control.risk_rank(computed_tier) OR coalesce(btrim(reason), '') <> '')
);
CREATE TRIGGER risk_tier_decision_append_only BEFORE UPDATE OR DELETE ON prove.risk_tier_decision
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();

-- ---------------------------------------------------------------- report

-- Shadow-agent queue and expiring agents, for BI (zenai4_report has SELECT on report.*).
CREATE VIEW report.shadow_agent_queue AS
SELECT discovery_id, source, kind, display_name, first_seen, last_seen, count
FROM control.discovered_agent
WHERE status = 'new' AND owner_id IS NULL AND agent_id IS NULL;

CREATE VIEW report.agent_expiring AS
SELECT agent_id, name, owner_id, business_unit, risk_tier, expires_at
FROM control.agent
WHERE lifecycle_state = 'active' AND expires_at <= now() + interval '14 days';

-- Views are owned by the migration user, so zenai4_report can read them without
-- needing access to the underlying control.* tables.
GRANT SELECT ON report.shadow_agent_queue, report.agent_expiring TO zenai4_report;
