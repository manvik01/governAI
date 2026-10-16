-- ZenAi4 0004: canonical events, runs, observed agents, price book, partition creation.
CREATE TABLE events.price_book (
  provider     text NOT NULL,
  model        text NOT NULL,
  valid_from   timestamptz NOT NULL,
  input_per_1m  numeric(12,6) NOT NULL,
  output_per_1m numeric(12,6) NOT NULL,
  currency     text NOT NULL DEFAULT 'USD',
  PRIMARY KEY (provider, model, valid_from)
);

CREATE TABLE events.observed_agent (
  observed_id   text PRIMARY KEY,                 -- hash of the identifying key
  key_kind      text NOT NULL CHECK (key_kind IN ('credential','agent_name','service_name','api_key_fingerprint')),
  key_value     text NOT NULL,
  agent_id      text REFERENCES control.agent(agent_id),   -- NULL = shadow agent
  confidence    numeric(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  first_seen_at timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL
);

CREATE TABLE events.run (
  run_id        text PRIMARY KEY,                 -- source + trace id
  observed_id   text NOT NULL REFERENCES events.observed_agent(observed_id),
  parent_run_id text REFERENCES events.run(run_id),
  acting_user   text,
  started_at    timestamptz NOT NULL,
  ended_at      timestamptz,
  outcome       text CHECK (outcome IN ('success','failure','running','stuck')),
  step_count    integer NOT NULL DEFAULT 0,
  cost_usd      numeric(14,6)
);

CREATE TABLE events.event (
  event_id        text NOT NULL,                  -- hash of source, trace id, span id
  event_time      timestamptz NOT NULL,
  run_id          text NOT NULL,
  observed_id     text NOT NULL,
  step_type       text NOT NULL CHECK (step_type IN ('model_call','tool_call','handoff','approval','error')),
  acting_user     text,
  provider        text,
  model           text,
  tool            text,
  input_tokens    integer,
  output_tokens   integer,
  cost_usd        numeric(14,6),                  -- NULL when usage is missing, never 0
  cost_status     text NOT NULL CHECK (cost_status IN ('priced','unresolved','not_applicable')),
  latency_ms      integer,
  status          text NOT NULL CHECK (status IN ('ok','error')),
  error_class     text CHECK (error_class IN ('rate_limit','timeout','tool_failure','policy_denial','runaway_loop','cost_spike')),
  mapping_version text NOT NULL,
  batch_id        text NOT NULL,
  PRIMARY KEY (event_time, event_id)
) PARTITION BY RANGE (event_time);
CREATE INDEX event_time_brin ON events.event USING brin (event_time);
CREATE INDEX event_agent     ON events.event (observed_id, event_time);
CREATE INDEX event_run       ON events.event (run_id);

-- Daily partitions: called by the nightly job for today + 7 days.
CREATE OR REPLACE FUNCTION events.ensure_partitions(days_ahead integer DEFAULT 7)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE d date; t text;
BEGIN
  FOR d IN SELECT generate_series(current_date, current_date + days_ahead, interval '1 day')::date LOOP
    FOREACH t IN ARRAY ARRAY['event','raw_span'] LOOP
      EXECUTE format('CREATE TABLE IF NOT EXISTS events.%I PARTITION OF events.%I FOR VALUES FROM (%L) TO (%L)',
                     t || '_' || to_char(d, 'YYYYMMDD'), t, d, d + 1);
    END LOOP;
  END LOOP;
END $$;

SELECT events.ensure_partitions(7);
