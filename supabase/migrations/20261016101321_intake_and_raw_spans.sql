-- ZenAi4 0003: intake sources, batches, raw spans (7-day, partitioned by day).
CREATE TABLE intake.source (
  source_id    text PRIMARY KEY,
  kind         text NOT NULL CHECK (kind IN ('otlp','litellm','file','syslog')),
  token_hash   text NOT NULL UNIQUE,
  enabled      boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz
);

CREATE TABLE intake.batch (
  batch_id       text PRIMARY KEY,                -- SHA-256 of the payload: a replay is a no-op
  source_id      text NOT NULL REFERENCES intake.source(source_id),
  received_at    timestamptz NOT NULL,
  loaded_at      timestamptz NOT NULL DEFAULT now(),
  byte_count     integer NOT NULL,
  record_count   integer NOT NULL,
  audit_seq      bigint NOT NULL REFERENCES control.audit_event(seq),
  deciphered_at  timestamptz
);

CREATE TABLE events.raw_span (
  batch_id    text NOT NULL,
  record_no   integer NOT NULL,
  received_at timestamptz NOT NULL,
  record      jsonb NOT NULL,                     -- redacted OTLP span or log record
  PRIMARY KEY (received_at, batch_id, record_no)
) PARTITION BY RANGE (received_at);
