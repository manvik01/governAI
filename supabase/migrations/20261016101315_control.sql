-- ZenAi4 0002: control tables (ported from SQLite).
CREATE TABLE control.directory_user (
  user_id       text PRIMARY KEY,
  display_name  text NOT NULL,
  email         text,
  business_unit text,
  active        boolean NOT NULL DEFAULT true,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.agent (
  agent_id        text PRIMARY KEY,
  name            text NOT NULL,
  purpose         text,
  owner_id        text REFERENCES control.directory_user(user_id),
  sub_owner_id    text REFERENCES control.directory_user(user_id),
  business_unit   text,
  platform        text,
  model_provider  text,
  risk_tier       text CHECK (risk_tier IN ('low','medium','high','critical')),
  lifecycle_state text NOT NULL DEFAULT 'draft'
                  CHECK (lifecycle_state IN ('draft','pending_approval','active','suspended','retired')),
  expires_at      timestamptz,
  data            jsonb NOT NULL DEFAULT '{}',   -- remaining registration fields, as in the SQLite store
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE control.credential (
  credential_id text PRIMARY KEY,
  agent_id      text NOT NULL REFERENCES control.agent(agent_id),
  secret_hash   text NOT NULL,
  issued_at     timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz,
  revoked_at    timestamptz,
  last_used_at  timestamptz
);

CREATE TABLE control.audit_event (
  seq        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,
  action     text NOT NULL,
  subject    text,
  detail     jsonb NOT NULL DEFAULT '{}',      -- secrets redacted before insert
  prev_hash  text NOT NULL,
  hash       text NOT NULL UNIQUE
);
CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE ON control.audit_event
  FOR EACH ROW EXECUTE FUNCTION control.refuse_change();
