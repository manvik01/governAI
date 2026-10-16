-- ZenAi4 0001: roles, schemas, append-only guard.
-- Schemas are owned by the migration user (postgres on Supabase).
-- They are NOT added to the Supabase Data API, so anon and authenticated cannot reach them.
-- Set role passwords by hand after this runs, never in a migration:
--   ALTER ROLE zenai4_app PASSWORD '...';  ALTER ROLE zenai4_report PASSWORD '...';

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zenai4_app')    THEN CREATE ROLE zenai4_app    LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zenai4_report') THEN CREATE ROLE zenai4_report LOGIN; END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS control;
CREATE SCHEMA IF NOT EXISTS intake;
CREATE SCHEMA IF NOT EXISTS events;
CREATE SCHEMA IF NOT EXISTS report;
CREATE SCHEMA IF NOT EXISTS prove;

-- Belt and braces: Supabase API roles get nothing here.
DO $$ DECLARE r text; BEGIN
  FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON SCHEMA control, intake, events, report, prove FROM %I', r);
    END IF;
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA control, intake, events, report, prove TO zenai4_app;
GRANT USAGE ON SCHEMA report TO zenai4_report;

-- Tables created later by this migration user get the same grants automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA control, intake, events, report, prove
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO zenai4_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA control, intake, events, report, prove
  GRANT USAGE, SELECT ON SEQUENCES TO zenai4_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA report GRANT SELECT ON TABLES TO zenai4_report;

CREATE OR REPLACE FUNCTION control.refuse_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
