-- ZenAi4 0006: retention helper. Drops whole day partitions older than keep_days.
-- Kept separate because Supabase asks for confirmation on any DROP statement.
-- Retention: drop whole days older than the setting.
CREATE OR REPLACE FUNCTION events.drop_partitions(tbl text, keep_days integer)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE r record; n integer := 0;
BEGIN
  FOR r IN SELECT c.relname FROM pg_inherits i
           JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
           JOIN pg_namespace s ON s.oid = p.relnamespace
           WHERE s.nspname = 'events' AND p.relname = tbl
             AND to_date(right(c.relname, 8), 'YYYYMMDD') < current_date - keep_days LOOP
    EXECUTE format('DROP TABLE events.%I', r.relname);
    n := n + 1;
  END LOOP;
  RETURN n;
END $$;
