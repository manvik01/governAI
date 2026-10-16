-- ZenAi4 0007: let the service create daily partitions without owning the tables.
-- ensure_partitions runs with its owner's rights (the migration user), with a fixed
-- search_path so it cannot be redirected. Only zenai4_app may call it.
ALTER FUNCTION events.ensure_partitions(integer) SECURITY DEFINER SET search_path = pg_catalog, events;
REVOKE ALL ON FUNCTION events.ensure_partitions(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION events.ensure_partitions(integer) TO zenai4_app;
