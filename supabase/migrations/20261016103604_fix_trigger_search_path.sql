-- ZenAi4 0008: fixed search_path on the append-only trigger function (Supabase advisor 0011).
ALTER FUNCTION control.refuse_change() SET search_path = pg_catalog;
