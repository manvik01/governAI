# ZenAi4 database on Supabase

Development database: Supabase project `governAI` (ref `svxazrxeisxcnatfwdbw`), PostgreSQL 17.
Migrations in `supabase/migrations/` are the source of truth for the schema; see the build plan
for which phase adds which tables.

| Schema | Holds |
|---|---|
| `control` | Agents, owners, credentials, append-only audit chain |
| `intake` | Log sources (token hashes) and every received batch |
| `events` | Raw spans (7 days) and canonical events, runs, observed agents, price book; partitioned by day |
| `report` | Daily roll-ups and report views |
| `prove` | Owner claims, recertification, MAS evidence (phase 4) |

None of these schemas is exposed through the Supabase Data API, and `anon` and `authenticated`
have no access. ZenAi4 connects as `zenai4_app`; BI tools use the read-only `zenai4_report`.

## After the first migration

Set the two role passwords in the SQL editor (never commit them):

    ALTER ROLE zenai4_app PASSWORD '...';
    ALTER ROLE zenai4_report PASSWORD '...';

Then use the session pooler connection string with that role as `DATABASE_URL`.

## Applying migrations

    npx supabase login
    npx supabase link --project-ref svxazrxeisxcnatfwdbw
    npx supabase db push

## Partition maintenance

`events.ensure_partitions(7)` must run daily (the ZenAi4 worker does this in phase 2), and
`events.drop_partitions('event', 30)` / `('raw_span', 7)` apply retention.
