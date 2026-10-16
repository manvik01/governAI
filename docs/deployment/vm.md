# Run ZenAi4 on one VM with telemetry intake

This setup is the phase 1.1 target: one small VM that runs the ZenAi4 gateway (API and
telemetry intake) behind TLS, an optional OpenTelemetry Collector, and a trimmed Supabase
stack (Postgres 17, postgres-meta, Studio) holding the ZenAi4 Postgres schema.

> **The running gateway still uses SQLite** (`/data/zenai4.db` in the `zenai4-data` volume).
> The Postgres service holds the migrated schema from `supabase/migrations/` so it can be
> reviewed, queried and prepared for reporting. **No ZenAi4 code writes to it yet.** Do not
> expect telemetry to appear in Postgres.

Files: `deploy/vm/compose.yaml`, `deploy/vm/Caddyfile`, `deploy/vm/otel-collector.yaml`.

## What is exposed

| Service | Port | Reachable from |
|---|---|---|
| Caddy (TLS) → gateway | 443, 80 | Your network. Serves the API and `/v1/intake/*`. |
| Postgres 17 | `127.0.0.1:5432` | This VM only. Use an SSH tunnel. |
| Supabase Studio | `127.0.0.1:3000` | This VM only. Use an SSH tunnel. |
| postgres-meta | none | Studio only (internal network). |
| gateway | none | Caddy only (internal network, no route out). |
| OTel Collector (optional) | `127.0.0.1:4318` | Agents on this VM. |

Not included, on purpose: Supabase auth (GoTrue), realtime, storage, Kong and analytics. The
ZenAi4 schemas are never exposed through the Supabase Data API (see migration 0001).

## Install

```bash
cd deploy/vm
cp ../../.env.example .env
# set: ZENAI4_BACKUP_KEY, ZENAI4_HOSTNAME, POSTGRES_PASSWORD   (openssl rand -base64 32)
docker compose up -d --build
docker compose exec gateway zenai4-admin init --admin-email you@company.com --admin-name "Your Name"
docker compose exec gateway zenai4-admin user add --email sec@company.com --name "Sec" --roles security_reviewer
```

## Telemetry sources

Each sender gets its own source token. Only the SHA-256 of the secret is stored; the token is
printed once.

```bash
docker compose exec gateway zenai4-admin source add --name otel-vm1 --kind otlp --capture metadata --as sec@company.com
docker compose exec gateway zenai4-admin source list
docker compose exec gateway zenai4-admin source revoke --id <id> --reason "rotated" --as sec@company.com
```

`--capture` is `none`, `metadata` (default: sizes only, no text) or `redacted` (text kept after
secret and PII redaction, truncated). Choose `redacted` only where someone needs to read
prompts and tool input, and set `ZENAI4_PAYLOAD_RETENTION_DAYS`.

### Run the bundled collector

Put the source token in `.env` as `ZENAI4_SOURCE_TOKEN`, then:

```bash
# with `tls internal`, give the collector Caddy's root CA
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt certs/caddy-root.crt
docker compose --profile collector up -d
```

Agents on the VM send OTLP/HTTP to `http://127.0.0.1:4318`. The collector keeps a file-backed
queue in the `otel-queue` volume and retries for 30 minutes; watch
`otelcol_exporter_send_failed_spans` for anything it finally drops. A collector on another host
uses the same `otel-collector.yaml` with `ZENAI4_INTAKE_URL=https://<ZENAI4_HOSTNAME>`.

## Apply the ZenAi4 migrations to Postgres

The migrations are mounted read-only at `/zenai4-migrations`. Apply them once, in order:

```bash
docker compose exec db sh -c 'for f in /zenai4-migrations/*.sql; do echo "$f"; psql -v ON_ERROR_STOP=1 -U postgres -d postgres -f "$f" || exit 1; done'
# then set the role passwords by hand (never in a migration or in git):
docker compose exec db psql -U postgres -c "ALTER ROLE zenai4_app PASSWORD '...'"
docker compose exec db psql -U postgres -c "ALTER ROLE zenai4_report PASSWORD '...'"
```

## Reach Studio and Postgres through an SSH tunnel

Nothing on the database tier listens on a public interface. From your laptop:

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 5432:127.0.0.1:5432 you@<vm-host>
```

Then open <http://localhost:3000> for Studio, or `psql "postgresql://postgres@localhost:5432/postgres"`.
Studio has no login of its own in this stack: whoever can open the tunnel can use it, so
restrict SSH access to people who may administer the database. Close the tunnel when done.
Use `zenai4_report` (read-only on `report.*`) for BI tools, not `postgres`.

## Verified so far

- `docker compose config` validates the file (with and without the `collector` profile), and
  only Caddy publishes on a non-loopback address.
- The migrations, including `20261016140000_telemetry_reconciliation.sql`, were applied to a
  throwaway local PostgreSQL 16 and their guards exercised (see
  `docs/phase1.1-telemetry-reconciliation.md`).
- **Not yet run:** the images could not be pulled in the build environment. The pinned tags
  for `supabase/postgres`, `supabase/postgres-meta`, `supabase/studio` and
  `otel/opentelemetry-collector-contrib` should be checked against current releases and the
  stack started once on a real VM before a customer sees it.
