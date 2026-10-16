# Capture: sending agent logs to ZenAi4 (phase 1)

ZenAi4 receives agent telemetry, strips content and personal data, queues it on
disk and loads it into Postgres. Agents change only where their telemetry goes.

```
agents ── OTLP ──▶ Collector :4317/:4318 ──▶ intake :8788 ──▶ disk queue ──▶ loader ──▶ Postgres
LiteLLM ── callback ─────────────────────────▶ intake :8788    (events.raw_span, intake.batch,
custom JSON logs ── file / syslog ─▶ Collector                    control.audit_event)
```

## 1. Start the stack

```sh
cp .env.example .env     # fill in the passwords (openssl rand -base64 24) and ZENAI4_BACKUP_KEY
docker compose up -d --build
docker compose exec intake zenai4-admin source add collector --kind otlp
# copy the printed token into .env as ZENAI4_COLLECTOR_TOKEN, then:
docker compose up -d collector
```

On a fresh Ubuntu VM, `deploy/cloud-init/user-data.yaml` does all of this.

Using Supabase or your own Postgres instead of the bundled container: see the
database section of `.env.example` and `supabase/README.md`.

## 2. Point each source at ZenAi4

| Source | What to set |
| --- | --- |
| Agent framework with OpenTelemetry (Pydantic AI, Vercel AI SDK, Strands, OpenLLMetry, OpenInference) | `OTEL_EXPORTER_OTLP_ENDPOINT=http://<vm>:4318` (Collector). Direct to intake also works: `http://<vm>:8788` with `OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <token>` |
| LiteLLM proxy | Copy `deploy/litellm/zenai4_callback.py` next to the proxy config, add `callbacks: zenai4_callback.proxy_handler_instance` under `litellm_settings`, set `ZENAI4_INTAKE_URL` and `ZENAI4_LITELLM_TOKEN` (from `zenai4-admin source add litellm --kind litellm`) |
| LiteLLM history | Export spend logs as JSON, then `zenai4-admin import litellm-spend --file spend.json --source litellm` |
| JSON log files | Set `ZENAI4_AGENT_LOG_DIR` in `.env`; the Collector tails `*.log` and `*.jsonl` there |
| Syslog | UDP 5514, RFC 5424 |

Working examples of the first three are in `fixtures/agents/`.

## 3. Check it is working

```sh
curl -s localhost:8788/readyz            # database true, queueDepth near 0
curl -s localhost:8788/metrics           # accepted, loaded, duplicates, lag
docker compose exec intake zenai4-admin source list      # last seen per source
docker compose exec intake zenai4-admin db audit-verify  # every batch is in the audit chain
```

## What is kept and what is not

- Kept: span and log structure, timings, status, model, tool and token attributes,
  service and agent names, LiteLLM key alias, cost and token counts.
- Dropped: prompts, completions, message histories, tool arguments and results
  (OpenTelemetry GenAI, OpenInference, OpenLLMetry and Pydantic AI keys, plus any
  value shaped like a chat transcript).
- Masked: API keys and tokens, JWTs, emails, Singapore NRIC numbers, card numbers
  (Luhn-checked), international phone numbers.
- Pseudonymised: user ids (`enduser.id`, LiteLLM user ids) become `user:<hash>`,
  keyed by `ZENAI4_PSEUDONYM_SALT`, so reports count users without storing them.
- Raw records are kept 7 days (for re-deciphering after a mapping fix); canonical
  events from phase 2 are kept 30 days.

## Durability

A batch is answered 200 only after it is fsynced to the disk queue. The loader
writes each batch, its audit event and its records in one transaction and deletes
the file only after commit; the batch id is the payload hash, so replays after a
crash never duplicate. If the database is down, batches wait on disk and the
intake keeps accepting from known sources.

Measured on 16 Oct 2026 (2 vCPU, 7 GB, Postgres on the same machine): 300,000
spans sent while the intake was killed with `kill -9` three times mid-burst,
300,000 rows in the database, no duplicates, audit chain intact. End-to-end
rate about 6,200 spans a second; about 1 KB of disk per raw record with indexes.
Not yet measured: the rate against a remote database, and a full VM reboot with
the Collector in front (phase 1 step 10 on a real VM).
