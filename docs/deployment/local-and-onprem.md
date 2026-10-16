# Run governAI locally or on-premises

governAI ships as one container. All state (agents, credentials, policies, budgets, the
audit chain) lives in a single volume mounted at `/data`. Two setups are provided:

| Setup | File | Who can reach it | TLS |
|---|---|---|---|
| Local (laptop, single server for testing) | `compose.yaml` | This machine only (`127.0.0.1:8787`) | None |
| On-premises (shared with other machines) | `deploy/onprem/compose.yaml` | Your network, through Caddy on port 443 | Yes |

Both run one gateway replica. More than one replica needs milestone M4 (Postgres and Redis).

## What you need

- Docker Engine 24+ with the Compose plugin (or Docker Desktop on a laptop).
- Outbound access to Docker Hub (`node`, and `caddy` for on-premises) and the npm registry to
  build the image. An air-gapped site builds the image elsewhere and loads it with
  `docker save` / `docker load`.
- 1 vCPU, 1 GB RAM and a few GB of disk are enough for a pilot.

## Local setup

```bash
git clone https://github.com/manvik01/governAI.git && cd governAI
cp .env.example .env
# put a key in .env:  GOVERNAI_BACKUP_KEY=$(openssl rand -base64 32)
docker compose up -d --build
docker compose ps                     # wait for "healthy"
```

Create the first administrator. This works once; the token prints once, so store it now:

```bash
docker compose exec gateway governai-admin init --admin-email you@company.com --admin-name "Your Name"
```

Add people and give them tokens:

```bash
docker compose exec gateway governai-admin user add --email ana@company.com --name "Ana" --roles security_reviewer
docker compose exec gateway governai-admin user add --email raj@company.com --name "Raj" --roles agent_owner
docker compose exec gateway governai-admin token issue --email raj@company.com
```

Roles: `admin`, `security_reviewer`, `budget_admin`, `auditor`, `agent_owner`.

Check it works:

```bash
curl -s localhost:8787/readyz                                         # {"ready":true}
curl -s localhost:8787/v1/agents -H "authorization: Bearer <token>"   # {"agents":[]}
```

From here the API flow is: set a policy (`PUT /v1/policies`, admin), register an agent
(`POST /v1/agents`, owner), review it (`POST /v1/agents/:id/review`, reviewer), then the agent
calls `POST /v1/call` with the credential it was issued. See `README.md` for the routes.

## On-premises setup (with TLS)

```bash
cd deploy/onprem
cp ../../.env.example .env
# set GOVERNAI_BACKUP_KEY and GOVERNAI_HOSTNAME (the DNS name clients will use)
docker compose up -d --build
docker compose exec gateway governai-admin init --admin-email you@company.com --admin-name "Your Name"
```

- Point `GOVERNAI_HOSTNAME` at this server in your internal DNS.
- **Certificates.** The Caddyfile uses `tls internal` (Caddy's own CA), which is fine for a
  pilot if clients trust that CA. For production, put your certificate and key in
  `deploy/onprem/certs/` and change the `tls` line to `tls /certs/cert.pem /certs/key.pem`.
- Only Caddy publishes ports. The gateway sits on an internal network with no route out, and
  trusts `X-Forwarded-For` only because every request has passed Caddy.

## Day-to-day operations

| Task | Command (prefix with `docker compose exec gateway`) |
|---|---|
| Verify the audit chain | `governai-admin audit verify` (exit 1 and the broken position if tampered) |
| Export audit log | `governai-admin audit export --out /backups/audit.jsonl` |
| Encrypted backup | `governai-admin backup --out /backups/governai-2026-10-16.bak` |
| Copy a backup off the host | `docker compose cp gateway:/backups/governai-2026-10-16.bak .` |
| Restore | `governai-admin restore --in /backups/<file>.bak --to /data/restored.db`, then set `GOVERNAI_DB_PATH=/data/restored.db` and restart |
| Remove a person | `governai-admin user deactivate --email <e>` (revokes their tokens at once) |
| Logs | `docker compose logs -f gateway` |
| SIEM feed | every audit event is appended to `/data/audit-siem.jsonl`; ship it with your log agent |
| Upgrade | `git pull && docker compose up -d --build` (the volume is kept) |

Schedule `backup` and `audit verify` daily (cron on the host or your scheduler). Keep
`GOVERNAI_BACKUP_KEY` in your secret store: a backup cannot be restored without it.

## Security notes

- Anyone who can run `docker compose exec` on the host can run `governai-admin`, which is
  administrator access. Restrict shell and Docker access on this server accordingly.
- The container runs as a non-root user with a read-only filesystem, no Linux capabilities and
  `no-new-privileges`; only `/data`, `/backups` and `/tmp` are writable.
- Never set `TRUST_PROXY=1` on the local setup: with no proxy in front, a client could forge its
  address and dodge per-address rate limits and alerts.
- Governance only holds if agents cannot reach model providers directly. Block provider domains
  from agent hosts and keep provider keys only in the gateway (milestone M1.2 and the egress guide).

## Verified so far

On 2026-10-16 the local setup was built and run end to end:

- health checks
- non-root user and read-only filesystem
- first-admin bootstrap, with a second `init` refused
- registration, review and credential issue
- an allowed call and a policy-denied call
- a spoofed agent id refused
- state kept across a restart
- clean stop in under a second
- suspension revoking the credential
- audit chain intact
- no secrets in the SIEM file
- an encrypted backup and verified restore

That run used a stand-in Node base image built locally, because Docker Hub was not reachable
from the build machine. The official `node:22-bookworm` images have not yet been used for a
build. The on-premises Caddy setup is validated with `docker compose config` but has not been
run, because the `caddy` image could not be pulled. Run it once on your server before a
customer sees it.
