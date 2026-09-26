# AGENTS.md

## Cursor Cloud specific instructions

Node.js 20+ / npm project (Agent Governance Control Plane POC). Native addon `better-sqlite3` needs build tools (`build-essential`, Python) — already present in the default Cloud Agent image.

### Services

| Command | What it does |
|---|---|
| `npm run demo` | In-process end-to-end refund scenario (writes `demo-ledger.db`) |
| `npm run demo:mcp` | Same scenario over MCP stdio (spawns `dist/gateway/mcp.js`, writes `mcp-demo-ledger.db`) |
| `npm run server` | HTTP gateway on `:8787` (writes `server-ledger.db`) |
| `npm run mcp` | MCP stdio gateway for agent frameworks (writes `mcp-ledger.db` or `LEDGER_DB`) |
| `npm run typecheck` / `npm run build` | TypeScript check / compile to `dist/` |

Standard setup and route docs live in `README.md`. Do not put `npm run server` / `npm run mcp` in the update script — start them per session when needed.

### Gotchas

- Each demo run expects a fresh SQLite file; demos delete their own db path on start. Do not point concurrent servers at the same `LEDGER_DB`.
- MCP uses **stdio** — keep application logs on stderr (`console.error`) so they do not corrupt the protocol on stdout.
- Registry/policy state is in-memory; only the ledger persists across process restarts. Restarting `server` or `mcp` clears registered agents/policies unless you re-seed them.
- There is no ESLint config in this repo; use `npm run typecheck` as the static check.
