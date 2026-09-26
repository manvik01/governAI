# AGENTS.md

## Cursor Cloud specific instructions

Node.js 20+ / npm project (Agent Governance Control Plane POC). Native addon `better-sqlite3` needs build tools (`build-essential`, Python) — already present in the default Cloud Agent image.

### Services

| Command | What it does |
|---|---|
| `npm run demo` | In-process refund scenario (`demo-ledger.db`) |
| `npm run mcp` | **Governed MCP gateway** (stdio): agents call `issue_refund` / `check_approval` |
| `npm run mcp:test-client` | Real MCP client/server round trip + out-of-band `mcp:approve` |
| `npm run mcp:approve` | Separate process: decide/status/verify against `LEDGER_DB` |
| `npm run agent:claude` | Claude Agent SDK client (needs `ANTHROPIC_API_KEY`) |
| `npm run server` | HTTP gateway on `:8787` |
| `npm run mcp:admin` | Optional admin MCP tools (register/policy/ledger) |
| `npm run typecheck` / `npm run build` | TypeScript check / compile |

Standard docs: `README.md`. Do not put long-running servers in the update script.

### Gotchas

- Prefer `npm run mcp` (transparent governed tools) over `mcp:admin` for agent-framework demos.
- MCP stdio: keep logs on **stderr** (`StderrApprovalChannel` / `console.error`) so stdout stays protocol-clean.
- Out-of-band approvals must use the **same** `LEDGER_DB` absolute/cwd-resolved path as the MCP server. Relative paths resolve against the process cwd.
- Registry/policy are in-memory per MCP server process; only the ledger is shared across `mcp` / `mcp:approve`.
- `zod` is v4 (required by `@anthropic-ai/claude-agent-sdk`).
- No ESLint config; use `npm run typecheck` as the static check.
