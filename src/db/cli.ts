// Postgres commands for zenai4-admin (reads DATABASE_URL).
//
//   zenai4-admin db migrate                     apply pending migrations (not on Supabase: use supabase db push)
//   zenai4-admin db status                      list migrations and whether each is applied
//   zenai4-admin db init-roles                  set zenai4_app / zenai4_report passwords from ZENAI4_DB_*_PASSWORD
//   zenai4-admin db partitions                  create today's + 7 days of event partitions
//   zenai4-admin db audit-verify                verify the Postgres audit chain; exit 1 if broken
//   zenai4-admin source add <id> --kind otlp|litellm|file|syslog   prints the token once
//   zenai4-admin source rotate <id>             prints the new token once
//   zenai4-admin source disable <id>
//   zenai4-admin source list
//   zenai4-admin import litellm-spend --file <spend.json> --source <id>
//                                               queues LiteLLM spend-log history for the loader

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { parseArgs } from "node:util";
import { createPool } from "./pool.js";
import { migrate, migrationStatus } from "./migrate.js";
import { verifyAuditChain } from "./audit-chain.js";
import { addSource, disableSource, listSources, rotateSource, type SourceKind } from "../intake/sources.js";
import { DiskQueue } from "../intake/queue.js";
import { redactValue } from "../intake/redact.js";

export const PG_GROUPS = ["db", "source", "import"];

export const PG_HELP = `
Postgres (reads DATABASE_URL):
  db migrate | db status | db init-roles | db partitions | db audit-verify
  source add <id> --kind otlp|litellm|file|syslog            prints the token once
  source rotate <id> | source disable <id> | source list
  import litellm-spend --file <spend.json> --source <id>     queues history for the loader
`;

const operator = () => {
  try { return `cli:${userInfo().username}`; } catch { return "cli:unknown"; }
};

export async function runPg(argv: string[]): Promise<number> {
  const [group, sub, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    options: { kind: { type: "string" }, file: { type: "string" }, source: { type: "string" } },
    allowPositionals: true,
    strict: true,
  });
  const pool = createPool(undefined, 2);
  const out = (s: string) => process.stdout.write(s + "\n");
  try {
    switch (`${group} ${sub ?? ""}`.trim()) {
      case "db migrate": {
        const applied = await migrate(pool, undefined, out);
        out(applied.length ? `${applied.length} migration(s) applied` : "database is up to date");
        return 0;
      }
      case "db status": {
        const { supabase, items } = await migrationStatus(pool);
        out(supabase ? "Supabase database (apply with: supabase db push)" : "Postgres database (apply with: zenai4-admin db migrate)");
        for (const i of items) out(`${i.applied ? (i.changed ? "CHANGED" : "applied") : "pending"}  ${i.version}_${i.name}`);
        return items.some((i) => i.changed) ? 1 : 0;
      }
      case "db init-roles": {
        // Sets passwords for the login roles created by the first migration, from the environment.
        for (const [role, env] of [["zenai4_app", "ZENAI4_DB_APP_PASSWORD"], ["zenai4_report", "ZENAI4_DB_REPORT_PASSWORD"]]) {
          const pw = process.env[env];
          if (!pw) { out(`${role}: ${env} not set, password unchanged`); continue; }
          if (pw.length < 16) throw new Error(`${env} must be at least 16 characters`);
          const stmt = await pool.query(`SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text) AS sql`, [role, pw]);
          await pool.query(stmt.rows[0].sql);
          out(`${role}: password set`);
        }
        return 0;
      }
      case "db partitions": {
        await pool.query(`SELECT events.ensure_partitions(7)`);
        out("partitions ready for today and the next 7 days");
        return 0;
      }
      case "db audit-verify": {
        const broken = await verifyAuditChain(pool);
        if (broken === -1) { out("audit chain intact"); return 0; }
        out(`audit chain broken at seq ${broken}`);
        return 1;
      }
      case "source add": {
        const id = positionals[0];
        if (!id || !values.kind) { process.stderr.write("usage: source add <id> --kind otlp|litellm|file|syslog\n"); return 2; }
        const token = await addSource(pool, id, values.kind as SourceKind, operator());
        out(`Source ${id} added. Token (shown once, store it in the sender's secret store):\n${token}`);
        return 0;
      }
      case "source rotate": {
        if (!positionals[0]) return 2;
        out(`New token for ${positionals[0]} (the old one stops working now):\n${await rotateSource(pool, positionals[0], operator())}`);
        return 0;
      }
      case "source disable": {
        if (!positionals[0]) return 2;
        await disableSource(pool, positionals[0], operator());
        out(`Source ${positionals[0]} disabled`);
        return 0;
      }
      case "source list": {
        for (const s of await listSources(pool)) {
          out(`${s.source_id}\t${s.kind}\t${s.enabled ? "enabled" : "disabled"}\tlast seen ${s.last_seen_at?.toISOString?.() ?? "never"}`);
        }
        return 0;
      }
      case "import litellm-spend": {
        if (!values.file || !values.source) { process.stderr.write("usage: import litellm-spend --file <spend.json> --source <id>\n"); return 2; }
        const src = await pool.query(`SELECT kind, enabled FROM intake.source WHERE source_id = $1`, [values.source]);
        if (!src.rows[0]?.enabled || src.rows[0].kind !== "litellm") throw new Error(`${values.source} is not an enabled litellm source`);
        const body = readFileSync(values.file);
        const parsed = JSON.parse(body.toString("utf8"));
        const rows: unknown[] = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.data) ? parsed.data : [parsed];
        const queue = new DiskQueue(process.env.ZENAI4_QUEUE_DIR ?? "./data/queue");
        const chunk = 1000;
        for (let i = 0; i < rows.length; i += chunk) {
          const part = rows.slice(i, i + chunk);
          const raw = Buffer.from(JSON.stringify(part));
          queue.enqueue({
            batchId: createHash("sha256").update(values.source).update("\0spend\0").update(raw).digest("hex"),
            sourceId: values.source,
            signal: "litellm",
            receivedAt: new Date().toISOString(),
            bytes: raw.length,
            records: part.map((x) => ({ kind: "litellm_spend", payload: redactValue(x) })) as never,
          });
        }
        out(`${rows.length} spend rows queued in ${Math.ceil(rows.length / chunk)} batch(es); the intake loader writes them to the database`);
        return 0;
      }
      default:
        process.stderr.write(`unknown command: ${argv.join(" ")}\n${PG_HELP}`);
        return 2;
    }
  } finally {
    await pool.end();
  }
}
