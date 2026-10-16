// Migration runner for supabase/migrations/*.sql.
//
// Two homes for the same files:
//   - Supabase: migrations are applied with `supabase db push` (or the Supabase
//     connector) and recorded in supabase_migrations.schema_migrations. This runner
//     only REPORTS status there and refuses to apply, so the two never disagree.
//   - Any other Postgres (bundled container, customer's server, CI): this runner
//     applies pending files in version order, each in its own transaction, under an
//     advisory lock, and records version + SHA-256 in public.zenai4_migrations.
//     A recorded file whose checksum changed stops the run: migrations are forward only.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type pg from "pg";

export interface MigrationFile { version: string; name: string; path: string; sha256: string; sql: string }
export interface MigrationStatus { version: string; name: string; applied: boolean; changed: boolean }

const LOCK_KEY = 4_141_982_001; // arbitrary, constant: one migrator at a time

export function migrationsDir(): string {
  if (process.env.ZENAI4_MIGRATIONS_DIR) return resolve(process.env.ZENAI4_MIGRATIONS_DIR);
  // dist/db/migrate.js -> repo root (or /app in the container)
  const here = dirname(fileURLToPath(import.meta.url));
  for (const up of ["../..", "../../.."]) {
    const p = resolve(here, up, "supabase/migrations");
    if (existsSync(p)) return p;
  }
  throw new Error("supabase/migrations not found; set ZENAI4_MIGRATIONS_DIR");
}

export function readMigrations(dir = migrationsDir()): MigrationFile[] {
  return readdirSync(dir)
    .filter((f) => /^\d{14}_[a-z0-9_]+\.sql$/.test(f))
    .sort()
    .map((f) => {
      const sql = readFileSync(join(dir, f), "utf8");
      return {
        version: f.slice(0, 14),
        name: f.slice(15, -4),
        path: join(dir, f),
        sha256: createHash("sha256").update(sql).digest("hex"),
        sql,
      };
    });
}

async function isSupabase(db: pg.Pool | pg.PoolClient): Promise<boolean> {
  const r = await db.query(`SELECT to_regclass('supabase_migrations.schema_migrations') IS NOT NULL AS yes`);
  return r.rows[0].yes;
}

async function ensureTable(db: pg.Pool | pg.PoolClient) {
  await db.query(`CREATE TABLE IF NOT EXISTS public.zenai4_migrations (
    version text PRIMARY KEY, name text NOT NULL, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
}

export async function migrationStatus(db: pg.Pool, files = readMigrations()): Promise<{ supabase: boolean; items: MigrationStatus[] }> {
  if (await isSupabase(db)) {
    const r = await db.query(`SELECT version FROM supabase_migrations.schema_migrations`);
    const done = new Set(r.rows.map((x) => String(x.version)));
    return { supabase: true, items: files.map((f) => ({ version: f.version, name: f.name, applied: done.has(f.version), changed: false })) };
  }
  await ensureTable(db);
  const r = await db.query(`SELECT version, sha256 FROM public.zenai4_migrations`);
  const done = new Map(r.rows.map((x) => [x.version as string, x.sha256 as string]));
  return {
    supabase: false,
    items: files.map((f) => ({
      version: f.version, name: f.name, applied: done.has(f.version),
      changed: done.has(f.version) && done.get(f.version) !== f.sha256,
    })),
  };
}

/** Applies pending migrations; returns the versions applied. */
export async function migrate(pool: pg.Pool, files = readMigrations(), log: (s: string) => void = () => {}): Promise<string[]> {
  const c = await pool.connect();
  try {
    if (await isSupabase(c)) {
      const { items } = await migrationStatus(pool, files);
      const pending = items.filter((i) => !i.applied);
      if (pending.length) {
        throw new Error(`Supabase database: apply with \`supabase db push\`, not this runner. Pending: ${pending.map((p) => p.version).join(", ")}`);
      }
      return [];
    }
    await c.query(`SELECT pg_advisory_lock($1)`, [LOCK_KEY]);
    try {
      await ensureTable(c);
      const r = await c.query(`SELECT version, sha256 FROM public.zenai4_migrations`);
      const done = new Map(r.rows.map((x) => [x.version as string, x.sha256 as string]));
      for (const f of files) {
        const prior = done.get(f.version);
        if (prior && prior !== f.sha256) throw new Error(`migration ${f.version}_${f.name} changed after it was applied; add a new migration instead`);
      }
      const applied: string[] = [];
      for (const f of files) {
        if (done.has(f.version)) continue;
        await c.query("BEGIN");
        try {
          await c.query(f.sql);
          await c.query(`INSERT INTO public.zenai4_migrations (version, name, sha256) VALUES ($1, $2, $3)`, [f.version, f.name, f.sha256]);
          await c.query("COMMIT");
        } catch (err) {
          await c.query("ROLLBACK").catch(() => undefined);
          throw new Error(`migration ${f.version}_${f.name} failed: ${(err as Error).message}`);
        }
        applied.push(f.version);
        log(`applied ${f.version}_${f.name}`);
      }
      return applied;
    } finally {
      await c.query(`SELECT pg_advisory_unlock($1)`, [LOCK_KEY]).catch(() => undefined);
    }
  } finally {
    c.release();
  }
}
