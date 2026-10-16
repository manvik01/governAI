// One Postgres pool per process. DATABASE_URL points at the bundled container,
// the customer's own Postgres, or Supabase in development.
//
// TLS: on by default for any host that is not local. ZENAI4_DB_SSL=disable turns
// it off (bundled container on the same Docker network); =no-verify keeps TLS but
// skips certificate checks (only for a provider whose CA you have not installed).

import pg from "pg";

let shared: pg.Pool | undefined;

export function databaseUrl(): string {
  const url = process.env.DATABASE_URL ?? process.env.ZENAI4_DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not set");
  return url;
}

function sslFor(url: string): pg.PoolConfig["ssl"] {
  const mode = process.env.ZENAI4_DB_SSL;
  if (mode === "disable") return false;
  if (mode === "no-verify") return { rejectUnauthorized: false };
  let host = "";
  try { host = new URL(url).hostname; } catch { /* socket path or key=value string */ }
  const local = !host || host === "localhost" || host === "127.0.0.1" || host === "postgres" || host.startsWith("/");
  return local ? false : { rejectUnauthorized: true };
}

export function createPool(url = databaseUrl(), max = Number(process.env.ZENAI4_DB_POOL ?? 10)): pg.Pool {
  const pool = new pg.Pool({
    connectionString: url,
    ssl: sslFor(url),
    max,
    statement_timeout: 30_000,
    idleTimeoutMillis: 30_000,
    application_name: "zenai4",
  });
  // An idle client losing its connection must not crash the process; the pool replaces it.
  pool.on("error", (err) => process.stderr.write(`postgres pool: ${err.message}\n`));
  return pool;
}

export function getPool(): pg.Pool {
  shared ??= createPool();
  return shared;
}

export async function closePool() {
  await shared?.end();
  shared = undefined;
}

/** Run fn inside one transaction; rolls back on any error. */
export async function inTransaction<T>(pool: pg.Pool, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const out = await fn(c);
    await c.query("COMMIT");
    return out;
  } catch (err) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
}
