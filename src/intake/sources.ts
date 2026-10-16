// Log sources and their tokens. One token per sender (a Collector, a LiteLLM
// proxy, an import job), stored only as a SHA-256 hash and printed once.
//
// Lookups are cached for five minutes, and the cache keeps answering while the
// database is unreachable, so a database outage does not turn away senders that
// were already known.

import { createHash, randomBytes } from "node:crypto";
import type pg from "pg";
import { appendAudit } from "../db/audit-chain.js";
import { inTransaction } from "../db/pool.js";

export type SourceKind = "otlp" | "litellm" | "file" | "syslog";
export const SOURCE_KINDS: SourceKind[] = ["otlp", "litellm", "file", "syslog"];
export interface Source { sourceId: string; kind: SourceKind; enabled: boolean }

export const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");
const newToken = (sourceId: string) => `zi4s_${sourceId}_${randomBytes(24).toString("base64url")}`;
const VALID_ID = /^[a-z0-9][a-z0-9-]{1,62}$/;

export async function addSource(pool: pg.Pool, sourceId: string, kind: SourceKind, actor: string): Promise<string> {
  if (!VALID_ID.test(sourceId)) throw new Error("source id: 2-63 lowercase letters, digits or hyphens");
  if (!SOURCE_KINDS.includes(kind)) throw new Error(`kind must be one of ${SOURCE_KINDS.join(", ")}`);
  const token = newToken(sourceId);
  await inTransaction(pool, async (c) => {
    await c.query(`INSERT INTO intake.source (source_id, kind, token_hash) VALUES ($1, $2, $3)`, [sourceId, kind, hashToken(token)]);
    await appendAudit(c, { actor, action: "intake.source.add", subject: sourceId, detail: { kind } });
  });
  return token;
}

export async function rotateSource(pool: pg.Pool, sourceId: string, actor: string): Promise<string> {
  const token = newToken(sourceId);
  await inTransaction(pool, async (c) => {
    const r = await c.query(`UPDATE intake.source SET token_hash = $2, enabled = true WHERE source_id = $1`, [sourceId, hashToken(token)]);
    if (!r.rowCount) throw new Error(`no source ${sourceId}`);
    await appendAudit(c, { actor, action: "intake.source.rotate", subject: sourceId });
  });
  return token;
}

export async function disableSource(pool: pg.Pool, sourceId: string, actor: string) {
  await inTransaction(pool, async (c) => {
    const r = await c.query(`UPDATE intake.source SET enabled = false WHERE source_id = $1`, [sourceId]);
    if (!r.rowCount) throw new Error(`no source ${sourceId}`);
    await appendAudit(c, { actor, action: "intake.source.disable", subject: sourceId });
  });
}

export async function listSources(pool: pg.Pool) {
  const r = await pool.query(`SELECT source_id, kind, enabled, created_at, last_seen_at FROM intake.source ORDER BY source_id`);
  return r.rows;
}

export class SourceAuth {
  private cache = new Map<string, { source: Source | null; at: number }>();
  constructor(private pool: pg.Pool, private ttlMs = 5 * 60_000, private now = () => Date.now()) {}

  /** Resolves a bearer token to an enabled source, or null. */
  async check(token: string | undefined): Promise<Source | null> {
    if (!token || !token.startsWith("zi4s_") || token.length > 200) return null;
    const h = hashToken(token);
    const hit = this.cache.get(h);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.source;
    try {
      const r = await this.pool.query(`SELECT source_id, kind, enabled FROM intake.source WHERE token_hash = $1`, [h]);
      const row = r.rows[0];
      const source = row && row.enabled ? { sourceId: row.source_id, kind: row.kind, enabled: true } : null;
      this.cache.set(h, { source, at: this.now() });
      return source;
    } catch {
      // Database unreachable: a previously known token keeps working until the database is back.
      return hit?.source ?? null;
    }
  }
}
