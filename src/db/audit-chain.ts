// Hash-chained audit log in Postgres (control.audit_event).
//
// Each row's hash covers its own fields and the previous row's hash, so editing
// or deleting any row breaks verification from that point on. The table also
// refuses UPDATE and DELETE through a trigger (migration roles_and_schemas).
//
// Appends are serialised with a transaction-scoped advisory lock, so the chain
// stays linear with several writers. Call appendAudit inside the caller's
// transaction: the audit row commits or rolls back with the work it records.
//
// detail is hashed as canonical JSON (keys sorted), because jsonb does not keep
// key order and a re-read must hash to the same value.

import { createHash } from "node:crypto";
import type pg from "pg";
import { redactDetails } from "../control/audit-log.js";

const GENESIS = "0".repeat(64);
const LOCK_KEY = 4_141_982_002;

export interface AuditInput { actor: string; action: string; subject?: string; detail?: Record<string, unknown> }
export interface AuditRow extends Required<Omit<AuditInput, "subject">> { seq: number; at: string; subject: string | null; prevHash: string; hash: string }

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

export function hashAudit(r: Omit<AuditRow, "hash">): string {
  const payload = [r.seq, r.at, r.actor, r.action, r.subject ?? "", canonicalJson(r.detail), r.prevHash].join("|");
  return createHash("sha256").update(payload).digest("hex");
}

export async function appendAudit(c: pg.PoolClient, input: AuditInput, now = new Date()): Promise<AuditRow> {
  await c.query(`SELECT pg_advisory_xact_lock($1)`, [LOCK_KEY]);
  const last = await c.query(`SELECT seq, hash FROM control.audit_event ORDER BY seq DESC LIMIT 1`);
  const row: Omit<AuditRow, "hash"> = {
    seq: last.rows.length ? Number(last.rows[0].seq) + 1 : 1,
    at: now.toISOString(),
    actor: input.actor,
    action: input.action,
    subject: input.subject ?? null,
    detail: redactDetails(input.detail),
    prevHash: last.rows.length ? last.rows[0].hash : GENESIS,
  };
  const hash = hashAudit(row);
  await c.query(
    `INSERT INTO control.audit_event (seq, at, actor, action, subject, detail, prev_hash, hash)
     OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [row.seq, row.at, row.actor, row.action, row.subject, JSON.stringify(row.detail), row.prevHash, hash],
  );
  return { ...row, hash };
}

/** Returns -1 when the whole chain verifies, else the first broken seq. */
export async function verifyAuditChain(db: pg.Pool | pg.PoolClient, batch = 5000): Promise<number> {
  let prev = GENESIS;
  let expectSeq = 1;
  let after = 0;
  for (;;) {
    const r = await db.query(
      `SELECT seq, at, actor, action, subject, detail, prev_hash, hash FROM control.audit_event WHERE seq > $1 ORDER BY seq LIMIT $2`,
      [after, batch],
    );
    for (const x of r.rows) {
      const seq = Number(x.seq);
      const row = { seq, at: (x.at as Date).toISOString(), actor: x.actor, action: x.action, subject: x.subject, detail: x.detail, prevHash: x.prev_hash };
      if (seq !== expectSeq || x.prev_hash !== prev || hashAudit(row) !== x.hash) return seq;
      prev = x.hash;
      expectSeq = seq + 1;
      after = seq;
    }
    if (r.rows.length < batch) return -1;
  }
}
