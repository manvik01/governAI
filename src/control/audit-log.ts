// Audit & user logs: one append-only, hash-chained log with two streams.
//
//   "user"  - what a HUMAN did: registered an agent, reviewed one, rotated a
//             credential, raised a budget, queried the audit log, logged in.
//   "audit" - what the SYSTEM did or saw: authentication outcomes, gateway
//             decisions, state changes, rate limiting, security alerts.
//
// Both streams share one chain, so a deletion or edit anywhere breaks
// verification from that point on (same principle as the governance
// ledger). Failures and denials are logged exactly like successes: an
// attacker's probing is evidence too.
//
// Secrets never enter the log: detail keys that look sensitive are redacted
// at write time, so even a careless caller cannot persist a token.
//
// Production notes: events are also pushed to pluggable sinks (JSON lines
// here; OpenTelemetry / OCSF / SIEM forwarders in production). The chain is
// per-database; with several gateway replicas the append must stay
// serialized (Postgres advisory lock, or a single log-writer service).

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import { nanoid } from "nanoid";

export type AuditStream = "audit" | "user";
export type ActorType = "user" | "agent" | "system" | "anonymous";
export type Outcome = "success" | "denied" | "failure";

export interface AuditEventInput {
  stream: AuditStream;
  actorType: ActorType;
  actorId: string;
  action: string; // dotted verb, e.g. "agent.review", "auth.failed", "gateway.call"
  targetType?: string;
  targetId?: string;
  outcome: Outcome;
  sourceIp?: string;
  requestId?: string;
  details?: Record<string, unknown>;
}

export interface AuditEvent extends Omit<AuditEventInput, "details"> {
  details: Record<string, unknown>;
  id: string;
  seq: number;
  ts: string;
  prevHash: string;
  hash: string;
}

export interface AuditSink {
  write(event: AuditEvent): void;
}

/** Appends each event as one JSON line - the shape a SIEM forwarder tails. */
export class JsonLinesSink implements AuditSink {
  constructor(private path: string) {}
  write(event: AuditEvent) {
    appendFileSync(this.path, JSON.stringify(event) + "\n");
  }
}

const GENESIS = "0".repeat(64);
const SENSITIVE_KEY = /secret|token|password|passwd|api[-_]?key|authorization|credential_value/i;

export function redactDetails(details: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!details) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(details)) {
    if (SENSITIVE_KEY.test(k)) out[k] = "[redacted]";
    else if (v && typeof v === "object" && !Array.isArray(v)) out[k] = redactDetails(v as Record<string, unknown>);
    else out[k] = v;
  }
  return out;
}

export class AuditLog {
  private listeners: Array<(e: AuditEvent) => void> = [];

  constructor(
    private db: Database.Database,
    private sinks: AuditSink[] = [],
    private now: () => Date = () => new Date(),
  ) {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        seq INTEGER NOT NULL UNIQUE,
        ts TEXT NOT NULL,
        stream TEXT NOT NULL,
        actor_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,
        outcome TEXT NOT NULL,
        source_ip TEXT,
        request_id TEXT,
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_stream ON audit_events(stream, seq);
      CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
    `);
  }

  onEvent(listener: (e: AuditEvent) => void) {
    this.listeners.push(listener);
  }

  append(input: AuditEventInput): AuditEvent {
    const details = redactDetails(input.details);
    const tx = this.db.transaction((): AuditEvent => {
      const last = this.db.prepare(`SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).get() as any;
      const seq = (last?.seq ?? 0) + 1;
      const prevHash = last?.hash ?? GENESIS;
      const id = nanoid();
      const ts = this.now().toISOString();
      // Human actions always land in the user stream, whatever the caller passed.
      const stream: AuditStream = input.actorType === "user" ? "user" : input.stream;
      const event: AuditEvent = { ...input, stream, details, id, seq, ts, prevHash, hash: "" };
      event.hash = hashEvent(event);
      this.db
        .prepare(
          `INSERT INTO audit_events (id, seq, ts, stream, actor_type, actor_id, action, target_type, target_id, outcome, source_ip, request_id, details, prev_hash, hash)
           VALUES (@id, @seq, @ts, @stream, @actorType, @actorId, @action, @targetType, @targetId, @outcome, @sourceIp, @requestId, @details, @prevHash, @hash)`,
        )
        .run({
          ...event,
          targetType: event.targetType ?? null,
          targetId: event.targetId ?? null,
          sourceIp: event.sourceIp ?? null,
          requestId: event.requestId ?? null,
          details: JSON.stringify(details),
        });
      return event;
    });
    const event = tx.immediate();
    for (const s of this.sinks) {
      try {
        s.write(event);
      } catch {
        /* a failing sink must never break the request path */
      }
    }
    for (const l of this.listeners) {
      try {
        l(event);
      } catch {
        /* same for listeners */
      }
    }
    return event;
  }

  query(f: { stream?: AuditStream; actorId?: string; action?: string; targetId?: string; outcome?: Outcome; limit?: number } = {}): AuditEvent[] {
    const where: string[] = [];
    const args: unknown[] = [];
    for (const [col, val] of [
      ["stream", f.stream],
      ["actor_id", f.actorId],
      ["action", f.action],
      ["target_id", f.targetId],
      ["outcome", f.outcome],
    ] as const) {
      if (val !== undefined) {
        where.push(`${col} = ?`);
        args.push(val);
      }
    }
    const sql = `SELECT * FROM audit_events ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY seq ASC LIMIT ?`;
    return (this.db.prepare(sql).all(...args, f.limit ?? 1000) as any[]).map(rowToEvent);
  }

  /** Returns -1 if the chain is intact, else the seq of the first bad row. */
  verifyChain(): number {
    const rows = this.db.prepare(`SELECT * FROM audit_events ORDER BY seq ASC`).all() as any[];
    let prev = GENESIS;
    for (const r of rows) {
      const e = rowToEvent(r);
      if (e.prevHash !== prev || hashEvent(e) !== e.hash) return e.seq;
      prev = e.hash;
    }
    return -1;
  }

  exportJsonl(f: Parameters<AuditLog["query"]>[0] = {}): string {
    return this.query(f).map((e) => JSON.stringify(e)).join("\n");
  }
}

function hashEvent(e: AuditEvent): string {
  const payload = [
    e.id, e.seq, e.ts, e.stream, e.actorType, e.actorId, e.action, e.targetType ?? "", e.targetId ?? "",
    e.outcome, e.sourceIp ?? "", e.requestId ?? "", JSON.stringify(e.details ?? {}), e.prevHash,
  ].join("|");
  return createHash("sha256").update(payload).digest("hex");
}

function rowToEvent(r: any): AuditEvent {
  return {
    id: r.id, seq: r.seq, ts: r.ts, stream: r.stream, actorType: r.actor_type, actorId: r.actor_id, action: r.action,
    targetType: r.target_type ?? undefined, targetId: r.target_id ?? undefined, outcome: r.outcome,
    sourceIp: r.source_ip ?? undefined, requestId: r.request_id ?? undefined,
    details: JSON.parse(r.details), prevHash: r.prev_hash, hash: r.hash,
  };
}
