// Telemetry store (phase 1.1): intake sources, batches, sessions, steps,
// policy violations and telemetry alerts, in the control plane's SQLite
// database (Postgres mirror: supabase/migrations/20261016140000_*.sql).
//
// Evidence rules, enforced by the database and not only by this class:
//   - telemetry_steps is append-only. The ONLY permitted update is the
//     retention sweep clearing the redacted payload columns (and stamping
//     payload_purged_at); every metadata column is immutable. No deletes.
//   - policy_violations and intake_batches are append-only: no update, no
//     delete. Violations are hash-chained (prev_hash/hash), the same
//     construction as the audit log and the ledger, so an edit or removal
//     breaks verification from that point on.
//   - intake_sources and telemetry_alerts cannot be deleted (revocation and
//     acknowledgement are recorded state changes, not removals).
//   - No foreign key here cascades; nothing removes evidence as a side effect.
// The class exposes no method that updates or deletes steps or violations.
//
// Steps are deduplicated by (session, step_key): step_key is "seq:<n>" when
// the producer numbers its steps (the steps API), else "span:<id>" (OTLP).
// The first write wins; a later duplicate is counted, not stored.
//
// Sessions are scoped to the principal that reported them ("source:<id>" or
// "agent:<id>"), so one source cannot write into another source's sessions.
//
// Intake-source tokens: zsrc.<sourceId>.<secret>; only SHA-256(secret) is
// stored, verification is constant-time, the plaintext is shown once.

import Database from "better-sqlite3";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { nanoid } from "nanoid";
import type { CaptureMode } from "./config.js";

const GENESIS = "0".repeat(64);
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export type StepType = "model_call" | "tool_call" | "handoff" | "approval" | "error" | "other";
export type StepStatus = "ok" | "error";
export type ErrorClass = "rate_limit" | "timeout" | "tool_failure" | "policy_denial" | "runaway_loop" | "cost_spike" | "auth" | "other";
export type AlertKind = "drift" | "bypass" | "dormant" | "telemetry_gap" | "violation_threshold" | "review_required";
export type AlertSeverity = "low" | "medium" | "high";
export type PolicyDecision = "allow" | "deny" | "hold_for_approval";

export interface IntakeSource {
  id: string;
  name: string;
  kind: string;
  captureMode: CaptureMode;
  enabled: boolean;
  createdAt: string;
  createdBy: string;
  revokedAt?: string;
  revokedBy?: string;
  revokedReason?: string;
  lastSeenAt?: string;
}

/** A step ready to store: identity resolved, payloads already redacted. */
export interface StepRecord {
  id: string;
  sessionId: string;
  stepKey: string;
  seq?: number;
  spanId?: string;
  parentSpanId?: string;
  batchId: string;
  sourceId?: string;
  agentId?: string;
  observedAgentKey: string;
  /** Registry lifecycle state of agentId when the step arrived ("expired" if past expiry). */
  agentState?: string;
  ts: string;
  receivedAt: string;
  stepType: StepType;
  operation?: string;
  toolName?: string;
  model?: string;
  provider?: string;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  latencyMs?: number;
  status: StepStatus;
  errorClass?: ErrorClass;
  captureMode: CaptureMode;
  promptRedacted?: string;
  inputRedacted?: string;
  outputRedacted?: string;
  reasoningRedacted?: string;
  payloadMeta: Record<string, unknown>;
  redactionCounts: Record<string, number>;
  payloadPurgedAt?: string;
  mappingVersion: string;
}

export interface SessionRow {
  id: string;
  scope: string;
  sessionKey: string;
  sourceId?: string;
  agentId?: string;
  observedAgentKey: string;
  firstSeen: string;
  lastSeen: string;
  stepCount: number;
  maxSeq?: number;
  gapCheckedSeq?: number;
}

export interface BatchRecord {
  id: string;
  receivedAt: string;
  endpoint: "steps" | "otlp";
  sourceId?: string;
  agentId?: string;
  byteCount: number;
  payloadSha256?: string;
  stepCount: number;
  accepted: number;
  duplicates: number;
  rejected: number;
  ignored: number;
  status: "accepted" | "partial" | "rejected";
  reasons: string[];
  auditSeq?: number;
}

export interface ViolationInput {
  agentId?: string;
  observedAgentKey?: string;
  sessionId?: string;
  stepId?: string;
  policyId: string;
  policyVersion?: number;
  rule?: string;
  decision: PolicyDecision;
  /** Already redacted text of the blocked action. */
  blockedAction?: string;
  source: "gateway" | "intake";
  details?: Record<string, unknown>;
  ts?: string;
}

export interface Violation extends Required<Pick<ViolationInput, "policyId" | "decision" | "source">> {
  seq: number;
  id: string;
  ts: string;
  agentId?: string;
  observedAgentKey?: string;
  sessionId?: string;
  stepId?: string;
  policyVersion?: number;
  rule?: string;
  blockedAction?: string;
  details: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface TelemetryAlert {
  id: string;
  kind: AlertKind;
  severity: AlertSeverity;
  agentId?: string;
  sessionId?: string;
  dedupeKey: string;
  details: Record<string, unknown>;
  status: "open" | "acknowledged";
  firstSeen: string;
  lastSeen: string;
  count: number;
  ackBy?: string;
  ackReason?: string;
  ackAt?: string;
}

/** Columns of telemetry_steps that may never change once written. */
const STEP_IMMUTABLE = [
  "id", "session_id", "step_key", "seq", "span_id", "parent_span_id", "batch_id", "source_id", "agent_id", "observed_agent_key",
  "agent_state", "ts", "received_at", "step_type", "operation", "tool_name", "model", "provider", "input_tokens", "output_tokens",
  "total_tokens", "latency_ms", "status", "error_class", "capture_mode", "payload_meta", "redaction_counts", "mapping_version",
];
const PAYLOAD_COLS = ["prompt_redacted", "input_redacted", "output_redacted", "reasoning_redacted"];

export class TelemetryStore {
  constructor(private db: Database.Database, private now: () => Date = () => new Date()) {
    const sameAsOld = STEP_IMMUTABLE.map((c) => `NEW.${c} IS OLD.${c}`).join(" AND ");
    const payloadCleared = PAYLOAD_COLS.map((c) => `NEW.${c} IS NULL`).join(" AND ");
    db.exec(`
      CREATE TABLE IF NOT EXISTS intake_sources (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('otlp','steps','litellm','file','syslog')),
        token_hash TEXT NOT NULL UNIQUE,
        capture_mode TEXT NOT NULL CHECK (capture_mode IN ('none','metadata','redacted')),
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        revoked_at TEXT,
        revoked_by TEXT,
        revoked_reason TEXT,
        last_seen_at TEXT
      );
      CREATE TRIGGER IF NOT EXISTS intake_sources_no_delete BEFORE DELETE ON intake_sources
        BEGIN SELECT RAISE(ABORT, 'intake_sources rows cannot be deleted; revoke instead'); END;

      CREATE TABLE IF NOT EXISTS intake_batches (
        id TEXT PRIMARY KEY,
        received_at TEXT NOT NULL,
        endpoint TEXT NOT NULL CHECK (endpoint IN ('steps','otlp')),
        source_id TEXT,
        agent_id TEXT,
        byte_count INTEGER NOT NULL,
        payload_sha256 TEXT,
        step_count INTEGER NOT NULL,
        accepted INTEGER NOT NULL,
        duplicates INTEGER NOT NULL,
        rejected INTEGER NOT NULL,
        ignored INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('accepted','partial','rejected')),
        reasons TEXT NOT NULL,
        audit_seq INTEGER,
        CHECK (source_id IS NOT NULL OR agent_id IS NOT NULL)
      );
      CREATE INDEX IF NOT EXISTS idx_intake_batches_received ON intake_batches(received_at);
      CREATE TRIGGER IF NOT EXISTS intake_batches_no_update BEFORE UPDATE ON intake_batches
        BEGIN SELECT RAISE(ABORT, 'intake_batches is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS intake_batches_no_delete BEFORE DELETE ON intake_batches
        BEGIN SELECT RAISE(ABORT, 'intake_batches is append-only'); END;

      CREATE TABLE IF NOT EXISTS telemetry_sessions (
        id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        session_key TEXT NOT NULL,
        source_id TEXT,
        agent_id TEXT,
        observed_agent_key TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        step_count INTEGER NOT NULL DEFAULT 0,
        max_seq INTEGER,
        gap_checked_seq INTEGER,
        UNIQUE (scope, session_key)
      );
      CREATE INDEX IF NOT EXISTS idx_tsess_agent ON telemetry_sessions(agent_id, last_seen);
      CREATE TRIGGER IF NOT EXISTS telemetry_sessions_no_delete BEFORE DELETE ON telemetry_sessions
        BEGIN SELECT RAISE(ABORT, 'telemetry_sessions rows cannot be deleted'); END;

      CREATE TABLE IF NOT EXISTS telemetry_steps (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        step_key TEXT NOT NULL,
        seq INTEGER,
        span_id TEXT,
        parent_span_id TEXT,
        batch_id TEXT NOT NULL,
        source_id TEXT,
        agent_id TEXT,
        observed_agent_key TEXT NOT NULL,
        agent_state TEXT,
        ts TEXT NOT NULL,
        received_at TEXT NOT NULL,
        step_type TEXT NOT NULL CHECK (step_type IN ('model_call','tool_call','handoff','approval','error','other')),
        operation TEXT,
        tool_name TEXT,
        model TEXT,
        provider TEXT,
        input_tokens INTEGER,
        output_tokens INTEGER,
        total_tokens INTEGER,
        latency_ms REAL,
        status TEXT NOT NULL CHECK (status IN ('ok','error')),
        error_class TEXT CHECK (error_class IN ('rate_limit','timeout','tool_failure','policy_denial','runaway_loop','cost_spike','auth','other')),
        capture_mode TEXT NOT NULL CHECK (capture_mode IN ('none','metadata','redacted')),
        prompt_redacted TEXT,
        input_redacted TEXT,
        output_redacted TEXT,
        reasoning_redacted TEXT,
        payload_meta TEXT NOT NULL,
        redaction_counts TEXT NOT NULL,
        payload_purged_at TEXT,
        mapping_version TEXT NOT NULL,
        UNIQUE (session_id, step_key)
      );
      CREATE INDEX IF NOT EXISTS idx_tsteps_agent ON telemetry_steps(agent_id, ts);
      CREATE INDEX IF NOT EXISTS idx_tsteps_received ON telemetry_steps(received_at);
      CREATE TRIGGER IF NOT EXISTS telemetry_steps_no_delete BEFORE DELETE ON telemetry_steps
        BEGIN SELECT RAISE(ABORT, 'telemetry_steps is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_steps_retention_only BEFORE UPDATE ON telemetry_steps
        WHEN NOT (${sameAsOld} AND ${payloadCleared} AND NEW.payload_purged_at IS NOT NULL)
        BEGIN SELECT RAISE(ABORT, 'telemetry_steps is append-only (only the retention sweep may clear payloads)'); END;

      CREATE TABLE IF NOT EXISTS policy_violations (
        id TEXT PRIMARY KEY,
        seq INTEGER NOT NULL UNIQUE,
        ts TEXT NOT NULL,
        agent_id TEXT,
        observed_agent_key TEXT,
        session_id TEXT,
        step_id TEXT,
        policy_id TEXT NOT NULL,
        policy_version INTEGER,
        rule TEXT,
        decision TEXT NOT NULL CHECK (decision IN ('allow','deny','hold_for_approval')),
        blocked_action TEXT,
        source TEXT NOT NULL CHECK (source IN ('gateway','intake')),
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL UNIQUE
      );
      CREATE INDEX IF NOT EXISTS idx_violations_agent ON policy_violations(agent_id, ts);
      CREATE TRIGGER IF NOT EXISTS policy_violations_no_update BEFORE UPDATE ON policy_violations
        BEGIN SELECT RAISE(ABORT, 'policy_violations is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS policy_violations_no_delete BEFORE DELETE ON policy_violations
        BEGIN SELECT RAISE(ABORT, 'policy_violations is append-only'); END;

      CREATE TABLE IF NOT EXISTS telemetry_alerts (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('drift','bypass','dormant','telemetry_gap','violation_threshold','review_required')),
        severity TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
        agent_id TEXT,
        session_id TEXT,
        dedupe_key TEXT NOT NULL UNIQUE,
        details TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open','acknowledged')),
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        count INTEGER NOT NULL,
        ack_by TEXT,
        ack_reason TEXT,
        ack_at TEXT,
        CHECK (status = 'open' OR (ack_by IS NOT NULL AND ack_reason IS NOT NULL AND ack_at IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS idx_talerts_status ON telemetry_alerts(status, last_seen);
      CREATE TRIGGER IF NOT EXISTS telemetry_alerts_no_delete BEFORE DELETE ON telemetry_alerts
        BEGIN SELECT RAISE(ABORT, 'telemetry_alerts rows cannot be deleted; acknowledge instead'); END;

      CREATE TABLE IF NOT EXISTS telemetry_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    `);
  }

  private iso() {
    return this.now().toISOString();
  }

  /** Runs fn in one write transaction (nested calls become savepoints). */
  tx<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }

  // ------------------------------------------------------------ sources

  createSource(name: string, kind: string, captureMode: CaptureMode, createdBy: string): { source: IntakeSource; token: string } {
    const id = nanoid(12).replace(/[-_]/g, "x");
    const secret = randomBytes(32).toString("base64url");
    this.db.prepare(`INSERT INTO intake_sources (id, name, kind, token_hash, capture_mode, enabled, created_at, created_by) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`)
      .run(id, name, kind, sha(secret), captureMode, this.iso(), createdBy);
    return { source: this.getSource(id)!, token: `zsrc.${id}.${secret}` };
  }

  revokeSource(id: string, by: string, reason: string): IntakeSource | undefined {
    this.db.prepare(`UPDATE intake_sources SET enabled = 0, revoked_at = ?, revoked_by = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(this.iso(), by, reason, id);
    return this.getSource(id);
  }

  getSource(id: string): IntakeSource | undefined {
    const r = this.db.prepare(`SELECT * FROM intake_sources WHERE id = ?`).get(id) as any;
    return r ? sourceRow(r) : undefined;
  }

  listSources(): IntakeSource[] {
    return (this.db.prepare(`SELECT * FROM intake_sources ORDER BY created_at`).all() as any[]).map(sourceRow);
  }

  /** Constant-time check of a zsrc token. Reasons are for the audit log only. */
  verifySourceToken(token: string): { ok: true; source: IntakeSource } | { ok: false; reason: "malformed" | "unknown_source" | "bad_secret" | "revoked"; sourceId?: string } {
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== "zsrc" || !parts[1] || !parts[2]) return { ok: false, reason: "malformed" };
    const row = this.db.prepare(`SELECT * FROM intake_sources WHERE id = ?`).get(parts[1]) as any;
    if (!row) return { ok: false, reason: "unknown_source" };
    const given = Buffer.from(sha(parts[2]), "hex");
    const stored = Buffer.from(row.token_hash, "hex");
    if (given.length !== stored.length || !timingSafeEqual(given, stored)) return { ok: false, reason: "bad_secret", sourceId: row.id };
    if (!row.enabled || row.revoked_at) return { ok: false, reason: "revoked", sourceId: row.id };
    this.db.prepare(`UPDATE intake_sources SET last_seen_at = ? WHERE id = ?`).run(this.iso(), row.id);
    return { ok: true, source: sourceRow(row) };
  }

  /** For tests: proves plaintext source tokens are never stored. */
  sourceTokenHashes(): string[] {
    return (this.db.prepare(`SELECT token_hash FROM intake_sources`).all() as any[]).map((r) => r.token_hash);
  }

  // ------------------------------------------------------------ sessions and steps

  sessionIdFor(scope: string, sessionKey: string) {
    return sha(`${scope}\u0000${sessionKey}`).slice(0, 32);
  }

  /** Inserts a step unless (session, step_key) exists. Creates/updates the session. */
  insertStep(scope: string, sessionKey: string, s: StepRecord): "inserted" | "duplicate" {
    return this.tx(() => {
      const existing = this.db.prepare(`SELECT 1 FROM telemetry_steps WHERE session_id = ? AND step_key = ?`).get(s.sessionId, s.stepKey);
      if (existing) return "duplicate";
      this.db.prepare(`INSERT INTO telemetry_sessions (id, scope, session_key, source_id, agent_id, observed_agent_key, first_seen, last_seen, step_count, max_seq)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
          ON CONFLICT(id) DO NOTHING`)
        .run(s.sessionId, scope, sessionKey, s.sourceId ?? null, s.agentId ?? null, s.observedAgentKey, s.ts, s.ts);
      this.db.prepare(`INSERT INTO telemetry_steps (id, session_id, step_key, seq, span_id, parent_span_id, batch_id, source_id, agent_id, observed_agent_key,
          agent_state, ts, received_at, step_type, operation, tool_name, model, provider, input_tokens, output_tokens, total_tokens, latency_ms, status,
          error_class, capture_mode, prompt_redacted, input_redacted, output_redacted, reasoning_redacted, payload_meta, redaction_counts, mapping_version)
          VALUES (@id, @sessionId, @stepKey, @seq, @spanId, @parentSpanId, @batchId, @sourceId, @agentId, @observedAgentKey,
          @agentState, @ts, @receivedAt, @stepType, @operation, @toolName, @model, @provider, @inputTokens, @outputTokens, @totalTokens, @latencyMs, @status,
          @errorClass, @captureMode, @promptRedacted, @inputRedacted, @outputRedacted, @reasoningRedacted, @payloadMeta, @redactionCounts, @mappingVersion)`)
        .run({
          ...nullify(s),
          payloadMeta: JSON.stringify(s.payloadMeta),
          redactionCounts: JSON.stringify(s.redactionCounts),
        });
      this.db.prepare(`UPDATE telemetry_sessions SET step_count = step_count + 1,
          first_seen = min(first_seen, ?), last_seen = max(last_seen, ?),
          max_seq = CASE WHEN ? IS NULL THEN max_seq ELSE max(coalesce(max_seq, -1), ?) END,
          agent_id = coalesce(agent_id, ?)
          WHERE id = ?`)
        .run(s.ts, s.ts, s.seq ?? null, s.seq ?? null, s.agentId ?? null, s.sessionId);
      return "inserted" as const;
    });
  }

  getStep(id: string): StepRecord | undefined {
    const r = this.db.prepare(`SELECT * FROM telemetry_steps WHERE id = ?`).get(id) as any;
    return r ? stepRow(r) : undefined;
  }

  /** Steps written after rowid `after` (reconciliation cursor). */
  stepsAfter(after: number, limit = 10_000): Array<StepRecord & { rowid: number }> {
    return (this.db.prepare(`SELECT rowid AS rowid, * FROM telemetry_steps WHERE rowid > ? ORDER BY rowid LIMIT ?`).all(after, limit) as any[])
      .map((r) => ({ ...stepRow(r), rowid: r.rowid }));
  }

  stepsForSession(sessionId: string): StepRecord[] {
    return (this.db.prepare(`SELECT * FROM telemetry_steps WHERE session_id = ? ORDER BY coalesce(seq, 0), ts`).all(sessionId) as any[]).map(stepRow);
  }

  stepsForAgentSince(agentId: string, sinceIso: string): StepRecord[] {
    return (this.db.prepare(`SELECT * FROM telemetry_steps WHERE agent_id = ? AND ts >= ? ORDER BY ts`).all(agentId, sinceIso) as any[]).map(stepRow);
  }

  getSession(id: string): SessionRow | undefined {
    const r = this.db.prepare(`SELECT * FROM telemetry_sessions WHERE id = ?`).get(id) as any;
    return r ? sessionRow(r) : undefined;
  }

  /** Sessions with numbered steps not yet checked for gaps, quiet since `quietBefore`. */
  sessionsToGapCheck(quietBefore: string): SessionRow[] {
    return (this.db.prepare(`SELECT * FROM telemetry_sessions WHERE max_seq IS NOT NULL AND (gap_checked_seq IS NULL OR gap_checked_seq < max_seq) AND last_seen <= ?`)
      .all(quietBefore) as any[]).map(sessionRow);
  }

  seqsForSession(sessionId: string): number[] {
    return (this.db.prepare(`SELECT seq FROM telemetry_steps WHERE session_id = ? AND seq IS NOT NULL ORDER BY seq`).all(sessionId) as any[]).map((r) => r.seq);
  }

  markGapChecked(sessionId: string, seq: number) {
    this.db.prepare(`UPDATE telemetry_sessions SET gap_checked_seq = ? WHERE id = ?`).run(seq, sessionId);
  }

  /** Last time each agent was seen in telemetry. */
  lastSeenByAgent(): Map<string, string> {
    const rows = this.db.prepare(`SELECT agent_id, max(last_seen) AS last FROM telemetry_sessions WHERE agent_id IS NOT NULL GROUP BY agent_id`).all() as any[];
    return new Map(rows.map((r) => [r.agent_id, r.last]));
  }

  /** Retention: clears redacted payloads of steps received before `cutoff`.
   * Metadata stays. Returns the number of steps purged. */
  purgePayloadsBefore(cutoffIso: string): number {
    return this.db.prepare(`UPDATE telemetry_steps SET prompt_redacted = NULL, input_redacted = NULL, output_redacted = NULL, reasoning_redacted = NULL,
        payload_purged_at = ? WHERE received_at < ? AND payload_purged_at IS NULL
        AND (prompt_redacted IS NOT NULL OR input_redacted IS NOT NULL OR output_redacted IS NOT NULL OR reasoning_redacted IS NOT NULL)`)
      .run(this.iso(), cutoffIso).changes;
  }

  // ------------------------------------------------------------ batches

  insertBatch(b: BatchRecord) {
    this.db.prepare(`INSERT INTO intake_batches (id, received_at, endpoint, source_id, agent_id, byte_count, payload_sha256, step_count, accepted, duplicates, rejected, ignored, status, reasons, audit_seq)
        VALUES (@id, @receivedAt, @endpoint, @sourceId, @agentId, @byteCount, @payloadSha256, @stepCount, @accepted, @duplicates, @rejected, @ignored, @status, @reasons, @auditSeq)`)
      .run({ ...nullify(b), reasons: JSON.stringify(b.reasons) });
  }

  getBatch(id: string): BatchRecord | undefined {
    const r = this.db.prepare(`SELECT * FROM intake_batches WHERE id = ?`).get(id) as any;
    return r ? batchRow(r) : undefined;
  }

  listBatches(limit = 100): BatchRecord[] {
    return (this.db.prepare(`SELECT * FROM intake_batches ORDER BY received_at DESC, rowid DESC LIMIT ?`).all(limit) as any[]).map(batchRow);
  }

  // ------------------------------------------------------------ violations (hash-chained)

  appendViolation(v: ViolationInput): Violation {
    return this.tx(() => {
      const last = this.db.prepare(`SELECT seq, hash FROM policy_violations ORDER BY seq DESC LIMIT 1`).get() as any;
      const row: Violation = {
        seq: (last?.seq ?? 0) + 1,
        id: nanoid(),
        ts: v.ts ?? this.iso(),
        agentId: v.agentId,
        observedAgentKey: v.observedAgentKey,
        sessionId: v.sessionId,
        stepId: v.stepId,
        policyId: v.policyId,
        policyVersion: v.policyVersion,
        rule: v.rule,
        decision: v.decision,
        blockedAction: v.blockedAction,
        source: v.source,
        details: v.details ?? {},
        prevHash: last?.hash ?? GENESIS,
        hash: "",
      };
      row.hash = hashViolation(row);
      this.db.prepare(`INSERT INTO policy_violations (id, seq, ts, agent_id, observed_agent_key, session_id, step_id, policy_id, policy_version, rule, decision, blocked_action, source, details, prev_hash, hash)
          VALUES (@id, @seq, @ts, @agentId, @observedAgentKey, @sessionId, @stepId, @policyId, @policyVersion, @rule, @decision, @blockedAction, @source, @details, @prevHash, @hash)`)
        .run({ ...nullify(row), details: JSON.stringify(row.details) });
      return row;
    });
  }

  listViolations(f: { agentId?: string; sinceIso?: string; limit?: number } = {}): Violation[] {
    const where: string[] = [];
    const args: unknown[] = [];
    if (f.agentId) { where.push("agent_id = ?"); args.push(f.agentId); }
    if (f.sinceIso) { where.push("ts >= ?"); args.push(f.sinceIso); }
    return (this.db.prepare(`SELECT * FROM policy_violations ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY seq ASC LIMIT ?`)
      .all(...args, f.limit ?? 10_000) as any[]).map(violationRow);
  }

  violationCountsSince(sinceIso: string): Map<string, number> {
    const rows = this.db.prepare(`SELECT agent_id, count(*) AS n FROM policy_violations WHERE agent_id IS NOT NULL AND ts >= ? AND decision = 'deny' GROUP BY agent_id`).all(sinceIso) as any[];
    return new Map(rows.map((r) => [r.agent_id, r.n]));
  }

  /** -1 if the violation chain is intact, else the seq of the first bad row. */
  verifyViolationChain(): number {
    let prev = GENESIS;
    let expectedSeq = 1;
    for (const r of this.db.prepare(`SELECT * FROM policy_violations ORDER BY seq ASC`).all() as any[]) {
      const v = violationRow(r);
      if (v.seq !== expectedSeq || v.prevHash !== prev || hashViolation(v) !== v.hash) return v.seq;
      prev = v.hash;
      expectedSeq++;
    }
    return -1;
  }

  // ------------------------------------------------------------ alerts

  /** Opens an alert, or bumps count/last_seen of the open or acknowledged
   * alert with the same dedupe key. Returns whether it is new. */
  raiseAlert(a: { kind: AlertKind; severity: AlertSeverity; agentId?: string; sessionId?: string; dedupeKey: string; details: Record<string, unknown> }): { alert: TelemetryAlert; created: boolean } {
    return this.tx(() => {
      const now = this.iso();
      const existing = this.db.prepare(`SELECT id FROM telemetry_alerts WHERE dedupe_key = ?`).get(a.dedupeKey) as any;
      if (existing) {
        this.db.prepare(`UPDATE telemetry_alerts SET count = count + 1, last_seen = ?, details = ? WHERE id = ?`).run(now, JSON.stringify(a.details), existing.id);
        return { alert: this.getAlert(existing.id)!, created: false };
      }
      const id = nanoid(12);
      this.db.prepare(`INSERT INTO telemetry_alerts (id, kind, severity, agent_id, session_id, dedupe_key, details, status, first_seen, last_seen, count)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 1)`)
        .run(id, a.kind, a.severity, a.agentId ?? null, a.sessionId ?? null, a.dedupeKey, JSON.stringify(a.details), now, now);
      return { alert: this.getAlert(id)!, created: true };
    });
  }

  ackAlert(id: string, by: string, reason: string): TelemetryAlert | undefined {
    this.db.prepare(`UPDATE telemetry_alerts SET status = 'acknowledged', ack_by = ?, ack_reason = ?, ack_at = ? WHERE id = ? AND status = 'open'`)
      .run(by, reason, this.iso(), id);
    return this.getAlert(id);
  }

  getAlert(id: string): TelemetryAlert | undefined {
    const r = this.db.prepare(`SELECT * FROM telemetry_alerts WHERE id = ?`).get(id) as any;
    return r ? alertRow(r) : undefined;
  }

  listAlerts(f: { status?: "open" | "acknowledged"; kind?: AlertKind; agentId?: string; limit?: number } = {}): TelemetryAlert[] {
    const where: string[] = [];
    const args: unknown[] = [];
    if (f.status) { where.push("status = ?"); args.push(f.status); }
    if (f.kind) { where.push("kind = ?"); args.push(f.kind); }
    if (f.agentId) { where.push("agent_id = ?"); args.push(f.agentId); }
    return (this.db.prepare(`SELECT * FROM telemetry_alerts ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY last_seen DESC LIMIT ?`)
      .all(...args, Math.min(f.limit ?? 500, 5000)) as any[]).map(alertRow);
  }

  // ------------------------------------------------------------ state

  getState(key: string): string | undefined {
    return (this.db.prepare(`SELECT value FROM telemetry_state WHERE key = ?`).get(key) as any)?.value;
  }

  setState(key: string, value: string) {
    this.db.prepare(`INSERT INTO telemetry_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(key, value);
  }
}

function hashViolation(v: Violation): string {
  return sha([
    v.id, v.seq, v.ts, v.agentId ?? "", v.observedAgentKey ?? "", v.sessionId ?? "", v.stepId ?? "", v.policyId, v.policyVersion ?? "",
    v.rule ?? "", v.decision, v.blockedAction ?? "", v.source, JSON.stringify(v.details ?? {}), v.prevHash,
  ].join("|"));
}

/** Every optional named parameter a statement may reference; absent ones bind NULL. */
const OPTIONAL_PARAMS = [
  "seq", "spanId", "parentSpanId", "sourceId", "agentId", "agentState", "operation", "toolName", "model", "provider", "inputTokens",
  "outputTokens", "totalTokens", "latencyMs", "errorClass", "promptRedacted", "inputRedacted", "outputRedacted", "reasoningRedacted",
  "payloadSha256", "auditSeq", "observedAgentKey", "sessionId", "stepId", "policyVersion", "rule", "blockedAction",
];

/** undefined -> null for SQLite named parameters (better-sqlite3 rejects missing ones). */
function nullify<T extends object>(o: T): Record<string, unknown> {
  const out: Record<string, unknown> = Object.fromEntries(OPTIONAL_PARAMS.map((k) => [k, null]));
  for (const [k, v] of Object.entries(o)) out[k] = v === undefined ? null : v;
  return out;
}

const u = <T>(v: T | null): T | undefined => (v === null ? undefined : v);

function sourceRow(r: any): IntakeSource {
  return {
    id: r.id, name: r.name, kind: r.kind, captureMode: r.capture_mode, enabled: r.enabled === 1 && !r.revoked_at, createdAt: r.created_at,
    createdBy: r.created_by, revokedAt: u(r.revoked_at), revokedBy: u(r.revoked_by), revokedReason: u(r.revoked_reason), lastSeenAt: u(r.last_seen_at),
  };
}

function stepRow(r: any): StepRecord {
  return {
    id: r.id, sessionId: r.session_id, stepKey: r.step_key, seq: u(r.seq), spanId: u(r.span_id), parentSpanId: u(r.parent_span_id), batchId: r.batch_id,
    sourceId: u(r.source_id), agentId: u(r.agent_id), observedAgentKey: r.observed_agent_key, agentState: u(r.agent_state), ts: r.ts, receivedAt: r.received_at,
    stepType: r.step_type, operation: u(r.operation), toolName: u(r.tool_name), model: u(r.model), provider: u(r.provider), inputTokens: u(r.input_tokens),
    outputTokens: u(r.output_tokens), totalTokens: u(r.total_tokens), latencyMs: u(r.latency_ms), status: r.status, errorClass: u(r.error_class),
    captureMode: r.capture_mode, promptRedacted: u(r.prompt_redacted), inputRedacted: u(r.input_redacted), outputRedacted: u(r.output_redacted),
    reasoningRedacted: u(r.reasoning_redacted), payloadMeta: JSON.parse(r.payload_meta), redactionCounts: JSON.parse(r.redaction_counts),
    payloadPurgedAt: u(r.payload_purged_at), mappingVersion: r.mapping_version,
  };
}

function sessionRow(r: any): SessionRow {
  return {
    id: r.id, scope: r.scope, sessionKey: r.session_key, sourceId: u(r.source_id), agentId: u(r.agent_id), observedAgentKey: r.observed_agent_key,
    firstSeen: r.first_seen, lastSeen: r.last_seen, stepCount: r.step_count, maxSeq: u(r.max_seq), gapCheckedSeq: u(r.gap_checked_seq),
  };
}

function batchRow(r: any): BatchRecord {
  return {
    id: r.id, receivedAt: r.received_at, endpoint: r.endpoint, sourceId: u(r.source_id), agentId: u(r.agent_id), byteCount: r.byte_count,
    payloadSha256: u(r.payload_sha256), stepCount: r.step_count, accepted: r.accepted, duplicates: r.duplicates, rejected: r.rejected, ignored: r.ignored,
    status: r.status, reasons: JSON.parse(r.reasons), auditSeq: u(r.audit_seq),
  };
}

function violationRow(r: any): Violation {
  return {
    seq: r.seq, id: r.id, ts: r.ts, agentId: u(r.agent_id), observedAgentKey: u(r.observed_agent_key), sessionId: u(r.session_id), stepId: u(r.step_id),
    policyId: r.policy_id, policyVersion: u(r.policy_version), rule: u(r.rule), decision: r.decision, blockedAction: u(r.blocked_action), source: r.source,
    details: JSON.parse(r.details), prevHash: r.prev_hash, hash: r.hash,
  };
}

function alertRow(r: any): TelemetryAlert {
  return {
    id: r.id, kind: r.kind, severity: r.severity, agentId: u(r.agent_id), sessionId: u(r.session_id), dedupeKey: r.dedupe_key, details: JSON.parse(r.details),
    status: r.status, firstSeen: r.first_seen, lastSeen: r.last_seen, count: r.count, ackBy: u(r.ack_by), ackReason: u(r.ack_reason), ackAt: u(r.ack_at),
  };
}
