// Budget Store: hierarchical budgets, atomic reservations, the consumption
// ledger, and the idempotency guards that make double-charging impossible.
//
// Concurrency model: every state change that touches more than one row runs
// inside `db.transaction(...).immediate()`, which takes SQLite's write lock
// up front. Two reservers — in the same process or in different OS processes
// sharing the DB file — are therefore serialized: the second one sees the
// first one's reservation when it checks remaining budget. That is what
// "reserve budget atomically" and "parallel child agents cannot
// over-allocate" mean here. (At production scale the same contract is met
// with Postgres row locks / SELECT ... FOR UPDATE on the budget rows.)
//
// Accounting model, per budget scope:
//     limit  >=  spent (reconciled)  +  reserved (in flight or unresolved)
// A request is admitted only if EVERY configured scope in its chain
// (org -> project -> agent -> root task) has room for the estimate.
//
// Units: integer micro-USD. Nothing here uses floating point.

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type { PricingBook } from "./pricing.js";

export type ScopeType = "org" | "project" | "agent" | "task";
export interface ScopeRef {
  type: ScopeType;
  id: string;
}

export type ReservationStatus =
  | "reserved" // in flight; estimate held
  | "reconciled" // usage reported; actual cost recorded
  | "released" // provider confirmed nothing was consumed; hold returned
  | "unresolved"; // outcome unknown or usage missing; estimate stays held

export type LedgerEventType =
  | "reserved"
  | "reconciled"
  | "released"
  | "unresolved"
  | "blocked"
  | "duplicate_usage_ignored"
  | "conflicting_usage_rejected"
  | "budget_increased"
  | "task_cancelled";

export interface ConsumptionEvent {
  id: string;
  ts: string;
  eventType: LedgerEventType;
  tenantId: string;
  projectId: string | null;
  agentId: string;
  taskId: string;
  parentTaskId: string | null;
  rootTaskId: string;
  requestId: string;
  attempt: number;
  provider: string | null;
  model: string | null;
  /** null = not reported. NEVER coerced to 0: missing usage stays unresolved. */
  inputTokens: number | null;
  outputTokens: number | null;
  estimatedMicro: number | null;
  /** null until usage is reconciled. */
  reconciledMicro: number | null;
  policyVersion: number | null;
  approvalRef: string | null;
  actionEventId: string | null;
  status: string; // execution status, e.g. "ok", "blocked:policy_deny", "failed:timeout"
  pricingVersion: string | null;
  detail: string | null;
}

export interface ReserveInput {
  requestId: string; // unique per attempt: "<callerRequestId>#<attempt>"
  attempt: number;
  tenantId: string;
  projectId?: string;
  agentId: string;
  taskId: string;
  parentTaskId?: string;
  rootTaskId: string;
  provider: string;
  model: string;
  estimatedMicro: number;
  policyVersion?: number;
  approvalRef?: string;
  actionEventId?: string;
  pricingVersion: string;
  ttlSeconds?: number;
}

export type ReserveResult =
  | { ok: true; reservationId: string; existing: boolean; status: ReservationStatus }
  | { ok: false; reason: "budget_exhausted"; scope: ScopeRef; limitMicro: number; spentMicro: number; reservedMicro: number; requestedMicro: number }
  | { ok: false; reason: "task_cancelled"; scope: ScopeRef };

export interface ReconcileInput {
  requestId: string;
  /** Provider-reported usage event id (or one derived from the response id). The dedupe key. */
  usageEventId: string;
  inputTokens: number;
  outputTokens: number;
  actualMicro: number;
  status?: string; // execution status, default "ok"
}

export type ReconcileResult =
  | { outcome: "reconciled"; overrunMicro: number }
  | { outcome: "duplicate_ignored" }
  | { outcome: "rejected"; reason: string };

interface AppendExtra {
  eventType?: LedgerEventType;
  status?: string;
  inputTokens?: number | null;
  outputTokens?: number | null;
  reconciledMicro?: number | null;
  detail?: string | null;
  estimatedMicro?: number | null;
}
type AppendBase = Pick<ReserveInput, "requestId" | "attempt" | "tenantId" | "agentId" | "taskId" | "rootTaskId" | "pricingVersion"> &
  AppendExtra & {
    projectId?: string | null;
    parentTaskId?: string | null;
    provider?: string | null;
    model?: string | null;
    policyVersion?: number | null;
    approvalRef?: string | null;
    actionEventId?: string | null;
  };

export const EXHAUSTION_NOTICE =
  "New calls are paused. Calls already in progress may still complete and incur charges beyond this point.";

export class BudgetStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("busy_timeout = 10000"); // wait for the write lock instead of failing under contention
    this.migrate();
  }

  /** Exposed for the billing module, which shares this connection/transactions. */
  get database(): Database.Database {
    return this.db;
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS budgets (
        scope_type TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        limit_micro INTEGER,              -- NULL = no limit configured at this scope
        spent_micro INTEGER NOT NULL DEFAULT 0,
        reserved_micro INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'cancelled'
        PRIMARY KEY (scope_type, scope_id)
      );

      CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        parent_task_id TEXT,
        root_task_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS reservations (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,   -- idempotency: one reservation per attempt key
        attempt INTEGER NOT NULL,
        tenant_id TEXT NOT NULL,
        project_id TEXT,
        agent_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        parent_task_id TEXT,
        root_task_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        estimated_micro INTEGER NOT NULL,
        actual_micro INTEGER,
        scopes TEXT NOT NULL,              -- JSON ScopeRef[] charged by this reservation
        status TEXT NOT NULL,
        policy_version INTEGER,
        approval_ref TEXT,
        action_event_id TEXT,
        pricing_version TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- Dedupe table: a usage event id can be applied at most once, ever.
      CREATE TABLE IF NOT EXISTS usage_events (
        usage_event_id TEXT PRIMARY KEY,
        reservation_id TEXT NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        actual_micro INTEGER NOT NULL,
        received_at TEXT NOT NULL
      );

      -- The consumption ledger: append-only, one row per state transition.
      CREATE TABLE IF NOT EXISTS consumption_events (
        id TEXT PRIMARY KEY,
        seq INTEGER NOT NULL,
        ts TEXT NOT NULL,
        event_type TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        project_id TEXT,
        agent_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        parent_task_id TEXT,
        root_task_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        attempt INTEGER NOT NULL,
        provider TEXT,
        model TEXT,
        input_tokens INTEGER,
        output_tokens INTEGER,
        estimated_micro INTEGER,
        reconciled_micro INTEGER,
        policy_version INTEGER,
        approval_ref TEXT,
        action_event_id TEXT,
        status TEXT NOT NULL,
        pricing_version TEXT,
        detail TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_ce_request ON consumption_events(request_id);
      CREATE INDEX IF NOT EXISTS idx_ce_root ON consumption_events(root_task_id);

      CREATE TABLE IF NOT EXISTS pricing_versions (
        version TEXT PRIMARY KEY,
        snapshot TEXT NOT NULL,
        first_used_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS budget_admins (
        principal TEXT NOT NULL,
        scope_type TEXT NOT NULL,   -- scope type, or '*'
        scope_id TEXT NOT NULL,     -- scope id, or '*'
        PRIMARY KEY (principal, scope_type, scope_id)
      );

      CREATE TABLE IF NOT EXISTS budget_increases (
        id TEXT PRIMARY KEY,
        scope_type TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        add_micro INTEGER NOT NULL,
        requested_by TEXT NOT NULL,
        approver TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS billing_records (
        id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        reservation_id TEXT,
        pricing_version TEXT NOT NULL,
        provider_micro INTEGER NOT NULL,
        governance_micro INTEGER NOT NULL,
        platform_micro INTEGER NOT NULL,
        total_micro INTEGER NOT NULL,
        treatment TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
  }

  // ---------------------------------------------------------------- config

  /** Sets (or replaces) the limit at a scope. Used by administrators for
   * org/project budgets and by registration for agent/task defaults. */
  setBudget(scope: ScopeRef, limitMicro: number | null) {
    if (limitMicro !== null && (!Number.isInteger(limitMicro) || limitMicro < 0)) {
      throw new Error("limitMicro must be a non-negative integer");
    }
    this.db
      .prepare(
        `INSERT INTO budgets (scope_type, scope_id, limit_micro) VALUES (?, ?, ?)
         ON CONFLICT(scope_type, scope_id) DO UPDATE SET limit_micro = excluded.limit_micro`,
      )
      .run(scope.type, scope.id, limitMicro);
  }

  /** Creates the budget row only if none exists — used for lazy defaults so a
   * later administrator-set limit is never overwritten by a registration default. */
  ensureBudget(scope: ScopeRef, limitMicro: number | null) {
    this.db
      .prepare(`INSERT OR IGNORE INTO budgets (scope_type, scope_id, limit_micro) VALUES (?, ?, ?)`)
      .run(scope.type, scope.id, limitMicro);
  }

  getBudget(scope: ScopeRef) {
    const r = this.db
      .prepare(`SELECT * FROM budgets WHERE scope_type = ? AND scope_id = ?`)
      .get(scope.type, scope.id) as any | undefined;
    return r
      ? {
          limitMicro: r.limit_micro as number | null,
          spentMicro: r.spent_micro as number,
          reservedMicro: r.reserved_micro as number,
          status: r.status as string,
        }
      : undefined;
  }

  /** Records a task and its parent so every descendant resolves to the one
   * originating (root) task. All child calls, retries and fallbacks charge
   * the ROOT task's budget — that is the shared task budget. */
  registerTask(taskId: string, parentTaskId?: string): string {
    const existing = this.db.prepare(`SELECT root_task_id FROM tasks WHERE task_id = ?`).get(taskId) as any;
    if (existing) return existing.root_task_id;
    let root = taskId;
    if (parentTaskId) {
      const parent = this.db.prepare(`SELECT root_task_id FROM tasks WHERE task_id = ?`).get(parentTaskId) as any;
      if (!parent) throw new Error(`Unknown parent task: ${parentTaskId}`);
      root = parent.root_task_id;
    }
    this.db
      .prepare(`INSERT INTO tasks (task_id, parent_task_id, root_task_id, created_at) VALUES (?, ?, ?, ?)`)
      .run(taskId, parentTaskId ?? null, root, new Date().toISOString());
    return root;
  }

  addBudgetAdmin(principal: string, scopeType: ScopeType | "*" = "*", scopeId = "*") {
    this.db
      .prepare(`INSERT OR IGNORE INTO budget_admins (principal, scope_type, scope_id) VALUES (?, ?, ?)`)
      .run(principal, scopeType, scopeId);
  }

  private isBudgetAdmin(principal: string, scope: ScopeRef): boolean {
    const row = this.db
      .prepare(
        `SELECT 1 FROM budget_admins WHERE principal = ?
           AND (scope_type = '*' OR scope_type = ?) AND (scope_id = '*' OR scope_id = ?)`,
      )
      .get(principal, scope.type, scope.id);
    return Boolean(row);
  }

  snapshotPricing(book: PricingBook) {
    this.db
      .prepare(`INSERT OR IGNORE INTO pricing_versions (version, snapshot, first_used_at) VALUES (?, ?, ?)`)
      .run(book.version, JSON.stringify(book), new Date().toISOString());
  }

  getPricingSnapshot(version: string): PricingBook | undefined {
    const r = this.db.prepare(`SELECT snapshot FROM pricing_versions WHERE version = ?`).get(version) as any;
    return r ? (JSON.parse(r.snapshot) as PricingBook) : undefined;
  }

  // ------------------------------------------------------------ reservation

  /** The atomic check-and-hold. Idempotent on `requestId`. */
  reserve(input: ReserveInput): ReserveResult {
    const scopes: ScopeRef[] = [
      { type: "org", id: input.tenantId },
      ...(input.projectId ? [{ type: "project" as const, id: input.projectId }] : []),
      { type: "agent", id: input.agentId },
      { type: "task", id: input.rootTaskId },
    ];

    const tx = this.db.transaction((): ReserveResult => {
      const existing = this.db
        .prepare(`SELECT id, status FROM reservations WHERE request_id = ?`)
        .get(input.requestId) as any | undefined;
      if (existing) {
        return { ok: true, reservationId: existing.id, existing: true, status: existing.status };
      }

      for (const scope of scopes) {
        const b = this.getBudget(scope);
        if (!b) continue; // no budget configured here
        if (b.status === "cancelled") {
          this.appendEvent({ ...input, eventType: "blocked", status: "blocked:task_cancelled", detail: `${scope.type}:${scope.id}` });
          return { ok: false, reason: "task_cancelled", scope };
        }
        if (b.limitMicro === null) continue;
        if (b.spentMicro + b.reservedMicro + input.estimatedMicro > b.limitMicro) {
          this.appendEvent({
            ...input,
            eventType: "blocked",
            status: "blocked:budget_exhausted",
            detail: `${scope.type}:${scope.id} limit=${b.limitMicro} spent=${b.spentMicro} reserved=${b.reservedMicro} requested=${input.estimatedMicro}`,
          });
          return {
            ok: false,
            reason: "budget_exhausted",
            scope,
            limitMicro: b.limitMicro,
            spentMicro: b.spentMicro,
            reservedMicro: b.reservedMicro,
            requestedMicro: input.estimatedMicro,
          };
        }
      }

      // Every scope admitted the request: hold the estimate at all of them.
      for (const scope of scopes) {
        this.db
          .prepare(`UPDATE budgets SET reserved_micro = reserved_micro + ? WHERE scope_type = ? AND scope_id = ?`)
          .run(input.estimatedMicro, scope.type, scope.id);
      }

      const now = new Date();
      const id = nanoid();
      this.db
        .prepare(
          `INSERT INTO reservations
           (id, request_id, attempt, tenant_id, project_id, agent_id, task_id, parent_task_id, root_task_id,
            provider, model, estimated_micro, actual_micro, scopes, status, policy_version, approval_ref,
            action_event_id, pricing_version, created_at, expires_at, updated_at)
           VALUES (@id, @requestId, @attempt, @tenantId, @projectId, @agentId, @taskId, @parentTaskId, @rootTaskId,
                   @provider, @model, @estimatedMicro, NULL, @scopes, 'reserved', @policyVersion, @approvalRef,
                   @actionEventId, @pricingVersion, @createdAt, @expiresAt, @createdAt)`,
        )
        .run({
          id,
          requestId: input.requestId,
          attempt: input.attempt,
          tenantId: input.tenantId,
          projectId: input.projectId ?? null,
          agentId: input.agentId,
          taskId: input.taskId,
          parentTaskId: input.parentTaskId ?? null,
          rootTaskId: input.rootTaskId,
          provider: input.provider,
          model: input.model,
          estimatedMicro: input.estimatedMicro,
          scopes: JSON.stringify(scopes),
          policyVersion: input.policyVersion ?? null,
          approvalRef: input.approvalRef ?? null,
          actionEventId: input.actionEventId ?? null,
          pricingVersion: input.pricingVersion,
          createdAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + (input.ttlSeconds ?? 300) * 1000).toISOString(),
        });
      this.appendEvent({ ...input, eventType: "reserved", status: "reserved", estimatedMicro: input.estimatedMicro });
      return { ok: true, reservationId: id, existing: false, status: "reserved" };
    });

    return tx.immediate();
  }

  getReservation(requestId: string) {
    const r = this.db.prepare(`SELECT * FROM reservations WHERE request_id = ?`).get(requestId) as any | undefined;
    return r ? rowToReservation(r) : undefined;
  }

  /** Applies reported usage. Idempotent on `usageEventId`: a replayed or
   * duplicated usage event changes nothing and is recorded as ignored. */
  reconcile(input: ReconcileInput): ReconcileResult {
    const tx = this.db.transaction((): ReconcileResult => {
      const res = this.getReservation(input.requestId);
      if (!res) throw new Error(`No reservation for request ${input.requestId}`);

      const inserted = this.db
        .prepare(
          `INSERT OR IGNORE INTO usage_events (usage_event_id, reservation_id, input_tokens, output_tokens, actual_micro, received_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(input.usageEventId, res.id, input.inputTokens, input.outputTokens, input.actualMicro, new Date().toISOString());

      if (inserted.changes === 0) {
        this.appendEvent(res, { eventType: "duplicate_usage_ignored", status: "ignored", detail: `usage_event_id=${input.usageEventId}` });
        return { outcome: "duplicate_ignored" };
      }

      if (res.status !== "reserved" && res.status !== "unresolved") {
        // A different usage event arriving for an already-settled request is
        // a conflict, not a charge. Keep the dedupe row out of the way.
        this.db.prepare(`DELETE FROM usage_events WHERE usage_event_id = ?`).run(input.usageEventId);
        this.appendEvent(res, {
          eventType: "conflicting_usage_rejected",
          status: "rejected",
          detail: `request already ${res.status}; usage_event_id=${input.usageEventId}`,
        });
        return { outcome: "rejected", reason: `reservation already ${res.status}` };
      }

      for (const scope of res.scopes) {
        this.db
          .prepare(
            `UPDATE budgets SET reserved_micro = reserved_micro - ?, spent_micro = spent_micro + ?
             WHERE scope_type = ? AND scope_id = ?`,
          )
          .run(res.estimatedMicro, input.actualMicro, scope.type, scope.id);
      }
      this.db
        .prepare(`UPDATE reservations SET status = 'reconciled', actual_micro = ?, updated_at = ? WHERE id = ?`)
        .run(input.actualMicro, new Date().toISOString(), res.id);
      this.appendEvent(res, {
        eventType: "reconciled",
        status: input.status ?? "ok",
        inputTokens: input.inputTokens,
        outputTokens: input.outputTokens,
        reconciledMicro: input.actualMicro,
        detail: `usage_event_id=${input.usageEventId}`,
      });
      return { outcome: "reconciled", overrunMicro: Math.max(0, input.actualMicro - res.estimatedMicro) };
    });
    return tx.immediate();
  }

  /** Provider CONFIRMED nothing was consumed (e.g. rejected before generation).
   * Returns the hold. Only call this when non-consumption is known; when it
   * is merely unknown, use markUnresolved. */
  release(requestId: string, status: string, detail?: string) {
    const tx = this.db.transaction(() => {
      const res = this.getReservation(requestId);
      if (!res || (res.status !== "reserved" && res.status !== "unresolved")) return false;
      for (const scope of res.scopes) {
        this.db
          .prepare(`UPDATE budgets SET reserved_micro = reserved_micro - ? WHERE scope_type = ? AND scope_id = ?`)
          .run(res.estimatedMicro, scope.type, scope.id);
      }
      this.db.prepare(`UPDATE reservations SET status = 'released', updated_at = ? WHERE id = ?`).run(new Date().toISOString(), res.id);
      this.appendEvent(res, { eventType: "released", status, detail });
      return true;
    });
    return tx.immediate();
  }

  /** Usage is missing or the outcome is unknown. The estimate STAYS reserved
   * (conservative) and the ledger row carries null usage/cost — it is never
   * recorded as zero. Resolved later by reconcile() with real usage. */
  markUnresolved(requestId: string, status: string, detail?: string) {
    const tx = this.db.transaction(() => {
      const res = this.getReservation(requestId);
      if (!res || res.status !== "reserved") return false;
      this.db.prepare(`UPDATE reservations SET status = 'unresolved', updated_at = ? WHERE id = ?`).run(new Date().toISOString(), res.id);
      this.appendEvent(res, { eventType: "unresolved", status, detail });
      return true;
    });
    return tx.immediate();
  }

  /** Reservations past their TTL that never saw usage become unresolved —
   * never silently released, since the provider may still have billed us. */
  sweepExpired(now = new Date()): number {
    const rows = this.db
      .prepare(`SELECT request_id FROM reservations WHERE status = 'reserved' AND expires_at < ?`)
      .all(now.toISOString()) as any[];
    for (const r of rows) this.markUnresolved(r.request_id, "unresolved:expired", "reservation TTL elapsed without usage");
    return rows.length;
  }

  listUnresolved() {
    return (this.db.prepare(`SELECT * FROM reservations WHERE status = 'unresolved' ORDER BY created_at`).all() as any[]).map(rowToReservation);
  }

  // ------------------------------------------------- exhaustion & overrides

  /** An authorised approver raises one scope's limit. This is purely a
   * spending-limit change: it touches no tool grants, no policy, no
   * approvals (see acceptance test "budget increase grants no permissions"). */
  increaseBudget(input: { scope: ScopeRef; addMicro: number; requestedBy: string; approver: string; reason: string }) {
    if (!Number.isInteger(input.addMicro) || input.addMicro <= 0) throw new Error("addMicro must be a positive integer");
    if (input.approver === input.requestedBy) throw new Error("Separation of duties: the requester cannot approve their own budget increase");
    if (!this.isBudgetAdmin(input.approver, input.scope)) {
      throw new Error(`${input.approver} is not an authorised budget approver for ${input.scope.type}:${input.scope.id}`);
    }
    const tx = this.db.transaction(() => {
      const b = this.getBudget(input.scope);
      if (!b || b.limitMicro === null) throw new Error(`No limit configured at ${input.scope.type}:${input.scope.id}; nothing to increase`);
      if (b.status === "cancelled") throw new Error("Cancelled tasks cannot be topped up; start a new task");
      this.db
        .prepare(`UPDATE budgets SET limit_micro = limit_micro + ? WHERE scope_type = ? AND scope_id = ?`)
        .run(input.addMicro, input.scope.type, input.scope.id);
      this.db
        .prepare(
          `INSERT INTO budget_increases (id, scope_type, scope_id, add_micro, requested_by, approver, reason, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(nanoid(), input.scope.type, input.scope.id, input.addMicro, input.requestedBy, input.approver, input.reason, new Date().toISOString());
    });
    tx.immediate();
  }

  /** Cancels a task: no NEW reservations are admitted. Calls already in
   * progress still reconcile normally (and may still incur charges). */
  cancelTask(rootTaskId: string, cancelledBy: string) {
    this.ensureBudget({ type: "task", id: rootTaskId }, null);
    this.db.prepare(`UPDATE budgets SET status = 'cancelled' WHERE scope_type = 'task' AND scope_id = ?`).run(rootTaskId);
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO consumption_events (id, seq, ts, event_type, tenant_id, agent_id, task_id, root_task_id, request_id, attempt, status, detail)
         VALUES (?, (SELECT COALESCE(MAX(seq),0)+1 FROM consumption_events), ?, 'task_cancelled', 'n/a', 'n/a', ?, ?, ?, 0, 'cancelled', ?)`,
      )
      .run(nanoid(), now, rootTaskId, rootTaskId, `cancel:${rootTaskId}`, `cancelled by ${cancelledBy}`);
  }

  // ------------------------------------------------------------ ledger I/O

  /** Appends a ledger row. Used for blocked requests (no reservation exists)
   * as well as every reservation state transition. */
  appendEvent(base: AppendBase, extra: AppendExtra = {}) {
    // `base` may itself carry eventType/status/detail when called from reserve().
    const merged: any = { ...base, ...extra };
    this.db
      .prepare(
        `INSERT INTO consumption_events
         (id, seq, ts, event_type, tenant_id, project_id, agent_id, task_id, parent_task_id, root_task_id, request_id, attempt,
          provider, model, input_tokens, output_tokens, estimated_micro, reconciled_micro, policy_version, approval_ref,
          action_event_id, status, pricing_version, detail)
         VALUES (@id, (SELECT COALESCE(MAX(seq),0)+1 FROM consumption_events), @ts, @eventType, @tenantId, @projectId, @agentId, @taskId,
                 @parentTaskId, @rootTaskId, @requestId, @attempt, @provider, @model, @inputTokens, @outputTokens, @estimatedMicro,
                 @reconciledMicro, @policyVersion, @approvalRef, @actionEventId, @status, @pricingVersion, @detail)`,
      )
      .run({
        id: nanoid(),
        ts: new Date().toISOString(),
        eventType: merged.eventType,
        tenantId: merged.tenantId,
        projectId: merged.projectId ?? null,
        agentId: merged.agentId,
        taskId: merged.taskId,
        parentTaskId: merged.parentTaskId ?? null,
        rootTaskId: merged.rootTaskId,
        requestId: merged.requestId,
        attempt: merged.attempt,
        provider: merged.provider ?? null,
        model: merged.model ?? null,
        inputTokens: merged.inputTokens ?? null,
        outputTokens: merged.outputTokens ?? null,
        estimatedMicro: merged.estimatedMicro ?? null,
        reconciledMicro: merged.reconciledMicro ?? null,
        policyVersion: merged.policyVersion ?? null,
        approvalRef: merged.approvalRef ?? null,
        actionEventId: merged.actionEventId ?? null,
        status: merged.status,
        pricingVersion: merged.pricingVersion ?? null,
        detail: merged.detail ?? null,
      });
  }

  /** Records a request that was blocked BEFORE any reservation (policy deny,
   * missing grant, unpermitted model, pending approval, inactive agent). */
  recordBlocked(input: Omit<ReserveInput, "estimatedMicro"> & { estimatedMicro?: number; status: string; detail?: string }) {
    const tx = this.db.transaction(() => {
      this.appendEvent(input, { eventType: "blocked", status: input.status, detail: input.detail ?? null });
    });
    tx.immediate();
  }

  ledgerForRequest(requestId: string): ConsumptionEvent[] {
    return (this.db.prepare(`SELECT * FROM consumption_events WHERE request_id = ? ORDER BY seq`).all(requestId) as any[]).map(rowToEvent);
  }

  ledgerForRootTask(rootTaskId: string): ConsumptionEvent[] {
    return (this.db.prepare(`SELECT * FROM consumption_events WHERE root_task_id = ? ORDER BY seq`).all(rootTaskId) as any[]).map(rowToEvent);
  }

  getUsageEvent(usageEventId: string) {
    return this.db.prepare(`SELECT * FROM usage_events WHERE usage_event_id = ?`).get(usageEventId) as any | undefined;
  }

  close() {
    this.db.close();
  }
}

export interface Reservation {
  id: string;
  requestId: string;
  attempt: number;
  tenantId: string;
  projectId: string | null;
  agentId: string;
  taskId: string;
  parentTaskId: string | null;
  rootTaskId: string;
  provider: string;
  model: string;
  estimatedMicro: number;
  actualMicro: number | null;
  scopes: ScopeRef[];
  status: ReservationStatus;
  policyVersion: number | null;
  approvalRef: string | null;
  actionEventId: string | null;
  pricingVersion: string;
}

function rowToReservation(r: any): Reservation {
  return {
    id: r.id,
    requestId: r.request_id,
    attempt: r.attempt,
    tenantId: r.tenant_id,
    projectId: r.project_id,
    agentId: r.agent_id,
    taskId: r.task_id,
    parentTaskId: r.parent_task_id,
    rootTaskId: r.root_task_id,
    provider: r.provider,
    model: r.model,
    estimatedMicro: r.estimated_micro,
    actualMicro: r.actual_micro,
    scopes: JSON.parse(r.scopes),
    status: r.status,
    policyVersion: r.policy_version,
    approvalRef: r.approval_ref,
    actionEventId: r.action_event_id,
    pricingVersion: r.pricing_version,
  };
}

function rowToEvent(r: any): ConsumptionEvent {
  return {
    id: r.id,
    ts: r.ts,
    eventType: r.event_type,
    tenantId: r.tenant_id,
    projectId: r.project_id,
    agentId: r.agent_id,
    taskId: r.task_id,
    parentTaskId: r.parent_task_id,
    rootTaskId: r.root_task_id,
    requestId: r.request_id,
    attempt: r.attempt,
    provider: r.provider,
    model: r.model,
    inputTokens: r.input_tokens,
    outputTokens: r.output_tokens,
    estimatedMicro: r.estimated_micro,
    reconciledMicro: r.reconciled_micro,
    policyVersion: r.policy_version,
    approvalRef: r.approval_ref,
    actionEventId: r.action_event_id,
    status: r.status,
    pricingVersion: r.pricing_version,
    detail: r.detail,
  };
}
