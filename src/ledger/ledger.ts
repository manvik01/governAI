// Evidence Ledger: append-only, hash-chained log of every governed action.
// This is the module that answers "what did agent X do, and can we prove it?"
//
// Design choices for the MVP:
// - SQLite for zero-ops local/demo storage; swap to Postgres/ClickHouse later
//   by reimplementing this same interface.
// - Each event's hash covers its own fields + the previous event's hash, so
//   any edit or deletion breaks the chain from that point forward. This is
//   the same principle as a blockchain's block-linking, without needing one.
// - Parameters are stored redacted (see redactParameters) by default; full
//   payload capture is an explicit opt-in per agent, not built here.

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
import type { ActionEvent, Approval, Decision } from "../types.js";

const GENESIS_HASH = "0".repeat(64);

export class Ledger {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS action_events (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        principal TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        parameters_redacted TEXT NOT NULL,
        decision TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        policy_version INTEGER NOT NULL,
        rule_triggered TEXT,
        latency_ms REAL NOT NULL,
        timestamp TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        approval_id TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_events_agent ON action_events(agent_id);
      CREATE INDEX IF NOT EXISTS idx_events_run ON action_events(run_id);
      CREATE INDEX IF NOT EXISTS idx_events_timestamp ON action_events(timestamp);

      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        action_event_id TEXT NOT NULL,
        approver TEXT,
        status TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        decided_at TEXT,
        reason TEXT
      );
    `);
  }

  /** Redacts sensitive parameter values to a short hash, keeping keys and
   * non-sensitive scalars (amounts, counts) visible for policy debugging. */
  static redactParameters(
    params: Record<string, unknown>,
    sensitiveKeys: string[] = ["email", "account_number", "ssn", "name"],
  ): string {
    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(params)) {
      if (sensitiveKeys.includes(key)) {
        redacted[key] = `sha256:${createHash("sha256").update(String(value)).digest("hex").slice(0, 16)}`;
      } else {
        redacted[key] = value;
      }
    }
    return JSON.stringify(redacted);
  }

  private lastHash(): string {
    const row = this.db
      .prepare(`SELECT hash FROM action_events ORDER BY rowid DESC LIMIT 1`)
      .get() as { hash: string } | undefined;
    return row?.hash ?? GENESIS_HASH;
  }

  /** Appends one action event to the chain and returns it with its computed hash. */
  append(input: {
    runId: string;
    agentId: string;
    principal: string;
    toolName: string;
    parameters: Record<string, unknown>;
    decision: Decision;
    policyId: string;
    policyVersion: number;
    ruleTriggered?: string;
    latencyMs: number;
    approvalId?: string;
  }): ActionEvent {
    const prevHash = this.lastHash();
    const id = nanoid();
    const timestamp = new Date().toISOString();
    const parametersRedacted = Ledger.redactParameters(input.parameters);

    const hashInput = [
      id,
      input.runId,
      input.agentId,
      input.principal,
      input.toolName,
      parametersRedacted,
      input.decision,
      input.policyId,
      String(input.policyVersion),
      input.ruleTriggered ?? "",
      timestamp,
      prevHash,
    ].join("|");
    const hash = createHash("sha256").update(hashInput).digest("hex");

    const event: ActionEvent = {
      id,
      runId: input.runId,
      agentId: input.agentId,
      principal: input.principal,
      toolName: input.toolName,
      parametersRedacted,
      decision: input.decision,
      policyId: input.policyId,
      policyVersion: input.policyVersion,
      ruleTriggered: input.ruleTriggered,
      latencyMs: input.latencyMs,
      timestamp,
      prevHash,
      hash,
      approvalId: input.approvalId,
    };

    this.db
      .prepare(
        `INSERT INTO action_events
         (id, run_id, agent_id, principal, tool_name, parameters_redacted, decision,
          policy_id, policy_version, rule_triggered, latency_ms, timestamp, prev_hash, hash, approval_id)
         VALUES (@id, @runId, @agentId, @principal, @toolName, @parametersRedacted, @decision,
                 @policyId, @policyVersion, @ruleTriggered, @latencyMs, @timestamp, @prevHash, @hash, @approvalId)`,
      )
      .run(event);

    return event;
  }

  /** Returns events for one agent, most recent first. */
  forAgent(agentId: string, limit = 100): ActionEvent[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM action_events WHERE agent_id = ? ORDER BY rowid DESC LIMIT ?`,
      )
      .all(agentId, limit) as any[];
    return rows.map(rowToEvent);
  }

  /** Returns every event within [sinceIso, now], for stateful policy checks
   * (e.g. "how many refunds has this agent issued in the last hour"). */
  forAgentSince(agentId: string, sinceIso: string): ActionEvent[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM action_events WHERE agent_id = ? AND timestamp >= ? ORDER BY rowid ASC`,
      )
      .all(agentId, sinceIso) as any[];
    return rows.map(rowToEvent);
  }

  /** Verifies the hash chain is intact. Returns the index of the first break, or -1 if clean. */
  verifyChain(): number {
    const rows = this.db
      .prepare(`SELECT * FROM action_events ORDER BY rowid ASC`)
      .all() as any[];
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      if (r.prev_hash !== expectedPrev) return i;
      const hashInput = [
        r.id,
        r.run_id,
        r.agent_id,
        r.principal,
        r.tool_name,
        r.parameters_redacted,
        r.decision,
        r.policy_id,
        String(r.policy_version),
        r.rule_triggered ?? "",
        r.timestamp,
        r.prev_hash,
      ].join("|");
      const recomputed = createHash("sha256").update(hashInput).digest("hex");
      if (recomputed !== r.hash) return i;
      expectedPrev = r.hash;
    }
    return -1;
  }

  recordApproval(input: { actionEventId: string; requestedAt: string }): string {
    const id = nanoid();
    this.db
      .prepare(
        `INSERT INTO approvals (id, action_event_id, status, requested_at)
         VALUES (?, ?, 'pending', ?)`,
      )
      .run(id, input.actionEventId, input.requestedAt);
    return id;
  }

  decideApproval(id: string, approver: string, approved: boolean, reason?: string) {
    this.db
      .prepare(
        `UPDATE approvals SET approver = ?, status = ?, decided_at = ?, reason = ? WHERE id = ?`,
      )
      .run(
        approver,
        approved ? "approved" : "rejected",
        new Date().toISOString(),
        reason ?? null,
        id,
      );
  }

  getApproval(id: string): Approval | undefined {
    const row = this.db.prepare(`SELECT * FROM approvals WHERE id = ?`).get(id) as any;
    if (!row) return undefined;
    return {
      id: row.id,
      actionEventId: row.action_event_id,
      approver: row.approver ?? undefined,
      status: row.status,
      requestedAt: row.requested_at,
      decidedAt: row.decided_at ?? undefined,
      reason: row.reason ?? undefined,
    };
  }

  getEvent(id: string): ActionEvent | undefined {
    const row = this.db
      .prepare(`SELECT * FROM action_events WHERE id = ?`)
      .get(id) as any;
    return row ? rowToEvent(row) : undefined;
  }

  /**
   * Out-of-band approval resolution for a separate OS process (e.g. mcp:approve).
   * Looks up the held event, marks the approval decided, and appends a follow-up
   * allow/deny event so stateful velocity rules see the human decision.
   */
  resolveApprovalOutOfBand(
    approvalId: string,
    approver: string,
    approved: boolean,
    reason?: string,
  ): { approval: Approval; event: ActionEvent } {
    const approval = this.getApproval(approvalId);
    if (!approval) throw new Error(`Unknown approval id: ${approvalId}`);
    if (approval.status !== "pending") {
      throw new Error(`Approval ${approvalId} is already ${approval.status}`);
    }
    const held = this.getEvent(approval.actionEventId);
    if (!held) throw new Error(`Missing action event ${approval.actionEventId}`);

    this.decideApproval(approvalId, approver, approved, reason);
    const parameters = JSON.parse(held.parametersRedacted) as Record<string, unknown>;
    const event = this.append({
      runId: held.runId,
      agentId: held.agentId,
      principal: held.principal,
      toolName: held.toolName,
      parameters,
      decision: approved ? "allow" : "deny",
      policyId: "approval",
      policyVersion: 1,
      ruleTriggered: approved ? "human_approval:approved" : "human_approval:rejected",
      latencyMs: 0,
      approvalId,
    });
    return {
      approval: this.getApproval(approvalId)!,
      event,
    };
  }

  close() {
    this.db.close();
  }
}

function rowToEvent(r: any): ActionEvent {
  return {
    id: r.id,
    runId: r.run_id,
    agentId: r.agent_id,
    principal: r.principal,
    toolName: r.tool_name,
    parametersRedacted: r.parameters_redacted,
    decision: r.decision,
    policyId: r.policy_id,
    policyVersion: r.policy_version,
    ruleTriggered: r.rule_triggered ?? undefined,
    latencyMs: r.latency_ms,
    timestamp: r.timestamp,
    prevHash: r.prev_hash,
    hash: r.hash,
    approvalId: r.approval_id ?? undefined,
  };
}
