// Security monitor: watches the audit stream for signs of probing or misuse
// and raises alerts. It reads the SAME events the audit log records, so
// anything an attacker does at the gateway is both evidence and signal.
//
// Rules (thresholds are constructor options):
//   auth_failure_burst        N failed authentications from one source in a window
//   dead_credential_used      a revoked or expired credential was presented
//   identity_spoofing         an agent tried to act as a different agent
//   credential_new_source     a known agent credential used from a never-seen network address
//   policy_probing            N policy denials for one agent in a window
//   rate_limit_abuse          repeated rate-limit hits by one subject
//   malformed_request_burst   N malformed/oversized requests from one source
//
// Each alert is stored, written back to the audit log as "security.alert"
// (so it reaches any SIEM sink and is covered by the tamper-evident chain),
// and de-duplicated per rule+subject during a cooldown.
//
// Windows are kept in memory per process. With several gateway replicas the
// counters must move to shared state (Redis / a stream processor); the rule
// definitions stay the same.

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type { AuditEvent, AuditLog } from "./audit-log.js";

export type Severity = "low" | "medium" | "high";
export interface SecurityAlert {
  id: string;
  ts: string;
  rule: string;
  severity: Severity;
  subject: string;
  details: Record<string, unknown>;
  status: "open" | "acknowledged";
}

export interface MonitorOptions {
  windowMs: number;
  authFailureThreshold: number;
  denyThreshold: number;
  rateLimitThreshold: number;
  malformedThreshold: number;
  cooldownMs: number;
}

const DEFAULTS: MonitorOptions = {
  windowMs: 60_000,
  authFailureThreshold: 5,
  denyThreshold: 5,
  rateLimitThreshold: 3,
  malformedThreshold: 5,
  cooldownMs: 5 * 60_000,
};

export class SecurityMonitor {
  private opts: MonitorOptions;
  private windows = new Map<string, number[]>();
  private lastAlert = new Map<string, number>();

  constructor(
    private db: Database.Database,
    private audit: AuditLog,
    opts: Partial<MonitorOptions> = {},
  ) {
    this.opts = { ...DEFAULTS, ...opts };
    db.exec(`
      CREATE TABLE IF NOT EXISTS security_alerts (
        id TEXT PRIMARY KEY, ts TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
        subject TEXT NOT NULL, details TEXT NOT NULL, status TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS credential_sources (
        subject TEXT NOT NULL, ip TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY (subject, ip)
      );
    `);
    audit.onEvent((e) => this.observe(e));
  }

  private hit(key: string, atMs: number): number {
    const arr = (this.windows.get(key) ?? []).filter((t) => atMs - t <= this.opts.windowMs);
    arr.push(atMs);
    this.windows.set(key, arr);
    return arr.length;
  }

  private raise(rule: string, severity: Severity, subject: string, atMs: number, details: Record<string, unknown>) {
    const key = `${rule}:${subject}`;
    const last = this.lastAlert.get(key);
    if (last !== undefined && atMs - last < this.opts.cooldownMs) return;
    this.lastAlert.set(key, atMs);
    const alert: SecurityAlert = { id: nanoid(), ts: new Date(atMs).toISOString(), rule, severity, subject, details, status: "open" };
    this.db
      .prepare(`INSERT INTO security_alerts (id, ts, rule, severity, subject, details, status) VALUES (?, ?, ?, ?, ?, ?, 'open')`)
      .run(alert.id, alert.ts, rule, severity, subject, JSON.stringify(details));
    this.audit.append({
      stream: "audit", actorType: "system", actorId: "security-monitor", action: "security.alert", targetType: "subject", targetId: subject,
      outcome: "success", details: { rule, severity, alertId: alert.id, ...details },
    });
  }

  private observe(e: AuditEvent) {
    if (e.action.startsWith("security.")) return; // never react to our own alerts
    const at = Date.parse(e.ts);
    const ip = e.sourceIp ?? "unknown";

    switch (e.action) {
      case "auth.failed": {
        const n = this.hit(`authfail:${ip}`, at);
        if (n >= this.opts.authFailureThreshold) this.raise("auth_failure_burst", "high", ip, at, { count: n, windowMs: this.opts.windowMs });
        const reason = e.details?.reason;
        if (reason === "revoked" || reason === "expired") {
          this.raise("dead_credential_used", "high", String(e.details?.subject ?? e.actorId), at, { reason, sourceIp: ip });
        }
        break;
      }
      case "auth.success": {
        if (e.actorType !== "agent" || !e.sourceIp) break;
        const known = this.db.prepare(`SELECT COUNT(*) AS n FROM credential_sources WHERE subject = ?`).get(e.actorId) as any;
        const seen = this.db.prepare(`SELECT 1 FROM credential_sources WHERE subject = ? AND ip = ?`).get(e.actorId, e.sourceIp);
        if (!seen) {
          this.db.prepare(`INSERT INTO credential_sources (subject, ip, first_seen) VALUES (?, ?, ?)`).run(e.actorId, e.sourceIp, e.ts);
          if (known.n > 0) this.raise("credential_new_source", "medium", e.actorId, at, { sourceIp: e.sourceIp, knownSources: known.n });
        }
        break;
      }
      case "identity.mismatch":
        this.raise("identity_spoofing", "high", e.actorId, at, { claimed: e.details?.claimedAgentId, sourceIp: ip });
        break;
      case "gateway.call":
        if (e.outcome === "denied") {
          const n = this.hit(`deny:${e.actorId}`, at);
          if (n >= this.opts.denyThreshold) this.raise("policy_probing", "medium", e.actorId, at, { denials: n, windowMs: this.opts.windowMs });
        }
        break;
      case "rate_limit.exceeded": {
        const n = this.hit(`rl:${e.actorId}`, at);
        if (n >= this.opts.rateLimitThreshold) this.raise("rate_limit_abuse", "low", e.actorId, at, { hits: n, sourceIp: ip });
        break;
      }
      case "request.malformed": {
        const n = this.hit(`bad:${ip}`, at);
        if (n >= this.opts.malformedThreshold) this.raise("malformed_request_burst", "medium", ip, at, { count: n });
        break;
      }
    }
  }

  listAlerts(status?: "open" | "acknowledged"): SecurityAlert[] {
    const rows = (status
      ? this.db.prepare(`SELECT * FROM security_alerts WHERE status = ? ORDER BY ts`).all(status)
      : this.db.prepare(`SELECT * FROM security_alerts ORDER BY ts`).all()) as any[];
    return rows.map((r) => ({ id: r.id, ts: r.ts, rule: r.rule, severity: r.severity, subject: r.subject, details: JSON.parse(r.details), status: r.status }));
  }
}
