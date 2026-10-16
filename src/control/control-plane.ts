// Control plane composition: builds every control-plane service around one
// shared database connection so registry, credentials, audit log, security
// monitor and the governance ledger all live in the same durable store.
//
// Phase 1 adds: manifests (registration as code), discovery (gateway,
// egress import, connectors, triage queue) and a scheduler that runs the
// discovery connectors and the expiry sweep. The scheduler is built but not
// started here; the gateway process starts it when ZENAI4_SCHEDULER=1, so
// tests and the CLI never run background jobs by accident.
//
// Phase 1.1 adds telemetry: an intake store (sources, batches, sessions,
// steps, hash-chained policy violations, alerts), the intake service the
// gateway's /v1/intake routes call, and reconciliation + payload retention
// registered as scheduler jobs (hourly and daily by default).

import Database from "better-sqlite3";
import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine, type Policy } from "../policy/engine.js";
import { Gateway } from "../gateway/gateway.js";
import { StderrApprovalChannel, type ApprovalChannel } from "../gateway/approvals.js";
import { AuditLog, JsonLinesSink, type AuditSink } from "./audit-log.js";
import { SqliteDirectory } from "./identity.js";
import { CredentialService } from "./credentials.js";
import { AccessProfileStore, type AccessProfile } from "./access-profiles.js";
import { RegistrationService } from "./registration.js";
import { SecurityMonitor, type MonitorOptions } from "./security-monitor.js";
import { ManifestService } from "./manifest.js";
import { DiscoveryService } from "../discovery/discovery.js";
import { Scheduler, intervalFromEnv } from "../discovery/scheduler.js";
import type { DiscoveryConnector } from "../discovery/connectors.js";
import { DEFAULT_TELEMETRY_CONFIG, telemetryConfigFromEnv, type TelemetryConfig } from "../telemetry/config.js";
import { TelemetryStore } from "../telemetry/store.js";
import { IntakeService } from "../telemetry/intake.js";
import { ReconcileService } from "../telemetry/reconcile.js";

export interface ControlPlaneOptions {
  dbPath: string;
  /** Append every audit event as a JSON line to this file (SIEM tail target). */
  siemPath?: string;
  sinks?: AuditSink[];
  approvals?: ApprovalChannel;
  monitor?: Partial<MonitorOptions>;
  now?: () => Date;
  /** Default certification period in days (90). */
  certificationDays?: number;
  /** Discovery connectors to schedule (see connectorsFromEnv). */
  connectors?: DiscoveryConnector[];
  /** Interval for connector runs; defaults to ZENAI4_DISCOVERY_INTERVAL_HOURS or 6h. */
  discoveryIntervalMs?: number;
  /** Telemetry settings. Unset keys come from ZENAI4_* env (when readEnv) or defaults. */
  telemetry?: Partial<TelemetryConfig>;
  /** Read telemetry settings from the environment (default true; tests pass false). */
  readTelemetryEnv?: boolean;
}

export function buildControlPlane(opts: ControlPlaneOptions) {
  const db = new Database(opts.dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 10000");

  const sinks: AuditSink[] = [...(opts.sinks ?? [])];
  if (opts.siemPath) sinks.push(new JsonLinesSink(opts.siemPath));
  const audit = new AuditLog(db, sinks, opts.now);

  const registry = new AgentRegistry(db, opts.now);
  // Every registry state change - from any caller - becomes an audit/user log entry.
  registry.setChangeListener((c) => {
    const human = c.actor.includes("@");
    audit.append({
      stream: human ? "user" : "audit",
      actorType: human ? "user" : "system",
      actorId: c.actor,
      action: c.action,
      targetType: "agent",
      targetId: c.agentId,
      outcome: "success",
      details: c.details,
    });
  });

  const directory = new SqliteDirectory(db);
  const profiles = new AccessProfileStore(db);
  const credentials = new CredentialService(db, opts.now);
  const registration = new RegistrationService(registry, directory, profiles, credentials, audit, {
    certificationDays: opts.certificationDays, now: opts.now,
  });
  const manifests = new ManifestService(registry, registration, audit);
  const discovery = new DiscoveryService(db, audit, registry, registration, directory, opts.now);
  const scheduler = new Scheduler(db, audit, { defaultIntervalMs: opts.discoveryIntervalMs ?? intervalFromEnv(), now: opts.now });
  for (const c of opts.connectors ?? []) scheduler.addConnector(c, discovery);
  scheduler.addExpirySweep(registration);
  const monitor = new SecurityMonitor(db, audit, opts.monitor);

  const ledger = new Ledger(opts.dbPath);
  const telemetryConfig: TelemetryConfig = {
    ...(opts.readTelemetryEnv === false ? DEFAULT_TELEMETRY_CONFIG : telemetryConfigFromEnv()),
    ...(opts.telemetry ?? {}),
  };
  const telemetry = new TelemetryStore(db, opts.now);
  const intake = new IntakeService(telemetry, registry, audit, telemetryConfig, opts.now);
  const reconcile = new ReconcileService(telemetry, registry, registration, discovery, profiles, ledger, audit, telemetryConfig, opts.now);
  scheduler.add({ id: "telemetry-reconcile", intervalMs: telemetryConfig.reconcileIntervalMs, run: async () => {
    const r = reconcile.run();
    return { items: r.stepsProcessed, created: r.newDiscoveries + r.alertsRaised };
  } });
  scheduler.add({ id: "telemetry-retention", intervalMs: 24 * 60 * 60 * 1000, run: async () => ({ items: reconcile.retentionSweep().purged }) });
  const policyEngine = new PolicyEngine(registry, ledger);
  const gateway = new Gateway(registry, policyEngine, ledger, opts.approvals ?? new StderrApprovalChannel());

  // Policies are durable: a restarted or newly added gateway replica loads the same set.
  db.exec(`CREATE TABLE IF NOT EXISTS policies (
    tool_name TEXT PRIMARY KEY, version INTEGER NOT NULL, body TEXT NOT NULL,
    updated_by TEXT NOT NULL, updated_at TEXT NOT NULL)`);
  for (const row of db.prepare("SELECT body FROM policies").all() as Array<{ body: string }>) {
    policyEngine.setPolicy(JSON.parse(row.body) as Policy);
  }
  /** Persist and activate a policy. Versions must increase, so history cannot be rolled back silently. */
  const savePolicy = (policy: Policy, actor: string): { ok: true } | { ok: false; currentVersion: number } => {
    const current = db.prepare("SELECT version FROM policies WHERE tool_name = ?").get(policy.toolName) as { version: number } | undefined;
    if (current && policy.version <= current.version) return { ok: false, currentVersion: current.version };
    db.prepare(`INSERT INTO policies (tool_name, version, body, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(tool_name) DO UPDATE SET version = excluded.version, body = excluded.body,
      updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
      .run(policy.toolName, policy.version, JSON.stringify(policy), actor, (opts.now?.() ?? new Date()).toISOString());
    policyEngine.setPolicy(policy);
    return { ok: true };
  };

  return {
    db, audit, registry, directory, profiles, credentials, registration, monitor, ledger, policyEngine, gateway, savePolicy,
    manifests, discovery, scheduler, telemetry, telemetryConfig, intake, reconcile,
    close() {
      scheduler.stop();
      ledger.close();
      db.close();
    },
  };
}
export type ControlPlane = ReturnType<typeof buildControlPlane>;

/** Starter profiles an administrator would tailor. */
export const DEFAULT_PROFILES: AccessProfile[] = [
  {
    id: "internal-readonly",
    name: "Internal read-only",
    description: "Reads internal, non-sensitive data. No review needed.",
    allowedTools: ["*"],
    allowedDataClasses: ["internal"],
    allowedModels: ["claude-haiku-4-5", "claude-sonnet-5"],
    maxAutonomy: "A1",
    requiresSecurityReview: false,
  },
  {
    id: "customer-facing",
    name: "Customer-facing",
    description: "Touches customer PII and money. Security review mandatory.",
    allowedTools: ["issue_refund", "llm_invoke", "read_invoice"],
    allowedDataClasses: ["customer_pii", "financial", "internal"],
    allowedModels: ["claude-sonnet-5"],
    maxAutonomy: "A2",
    requiresSecurityReview: true,
  },
];
