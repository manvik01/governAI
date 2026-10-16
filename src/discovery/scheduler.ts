// Scheduler: runs discovery connectors and the expiry sweep on an interval.
//
//   - Default interval 6 hours (ZENAI4_DISCOVERY_INTERVAL_HOURS), per job
//     overridable. Timers are unref'd so they never keep a process alive.
//   - One run at a time per job: a run that is still going when the next
//     tick fires is skipped and recorded as "skipped", never stacked.
//   - Every run is recorded in discovery_runs (started, finished, status,
//     items, new items, error) and audited. Error text is scrubbed of
//     anything secret-shaped before it is stored, and connectors never put
//     credentials in errors in the first place.
//   - A failing connector does not stop the others.
//
// With several gateway replicas, run the scheduler in exactly one process
// (a worker), or move the in-flight lock to the database (Postgres advisory
// lock); the in-memory lock here only guards one process.

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type { AuditLog } from "../control/audit-log.js";
import type { RegistrationService } from "../control/registration.js";
import { scrubSecrets } from "../control/secret-patterns.js";
import type { DiscoveryConnector } from "./connectors.js";
import type { DiscoveryService } from "./discovery.js";

export const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;

export interface Job {
  id: string;
  intervalMs?: number;
  run(): Promise<{ items: number; created?: number }>;
}

export interface RunRecord {
  id: string;
  jobId: string;
  startedAt: string;
  finishedAt?: string;
  status: "running" | "ok" | "error" | "skipped";
  items: number;
  created: number;
  error?: string;
}

export class Scheduler {
  private jobs = new Map<string, Job>();
  private inFlight = new Set<string>();
  private timers: NodeJS.Timeout[] = [];

  constructor(
    private db: Database.Database,
    private audit: AuditLog,
    private opts: { defaultIntervalMs?: number; now?: () => Date } = {},
  ) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS discovery_runs (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running','ok','error','skipped')),
        items INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL DEFAULT 0,
        error TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_discovery_runs_job ON discovery_runs(job_id, started_at);
    `);
  }

  private now() {
    return (this.opts.now?.() ?? new Date()).toISOString();
  }

  add(job: Job) {
    if (this.jobs.has(job.id)) throw new Error(`duplicate job id ${job.id}`);
    this.jobs.set(job.id, job);
    return this;
  }

  /** Adds a connector as a job that records what it finds through discovery. */
  addConnector(c: DiscoveryConnector, discovery: DiscoveryService, intervalMs?: number) {
    return this.add({
      id: `connector:${c.id}`,
      intervalMs,
      run: async () => {
        const found = await c.run();
        let created = 0;
        for (const item of found) if (discovery.record({ ...item, source: c.kind }).created) created++;
        return { items: found.length, created };
      },
    });
  }

  /** Adds the expiry sweep (suspends expired agents, revokes credentials). */
  addExpirySweep(registration: RegistrationService, intervalMs?: number) {
    return this.add({
      id: "expiry-sweep",
      intervalMs: intervalMs ?? 60 * 60 * 1000,
      run: async () => ({ items: registration.expirySweep().length }),
    });
  }

  jobIds() {
    return [...this.jobs.keys()];
  }

  /** Runs one job now. Never throws: the outcome is in the returned record. */
  async runOnce(jobId: string): Promise<RunRecord> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error(`unknown job ${jobId}`);
    const rec: RunRecord = { id: nanoid(12), jobId, startedAt: this.now(), status: "running", items: 0, created: 0 };
    if (this.inFlight.has(jobId)) {
      rec.status = "skipped";
      rec.finishedAt = rec.startedAt;
      rec.error = "previous run still in progress";
      this.save(rec);
      return rec;
    }
    this.inFlight.add(jobId);
    this.save(rec);
    try {
      const out = await job.run();
      rec.status = "ok";
      rec.items = out.items;
      rec.created = out.created ?? 0;
    } catch (e) {
      rec.status = "error";
      rec.error = scrubSecrets(String((e as Error)?.message ?? e)).slice(0, 500);
    } finally {
      this.inFlight.delete(jobId);
      rec.finishedAt = this.now();
      this.save(rec);
      this.audit.append({
        stream: "audit", actorType: "system", actorId: "scheduler", action: "discovery.run", targetType: "job", targetId: jobId,
        outcome: rec.status === "ok" ? "success" : "failure", details: { runId: rec.id, status: rec.status, items: rec.items, created: rec.created, error: rec.error },
      });
    }
    return rec;
  }

  async runAll(): Promise<RunRecord[]> {
    return Promise.all(this.jobIds().map((id) => this.runOnce(id)));
  }

  private save(r: RunRecord) {
    this.db.prepare(`INSERT INTO discovery_runs (id, job_id, started_at, finished_at, status, items, created, error)
        VALUES (@id, @jobId, @startedAt, @finishedAt, @status, @items, @created, @error)
        ON CONFLICT(id) DO UPDATE SET finished_at = excluded.finished_at, status = excluded.status,
          items = excluded.items, created = excluded.created, error = excluded.error`)
      .run({ ...r, finishedAt: r.finishedAt ?? null, error: r.error ?? null });
  }

  /** Last run per job (for GET /v1/discovery/connectors and the CLI). */
  status(): Array<{ jobId: string; intervalMs: number; running: boolean; lastRun?: RunRecord }> {
    return this.jobIds().map((jobId) => {
      const r = this.db.prepare(`SELECT * FROM discovery_runs WHERE job_id = ? AND status != 'skipped' ORDER BY started_at DESC, rowid DESC LIMIT 1`).get(jobId) as any;
      return {
        jobId,
        intervalMs: this.jobs.get(jobId)!.intervalMs ?? this.opts.defaultIntervalMs ?? DEFAULT_INTERVAL_MS,
        running: this.inFlight.has(jobId),
        lastRun: r ? { id: r.id, jobId: r.job_id, startedAt: r.started_at, finishedAt: r.finished_at ?? undefined, status: r.status, items: r.items, created: r.created, error: r.error ?? undefined } : undefined,
      };
    });
  }

  /** Starts interval timers (first run immediately unless runNow is false). */
  start(runNow = true) {
    for (const job of this.jobs.values()) {
      const every = job.intervalMs ?? this.opts.defaultIntervalMs ?? DEFAULT_INTERVAL_MS;
      if (runNow) void this.runOnce(job.id);
      const t = setInterval(() => void this.runOnce(job.id), every);
      t.unref();
      this.timers.push(t);
    }
  }

  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }
}

export function intervalFromEnv(env: Record<string, string | undefined> = process.env): number {
  const h = Number(env.ZENAI4_DISCOVERY_INTERVAL_HOURS);
  return Number.isFinite(h) && h > 0 ? Math.round(h * 3_600_000) : DEFAULT_INTERVAL_MS;
}
