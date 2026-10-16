// Loader: moves batches from the disk queue into Postgres.
//
// Per batch, one transaction writes the intake.batch row, its audit event and
// every raw record. The batch id is the payload hash, so a batch that was
// committed but whose file survived a crash is recognised and only its file is
// removed: replays never duplicate rows. Files are deleted only after commit.

import type pg from "pg";
import { appendAudit } from "../db/audit-chain.js";
import { inTransaction } from "../db/pool.js";
import type { DiskQueue, QueuedBatch } from "./queue.js";

export interface LoaderStats { loaded: number; duplicates: number; records: number; lastError?: string; lastLoadAt?: string }

const NO_PARTITION = "23514"; // check_violation: "no partition of relation ... found for row"

export class Loader {
  readonly stats: LoaderStats = { loaded: 0, duplicates: 0, records: 0 };
  private timer?: NodeJS.Timeout;
  private running?: Promise<void>;
  private stopped = false;
  private lastPartitionCheck = 0;

  constructor(private pool: pg.Pool, private queue: DiskQueue, private intervalMs = 500, private batchLimit = 200) {}

  start() {
    this.stopped = false;
    const tick = async () => {
      if (this.stopped) return;
      this.running = this.runOnce().then(() => undefined, () => undefined);
      await this.running;
      if (!this.stopped) this.timer = setTimeout(tick, this.queue.depth() ? 0 : this.intervalMs);
    };
    this.timer = setTimeout(tick, 0);
  }

  /** Stops after the batch in progress commits. */
  async stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running;
  }

  async ensurePartitions(force = false) {
    if (!force && Date.now() - this.lastPartitionCheck < 60 * 60_000) return;
    await this.pool.query(`SELECT events.ensure_partitions(7)`);
    this.lastPartitionCheck = Date.now();
  }

  /** Loads up to batchLimit queued files; returns how many files it cleared. */
  async runOnce(): Promise<number> {
    let cleared = 0;
    try {
      await this.ensurePartitions();
      for (const name of this.queue.list(this.batchLimit)) {
        if (this.stopped) break;
        let batch: QueuedBatch;
        try {
          batch = this.queue.read(name);
        } catch {
          continue; // unreadable file: leave it for an operator; never acknowledged as loaded
        }
        try {
          await this.loadBatch(batch);
        } catch (err) {
          if ((err as { code?: string }).code !== NO_PARTITION) throw err;
          await this.ensurePartitions(true); // e.g. a batch from a day the nightly job has not reached
          await this.loadBatch(batch);
        }
        this.queue.remove(name);
        cleared++;
      }
      this.stats.lastError = undefined;
    } catch (err) {
      this.stats.lastError = (err as Error).message;
    }
    return cleared;
  }

  private async loadBatch(b: QueuedBatch) {
    await inTransaction(this.pool, async (c) => {
      const seen = await c.query(`SELECT 1 FROM intake.batch WHERE batch_id = $1`, [b.batchId]);
      if (seen.rowCount) {
        this.stats.duplicates++;
        return;
      }
      const audit = await appendAudit(c, {
        actor: `source:${b.sourceId}`,
        action: "intake.batch",
        subject: b.batchId,
        detail: { signal: b.signal, records: b.records.length, bytes: b.bytes },
      });
      await c.query(
        `INSERT INTO intake.batch (batch_id, source_id, received_at, byte_count, record_count, audit_seq)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [b.batchId, b.sourceId, b.receivedAt, b.bytes, b.records.length, audit.seq],
      );
      if (b.records.length) {
        await c.query(
          `INSERT INTO events.raw_span (batch_id, record_no, received_at, record)
           SELECT $1, t.n, $2, t.r FROM jsonb_array_elements($3::jsonb) WITH ORDINALITY AS t(r, n)`,
          [b.batchId, b.receivedAt, JSON.stringify(b.records)],
        );
      }
      await c.query(`UPDATE intake.source SET last_seen_at = $2 WHERE source_id = $1`, [b.sourceId, b.receivedAt]);
      this.stats.loaded++;
      this.stats.records += b.records.length;
      this.stats.lastLoadAt = new Date().toISOString();
    });
  }
}
