// Disk queue between the intake endpoint and the database.
//
// A batch is acknowledged to the sender only after its file is fsynced and
// renamed into place (and the directory entry fsynced), so a crash or power loss
// after the 200 cannot lose it. The loader deletes a file only after the
// database transaction holding that batch has committed. If the database is
// slow, remote or down, files simply accumulate here.

import { closeSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statfsSync, statSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { OtlpRecord } from "./otlp.js";

export interface QueuedBatch {
  batchId: string;        // SHA-256 of source + signal + raw body: identical resends are one batch
  sourceId: string;
  signal: "traces" | "logs" | "litellm";
  receivedAt: string;
  bytes: number;
  records: Array<OtlpRecord | Record<string, unknown>>;
}

export class DiskQueue {
  constructor(public readonly dir: string) {
    mkdirSync(dir, { recursive: true });
  }

  /** Durable write; returns the file name. */
  enqueue(b: QueuedBatch): string {
    const name = `${Date.now().toString().padStart(14, "0")}-${b.batchId.slice(0, 32)}.json`;
    const tmp = join(this.dir, `.${name}.tmp`);
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, JSON.stringify(b));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, join(this.dir, name));
    const dfd = openSync(this.dir, "r");
    try { fsyncSync(dfd); } finally { closeSync(dfd); }
    return name;
  }

  /** Oldest first. Temp files from an interrupted write are ignored (never acknowledged). */
  list(limit = 1000): string[] {
    return readdirSync(this.dir).filter((f) => f.endsWith(".json") && !f.startsWith(".")).sort().slice(0, limit);
  }

  read(name: string): QueuedBatch {
    return JSON.parse(readFileSync(join(this.dir, name), "utf8"));
  }

  remove(name: string) {
    unlinkSync(join(this.dir, name));
  }

  depth(): number {
    return this.list(1_000_000).length;
  }

  oldestAgeMs(now = Date.now()): number {
    const [first] = this.list(1);
    if (!first) return 0;
    try { return now - statSync(join(this.dir, first)).mtimeMs; } catch { return 0; }
  }

  freeBytes(): number {
    const s = statfsSync(this.dir);
    return Number(s.bavail) * Number(s.bsize);
  }
}
