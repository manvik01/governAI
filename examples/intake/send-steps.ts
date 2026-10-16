// Minimal ZenAi4 steps sender: buffers to disk, assigns per-session sequence
// numbers, retries with exponential backoff, and never drops data silently.
//
// Prefer OpenTelemetry GenAI instrumentation plus a Collector (see
// docs/phase1.1-telemetry-reconciliation.md). Use this only for an agent you
// cannot instrument with OTel, or as a reference for writing your own sender.
//
//   ZENAI4_URL=https://zenai4.internal.example.com \
//   ZENAI4_TOKEN=<agent credential gai.a.... or source token zsrc....> \
//   node --experimental-strip-types examples/intake/send-steps.ts
//
// Guarantees and limits:
//   - Every step is appended to a local JSON-lines spool before send() returns,
//     so a crash loses nothing that send() accepted.
//   - seq is assigned per session and persisted with the spool, so the server
//     can detect gaps (lost steps) and drop duplicates (re-sent steps).
//   - Batches retry on network errors, 429 and 5xx with exponential backoff and
//     jitter. 4xx other than 429 are permanent: those steps are moved to a
//     dead-letter file and COUNTED, and flush() reports them; they are never
//     discarded without a record.
//   - The server dedupes by (session, seq), so retrying a batch that actually
//     arrived is harmless.

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface Step {
  session_id: string;
  seq?: number;                       // assigned by the sender if omitted
  ts?: string;
  agent_key?: string;                 // only with a source token; an agent credential identifies itself
  type?: "model_call" | "tool_call" | "handoff" | "approval" | "error" | "other";
  tool_name?: string;
  model?: string;
  provider?: string;
  usage?: { input_tokens?: number; output_tokens?: number };
  latency_ms?: number;
  status?: "ok" | "error";
  error_class?: string;
  prompt?: unknown;                   // stored only if the source's capture mode is "redacted"
  input?: unknown;
  output?: unknown;
  policy?: { id: string; version?: number; rule?: string; decision: "allow" | "deny" | "hold_for_approval" };
}

/** Counts for ONE flush() call; StepSender.totals() has the running totals. */
export interface FlushReport {
  sent: number;
  duplicates: number;
  /** Steps the server refused permanently (moved to dead-letter). */
  deadLettered: number;
  /** Steps still spooled because the server was unreachable; retried next flush. */
  pending: number;
  lastError?: string;
}

export interface SenderOptions { url: string; token: string; dir: string; batchSize?: number; maxAttempts?: number; baseDelayMs?: number }

export class StepSender {
  private spool: string;
  private dead: string;
  private seqFile: string;
  private seqs: Record<string, number>;
  private totals = { sent: 0, duplicates: 0, deadLettered: 0 };
  private opts: SenderOptions;

  constructor(opts: SenderOptions) {
    this.opts = opts;
    mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
    this.spool = join(opts.dir, "spool.jsonl");
    this.dead = join(opts.dir, "dead-letter.jsonl");
    this.seqFile = join(opts.dir, "seq.json");
    this.seqs = existsSync(this.seqFile) ? JSON.parse(readFileSync(this.seqFile, "utf8")) : {};
  }

  /** Durably queues one step (assigning seq) and returns its seq. */
  send(step: Step): number {
    const seq = step.seq ?? (this.seqs[step.session_id] ?? -1) + 1;
    this.seqs[step.session_id] = Math.max(seq, this.seqs[step.session_id] ?? -1);
    const tmp = this.seqFile + ".tmp";
    writeFileSync(tmp, JSON.stringify(this.seqs), { mode: 0o600 });
    renameSync(tmp, this.seqFile);
    appendFileSync(this.spool, JSON.stringify({ ...step, seq, ts: step.ts ?? new Date().toISOString() }) + "\n", { mode: 0o600 });
    return seq;
  }

  /** Sends everything spooled. Safe to call repeatedly (e.g. on a timer and at exit). */
  totals() {
    return { ...this.totals };
  }

  async flush(): Promise<FlushReport> {
    const before = { ...this.totals };
    const delta = (pending: number, lastError?: string): FlushReport => ({
      sent: this.totals.sent - before.sent, duplicates: this.totals.duplicates - before.duplicates,
      deadLettered: this.totals.deadLettered - before.deadLettered, pending, lastError,
    });
    if (!existsSync(this.spool)) return delta(0);
    // Claim the spool atomically so concurrent send() calls go to a fresh file.
    const work = `${this.spool}.${Date.now()}.sending`;
    renameSync(this.spool, work);
    const lines = readFileSync(work, "utf8").split("\n").filter(Boolean);
    const size = this.opts.batchSize ?? 200;
    const unsent: string[] = [];
    let lastError: string | undefined;
    for (let i = 0; i < lines.length; i += size) {
      const chunk = lines.slice(i, i + size);
      if (unsent.length) { unsent.push(...chunk); continue; }   // server is down: keep order, stop trying
      const r = await this.post(chunk.map((l) => JSON.parse(l)));
      if (r.kind === "ok") {
        this.totals.sent += r.accepted;
        this.totals.duplicates += r.duplicates;
        // Individually rejected steps (validation errors) are dead-lettered with the reason.
        for (const e of r.errors) this.deadLetter(chunk[e.index], `rejected: ${e.reason}`);
      } else if (r.kind === "permanent") {
        lastError = r.error;
        for (const l of chunk) this.deadLetter(l, r.error);
      } else {
        lastError = r.error;
        unsent.push(...chunk);
      }
    }
    // Put back what could not be sent, ahead of anything queued meanwhile.
    if (unsent.length) {
      const newer = existsSync(this.spool) ? readFileSync(this.spool, "utf8") : "";
      writeFileSync(this.spool + ".tmp", unsent.join("\n") + "\n" + newer, { mode: 0o600 });
      renameSync(this.spool + ".tmp", this.spool);
    }
    unlinkSync(work);
    return delta(unsent.length, lastError);
  }

  private deadLetter(line: string, reason: string) {
    this.totals.deadLettered++;
    appendFileSync(this.dead, JSON.stringify({ reason, at: new Date().toISOString(), step: JSON.parse(line) }) + "\n", { mode: 0o600 });
  }

  private async post(steps: unknown[]): Promise<
    | { kind: "ok"; accepted: number; duplicates: number; errors: Array<{ index: number; reason: string }> }
    | { kind: "permanent"; error: string }
    | { kind: "retry"; error: string }
  > {
    const max = this.opts.maxAttempts ?? 6;
    const base = this.opts.baseDelayMs ?? 500;
    let error = "unknown";
    for (let attempt = 0; attempt < max; attempt++) {
      if (attempt) await new Promise((r) => setTimeout(r, Math.min(base * 2 ** attempt, 60_000) * (0.5 + Math.random())));
      try {
        const res = await fetch(`${this.opts.url.replace(/\/+$/, "")}/v1/intake/steps`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.token}` },
          body: JSON.stringify({ steps }),
        });
        const body: any = await res.json().catch(() => ({}));
        if (res.ok || res.status === 422) return { kind: "ok", accepted: body.accepted ?? 0, duplicates: body.duplicates ?? 0, errors: body.errors ?? [] };
        error = `HTTP ${res.status} ${body.error ?? ""}`.trim();
        if (res.status !== 429 && res.status < 500) return { kind: "permanent", error };
      } catch (e) {
        error = `network: ${(e as Error).message}`;
      }
    }
    return { kind: "retry", error };
  }
}

// ---- demo: three steps in one session, flushed with a visible report
if (import.meta.url === `file://${process.argv[1]}`) {
  const url = process.env.ZENAI4_URL, token = process.env.ZENAI4_TOKEN;
  if (!url || !token) {
    console.error("set ZENAI4_URL and ZENAI4_TOKEN");
    process.exit(2);
  }
  const sender = new StepSender({ url, token, dir: process.env.ZENAI4_SPOOL_DIR ?? ".zenai4-spool" });
  const session = `demo-${Date.now()}`;
  sender.send({ session_id: session, type: "model_call", model: "claude-haiku-4-5", provider: "anthropic", usage: { input_tokens: 120, output_tokens: 40 }, latency_ms: 850 });
  sender.send({ session_id: session, type: "tool_call", tool_name: "read_docs", latency_ms: 40 });
  sender.send({ session_id: session, type: "tool_call", tool_name: "export_csv", status: "error", error_class: "policy_denial", policy: { id: "exports", decision: "deny" } });
  const report = await sender.flush();
  console.log(JSON.stringify(report));
  // Non-zero exit when anything was dropped or is still pending: never silent.
  process.exit(report.deadLettered || report.pending ? 1 : 0);
}
