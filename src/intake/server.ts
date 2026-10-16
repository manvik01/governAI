// ZenAi4 intake: receives agent logs and queues them durably for the loader.
//
//   POST /v1/traces | /v1/intake/otlp/traces    OTLP traces, JSON or protobuf
//   POST /v1/logs   | /v1/intake/otlp/logs      OTLP logs, JSON or protobuf
//   POST /v1/intake/litellm                     LiteLLM standard logging payload(s)
//   GET  /healthz                               process is up
//   GET  /readyz                                database reachable, queue not backed up
//   GET  /metrics                               Prometheus text
//
// The /v1/traces and /v1/logs paths are the OTLP/HTTP defaults, so an agent's
// exporter can point at ZenAi4 with only an endpoint and a header:
//   OTEL_EXPORTER_OTLP_ENDPOINT=http://zenai4:8788
//   OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <source token>
//
// A request is answered 200 only after its batch is fsynced to the disk queue.
// Every authentication failure gets the same 401.

import "../config/env-compat.js";
import { createHash } from "node:crypto";
import express, { type Request, type Response } from "express";
import type pg from "pg";
import { createPool } from "../db/pool.js";
import { Loader } from "./loader.js";
import { parseOtlp, type SignalKind } from "./otlp.js";
import { DiskQueue } from "./queue.js";
import { redactValue } from "./redact.js";
import { SourceAuth, type Source } from "./sources.js";

export interface IntakeOptions {
  maxBodyBytes?: number;
  /** Refuse new batches (503) when the queue disk has less than this free. */
  minFreeBytes?: number;
  /** /readyz fails when the oldest queued batch is older than this. */
  maxLagMs?: number;
}

const bearer = (req: Request) => {
  const h = req.headers.authorization ?? "";
  return h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : undefined;
};

export function createIntakeApp(pool: pg.Pool, queue: DiskQueue, auth: SourceAuth, loader?: Loader, opts: IntakeOptions = {}) {
  const app = express();
  app.disable("x-powered-by");
  const maxBody = opts.maxBodyBytes ?? 16 * 1024 * 1024;
  const minFree = opts.minFreeBytes ?? 512 * 1024 * 1024;
  const counters = { accepted: 0, rejected: 0, records: 0, unauthorized: 0 };

  const raw = express.raw({ type: () => true, limit: maxBody, inflate: true });

  const authenticate = async (req: Request, res: Response): Promise<Source | null> => {
    const source = await auth.check(bearer(req));
    if (!source) {
      counters.unauthorized++;
      res.status(401).json({ error: "unauthorized" });
    }
    return source;
  };

  const accept = (res: Response, source: Source, signal: "traces" | "logs" | "litellm", body: Buffer, records: unknown[], proto: boolean) => {
    if (queue.freeBytes() < minFree) {
      counters.rejected++;
      res.set("Retry-After", "30").status(503).json({ error: "queue disk full" });
      return;
    }
    const batchId = createHash("sha256").update(source.sourceId).update("\0").update(signal).update("\0").update(body).digest("hex");
    queue.enqueue({ batchId, sourceId: source.sourceId, signal, receivedAt: new Date().toISOString(), bytes: body.length, records: records as never });
    counters.accepted++;
    counters.records += records.length;
    // OTLP/HTTP success: an empty Export*ServiceResponse in the request's encoding.
    if (proto) res.status(200).type("application/x-protobuf").end(Buffer.alloc(0));
    else res.status(200).json({});
  };

  const otlp = (signal: SignalKind) => async (req: Request, res: Response) => {
    const source = await authenticate(req, res);
    if (!source) return;
    if (source.kind !== "otlp" && source.kind !== "file" && source.kind !== "syslog") {
      res.status(403).json({ error: "this source token is not for OTLP" });
      return;
    }
    const ct = String(req.headers["content-type"] ?? "application/json");
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    let records;
    try {
      records = parseOtlp(signal, ct, body);
    } catch {
      counters.rejected++;
      res.status(400).json({ error: `body is not an OTLP ${signal} request` });
      return;
    }
    try {
      accept(res, source, signal, body, records, /protobuf/i.test(ct));
    } catch (err) {
      counters.rejected++;
      res.set("Retry-After", "5").status(503).json({ error: "could not queue batch", detail: (err as Error).message });
    }
  };

  for (const p of ["/v1/traces", "/v1/intake/otlp/traces"]) app.post(p, raw, otlp("traces"));
  for (const p of ["/v1/logs", "/v1/intake/otlp/logs"]) app.post(p, raw, otlp("logs"));

  app.post("/v1/intake/litellm", raw, async (req, res) => {
    const source = await authenticate(req, res);
    if (!source) return;
    if (source.kind !== "litellm") {
      res.status(403).json({ error: "this source token is not for LiteLLM" });
      return;
    }
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    let parsed: unknown;
    try { parsed = JSON.parse(body.toString("utf8")); } catch {
      counters.rejected++;
      res.status(400).json({ error: "body is not JSON" });
      return;
    }
    const items = (Array.isArray(parsed) ? parsed : [parsed]).filter((x) => x && typeof x === "object");
    const records = items.map((x) => ({ kind: "litellm", payload: redactValue(x) }));
    try {
      accept(res, source, "litellm", body, records, false);
    } catch (err) {
      counters.rejected++;
      res.set("Retry-After", "5").status(503).json({ error: "could not queue batch", detail: (err as Error).message });
    }
  });

  app.get("/healthz", (_req, res) => res.json({ ok: true }));

  app.get("/readyz", async (_req, res) => {
    let db = false;
    try { await pool.query("SELECT 1"); db = true; } catch { /* reported below */ }
    const depth = queue.depth();
    const lagMs = queue.oldestAgeMs();
    const ok = db && lagMs < (opts.maxLagMs ?? 15 * 60_000);
    res.status(ok ? 200 : 503).json({ ok, database: db, queueDepth: depth, queueLagMs: lagMs, loader: loader?.stats });
  });

  app.get("/metrics", (_req, res) => {
    const s = loader?.stats;
    res.type("text/plain").send([
      `zenai4_intake_batches_accepted_total ${counters.accepted}`,
      `zenai4_intake_batches_rejected_total ${counters.rejected}`,
      `zenai4_intake_records_accepted_total ${counters.records}`,
      `zenai4_intake_unauthorized_total ${counters.unauthorized}`,
      `zenai4_queue_depth ${queue.depth()}`,
      `zenai4_queue_lag_seconds ${(queue.oldestAgeMs() / 1000).toFixed(1)}`,
      `zenai4_loader_batches_loaded_total ${s?.loaded ?? 0}`,
      `zenai4_loader_batches_duplicate_total ${s?.duplicates ?? 0}`,
      `zenai4_loader_records_loaded_total ${s?.records ?? 0}`,
      `zenai4_loader_error ${s?.lastError ? 1 : 0}`,
      "",
    ].join("\n"));
  });

  // Body too large or malformed encoding.
  app.use((err: any, _req: Request, res: Response, _next: express.NextFunction) => {
    counters.rejected++;
    res.status(err?.type === "entity.too.large" ? 413 : 400).json({ error: err?.type ?? "bad request" });
  });

  return app;
}

async function main() {
  const pool = createPool();
  const queue = new DiskQueue(process.env.ZENAI4_QUEUE_DIR ?? "./data/queue");
  const loader = new Loader(pool, queue);
  const app = createIntakeApp(pool, queue, new SourceAuth(pool), loader, {
    maxBodyBytes: Number(process.env.ZENAI4_INTAKE_MAX_BODY_BYTES ?? 16 * 1024 * 1024),
  });
  loader.start();
  const port = Number(process.env.ZENAI4_INTAKE_PORT ?? 8788);
  const server = app.listen(port, process.env.ZENAI4_INTAKE_HOST ?? "0.0.0.0", () =>
    process.stdout.write(`zenai4 intake listening on :${port}, queue ${queue.dir}\n`),
  );
  const shutdown = async (sig: string) => {
    process.stdout.write(`${sig}: draining\n`);
    server.close();
    await loader.stop();
    await pool.end().catch(() => undefined);
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stderr.write(`intake failed to start: ${err.message}\n`);
    process.exit(1);
  });
}
