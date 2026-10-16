// OTLP traces and logs -> flat, redacted records.
//
// Accepts both OTLP encodings over HTTP: JSON (the Collector's otlphttp exporter
// with encoding: json, Node SDKs) and protobuf (Python and Go SDKs, the
// Collector's default). Each span or log record becomes one self-contained
// record with its resource and scope attributes folded in, which is what the
// decipher stage (phase 2) maps to canonical events.

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";
import { isContentEvent, redactAttributes, redactValue, type RedactOptions } from "./redact.js";

export type SignalKind = "traces" | "logs";

export interface SpanRecord {
  kind: "span";
  resource: Record<string, unknown>;
  scope: { name?: string; version?: string };
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  spanKind?: number;
  startTime: string;
  endTime?: string;
  startTimeUnixNano: string;
  endTimeUnixNano?: string;
  status?: { code?: number; message?: string };
  attributes: Record<string, unknown>;
  events: Array<{ name: string; time?: string; attributes: Record<string, unknown> }>;
  links: Array<{ traceId: string; spanId: string }>;
}

export interface LogRecord {
  kind: "log";
  resource: Record<string, unknown>;
  scope: { name?: string; version?: string };
  time?: string;
  timeUnixNano?: string;
  severityText?: string;
  severityNumber?: number;
  eventName?: string;
  body?: unknown;
  attributes: Record<string, unknown>;
  traceId?: string;
  spanId?: string;
}

export type OtlpRecord = SpanRecord | LogRecord;

// ---- protobuf decoding

let root: protobuf.Root | undefined;
function protoRoot(): protobuf.Root {
  if (root) return root;
  const here = dirname(fileURLToPath(import.meta.url));
  const dir = [resolve(here, "../../proto"), resolve(here, "../../../proto")].find((d) => existsSync(d));
  if (!dir) throw new Error("OTLP proto directory not found");
  const r = new protobuf.Root();
  r.resolvePath = (_origin, target) => resolve(dir, target);
  r.loadSync([
    "opentelemetry/proto/collector/trace/v1/trace_service.proto",
    "opentelemetry/proto/collector/logs/v1/logs_service.proto",
  ], { keepCase: false });
  root = r;
  return r;
}

const REQUEST_TYPE: Record<SignalKind, string> = {
  traces: "opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest",
  logs: "opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest",
};

export function decodeProtobuf(signal: SignalKind, buf: Buffer): any {
  const T = protoRoot().lookupType(REQUEST_TYPE[signal]);
  const msg = T.decode(buf);
  // Same shape as OTLP JSON: camelCase keys, 64-bit numbers as strings, bytes as hex below.
  return T.toObject(msg, { longs: String, enums: Number, bytes: Buffer, defaults: false, arrays: true });
}

// ---- normalisation (works for JSON and decoded protobuf)

const hex = (v: unknown): string => {
  if (v === undefined || v === null || v === "") return "";
  if (Buffer.isBuffer(v)) return v.toString("hex");
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  const s = String(v);
  // OTLP JSON uses hex; some emitters send base64. 32/16 hex chars are the valid lengths.
  if (/^[0-9a-f]+$/i.test(s) && (s.length === 32 || s.length === 16)) return s.toLowerCase();
  try { return Buffer.from(s, "base64").toString("hex"); } catch { return s; }
};

const iso = (nanos: unknown): string | undefined => {
  if (nanos === undefined || nanos === null || nanos === "" || nanos === "0" || nanos === 0) return undefined;
  const ms = Number(BigInt(String(nanos)) / 1_000_000n);
  return new Date(ms).toISOString();
};

export function anyValue(v: any): unknown {
  if (v === null || v === undefined) return undefined;
  if ("stringValue" in v) return v.stringValue;
  if ("boolValue" in v) return v.boolValue;
  if ("intValue" in v) { const n = Number(v.intValue); return Number.isSafeInteger(n) ? n : String(v.intValue); }
  if ("doubleValue" in v) return Number(v.doubleValue);
  if ("arrayValue" in v) return (v.arrayValue?.values ?? []).map(anyValue);
  if ("kvlistValue" in v) return attrs(v.kvlistValue?.values);
  if ("bytesValue" in v) return hex(v.bytesValue);
  return undefined;
}

export function attrs(list: any[] | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const kv of list ?? []) if (kv?.key) out[kv.key] = anyValue(kv.value);
  return out;
}

export function flattenTraces(req: any, opts: RedactOptions = {}): SpanRecord[] {
  const out: SpanRecord[] = [];
  for (const rs of req?.resourceSpans ?? []) {
    const resource = redactAttributes(attrs(rs.resource?.attributes), opts);
    for (const ss of rs.scopeSpans ?? rs.instrumentationLibrarySpans ?? []) {
      const sc = ss.scope ?? ss.instrumentationLibrary ?? {};
      const scope = { name: sc.name || undefined, version: sc.version || undefined };
      for (const s of ss.spans ?? []) {
        const traceId = hex(s.traceId);
        const spanId = hex(s.spanId);
        if (!traceId || !spanId) continue; // not a valid span; nothing to rebuild a run from
        const startTime = iso(s.startTimeUnixNano) ?? new Date().toISOString();
        out.push({
          kind: "span",
          resource,
          scope,
          traceId,
          spanId,
          parentSpanId: hex(s.parentSpanId) || undefined,
          name: String(s.name ?? ""),
          spanKind: s.kind !== undefined ? Number(s.kind) : undefined,
          startTime,
          endTime: iso(s.endTimeUnixNano),
          startTimeUnixNano: String(s.startTimeUnixNano ?? ""),
          endTimeUnixNano: s.endTimeUnixNano ? String(s.endTimeUnixNano) : undefined,
          status: s.status ? { code: s.status.code !== undefined ? Number(s.status.code) : undefined, message: s.status.message ? String(redactValue(s.status.message, opts)) : undefined } : undefined,
          attributes: redactAttributes(attrs(s.attributes), opts),
          events: (s.events ?? []).map((e: any) => ({
            name: String(e.name ?? ""),
            time: iso(e.timeUnixNano),
            attributes: !opts.captureContent && isContentEvent(e.name) ? {} : redactAttributes(attrs(e.attributes), opts),
          })),
          links: (s.links ?? []).map((l: any) => ({ traceId: hex(l.traceId), spanId: hex(l.spanId) })),
        });
      }
    }
  }
  return out;
}

export function flattenLogs(req: any, opts: RedactOptions = {}): LogRecord[] {
  const out: LogRecord[] = [];
  for (const rl of req?.resourceLogs ?? []) {
    const resource = redactAttributes(attrs(rl.resource?.attributes), opts);
    for (const sl of rl.scopeLogs ?? []) {
      const scope = { name: sl.scope?.name || undefined, version: sl.scope?.version || undefined };
      for (const l of sl.logRecords ?? []) {
        const attributes = attrs(l.attributes);
        const eventName = (l.eventName as string) || (attributes["event.name"] as string) || undefined;
        const dropBody = !opts.captureContent && isContentEvent(eventName);
        const t = l.timeUnixNano && l.timeUnixNano !== "0" ? l.timeUnixNano : l.observedTimeUnixNano;
        out.push({
          kind: "log",
          resource,
          scope,
          time: iso(t),
          timeUnixNano: t ? String(t) : undefined,
          severityText: l.severityText || undefined,
          severityNumber: l.severityNumber !== undefined ? Number(l.severityNumber) : undefined,
          eventName,
          body: dropBody ? undefined : redactValue(anyValue(l.body), opts, "body"),
          attributes: redactAttributes(attributes, opts),
          traceId: hex(l.traceId) || undefined,
          spanId: hex(l.spanId) || undefined,
        });
      }
    }
  }
  return out;
}

/** Parses one HTTP body into redacted records. Throws on anything that is not OTLP. */
export function parseOtlp(signal: SignalKind, contentType: string, body: Buffer, opts: RedactOptions = {}): OtlpRecord[] {
  const isProto = /application\/(x-)?protobuf/i.test(contentType);
  const req = isProto ? decodeProtobuf(signal, body) : JSON.parse(body.toString("utf8"));
  if (!req || typeof req !== "object") throw new Error("not an OTLP request");
  return signal === "traces" ? flattenTraces(req, opts) : flattenLogs(req, opts);
}
