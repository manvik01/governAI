// Telemetry mapping (phase 1.1): turns the two wire formats intake accepts
// into one RawStep shape, before identity resolution and redaction.
//
//   POST /v1/intake/steps  ZenAi4's own JSON batch: {"steps":[...]}, snake_case,
//                          producer-assigned per-session `seq` (gaps and
//                          duplicates are detectable).
//   POST /v1/intake/otlp   OTLP/HTTP JSON traces (ExportTraceServiceRequest).
//                          Spans are mapped with the OpenTelemetry GenAI
//                          semantic conventions; spans with no GenAI, LLM or
//                          tool attributes are counted as "ignored".
//
// GenAI convention generations tolerated (the attribute names moved between
// semconv releases and between instrumentation libraries):
//
//   field          newest (semconv >= 1.37)        1.27-1.36                  oldest / OpenLLMetry / OpenInference
//   provider       gen_ai.provider.name            gen_ai.system              llm.vendor, llm.provider, llm.system
//   operation      gen_ai.operation.name           gen_ai.operation.name      llm.request.type, openinference.span.kind
//   request model  gen_ai.request.model            gen_ai.request.model       llm.request.model, llm.model_name
//   response model gen_ai.response.model           gen_ai.response.model      llm.response.model
//   input tokens   gen_ai.usage.input_tokens       gen_ai.usage.input_tokens  gen_ai.usage.prompt_tokens, llm.usage.prompt_tokens, llm.token_count.prompt
//   output tokens  gen_ai.usage.output_tokens      gen_ai.usage.output_tokens gen_ai.usage.completion_tokens, llm.usage.completion_tokens, llm.token_count.completion
//   tool           gen_ai.tool.name                gen_ai.tool.name           tool.name, llm.tool.name
//   agent          gen_ai.agent.id / .name         gen_ai.agent.id / .name    (resource) service.name
//   session        gen_ai.conversation.id          gen_ai.conversation.id     session.id, (fallback) trace id
//   prompt         gen_ai.input.messages,          events gen_ai.user.message gen_ai.prompt, gen_ai.prompt.N.content,
//                  gen_ai.system_instructions      / gen_ai.system.message    input.value, llm.prompts
//   output         gen_ai.output.messages          event gen_ai.choice        gen_ai.completion, gen_ai.completion.N.content, output.value
//   tool input     gen_ai.tool.call.arguments      -                          tool.parameters, input.value (tool spans)
//   tool output    gen_ai.tool.call.result         -                          output.value (tool spans)
//   reasoning      message parts of type           -                          gen_ai.reasoning.content
//                  "reasoning" / "thinking"
//
// ZenAi4 extensions (optional span attributes): zenai4.agent.key,
// zenai4.step.seq, zenai4.policy.id / .version / .rule / .decision.
//
// Nothing here stores anything: payload fields are carried raw to the intake
// service, which applies the source's capture mode and redaction.

import { z } from "zod";
import type { ErrorClass, PolicyDecision, StepStatus, StepType } from "./store.js";

export const MAPPING_VERSION = "zenai4-genai-1";

export interface RawStep {
  sessionKey?: string;
  seq?: number;
  spanId?: string;
  parentSpanId?: string;
  agentKey?: string;
  ts: string;
  stepType: StepType;
  operation?: string;
  toolName?: string;
  model?: string;
  provider?: string;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  latencyMs?: number;
  status: StepStatus;
  errorClass?: ErrorClass;
  prompt?: unknown;
  input?: unknown;
  output?: unknown;
  reasoning?: unknown;
  policy?: { id: string; version?: number; rule?: string; decision: PolicyDecision };
  /** Which attribute generation produced the fields (for diagnostics). */
  conventions?: string[];
}

export interface ParsedBatch {
  steps: RawStep[];
  /** Per-item errors (index + message); those items are rejected. */
  rejected: Array<{ index: number; reason: string }>;
  /** Items that were not agent telemetry (OTLP spans without GenAI attributes). */
  ignored: number;
  /** Total items seen (steps, or spans). */
  total: number;
}

// ------------------------------------------------------------------ steps API

const STEP_TYPES = ["model_call", "tool_call", "handoff", "approval", "error", "other"] as const;
const ERROR_CLASSES = ["rate_limit", "timeout", "tool_failure", "policy_denial", "runaway_loop", "cost_spike", "auth", "other"] as const;
const shortStr = z.string().trim().min(1).max(200);
const count = z.number().int().nonnegative().max(1e12);

export const stepSchema = z.object({
  session_id: shortStr,
  seq: z.number().int().nonnegative().max(1e12),
  agent_key: shortStr.optional(),
  ts: z.string().refine((s) => !Number.isNaN(Date.parse(s)), "ts must be an ISO-8601 timestamp"),
  type: z.enum(STEP_TYPES).optional(),
  operation: shortStr.optional(),
  tool_name: shortStr.optional(),
  model: shortStr.optional(),
  provider: shortStr.optional(),
  usage: z.object({ input_tokens: count.optional(), output_tokens: count.optional(), total_tokens: count.optional() }).optional(),
  latency_ms: z.number().nonnegative().max(1e9).optional(),
  status: z.enum(["ok", "error"]).optional(),
  error_class: z.enum(ERROR_CLASSES).optional(),
  prompt: z.unknown().optional(),
  input: z.unknown().optional(),
  output: z.unknown().optional(),
  reasoning: z.unknown().optional(),
  policy: z.object({
    id: shortStr,
    version: z.number().int().nonnegative().optional(),
    rule: shortStr.optional(),
    decision: z.enum(["allow", "deny", "hold_for_approval"]),
  }).optional(),
});

export const stepsBatchSchema = z.object({ steps: z.array(z.unknown()) });

/** Validates each step on its own: one bad step does not sink the batch. */
export function parseStepsBatch(body: unknown): { ok: true; batch: ParsedBatch } | { ok: false; reason: string } {
  const outer = stepsBatchSchema.safeParse(body);
  if (!outer.success) return { ok: false, reason: 'body must be JSON {"steps": [...]}' };
  const steps: RawStep[] = [];
  const rejected: ParsedBatch["rejected"] = [];
  outer.data.steps.forEach((raw, index) => {
    const r = stepSchema.safeParse(raw);
    if (!r.success) {
      rejected.push({ index, reason: r.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "step"}: ${i.message}`).join("; ") });
      return;
    }
    const s = r.data;
    const status: StepStatus = s.status ?? (s.error_class ? "error" : "ok");
    steps.push({
      sessionKey: s.session_id, seq: s.seq, agentKey: s.agent_key, ts: new Date(s.ts).toISOString(),
      stepType: s.type ?? (s.tool_name ? "tool_call" : s.model ? "model_call" : "other"),
      operation: s.operation, toolName: s.tool_name, model: s.model, provider: s.provider,
      inputTokens: s.usage?.input_tokens, outputTokens: s.usage?.output_tokens,
      totalTokens: s.usage?.total_tokens ?? sumTokens(s.usage?.input_tokens, s.usage?.output_tokens),
      latencyMs: s.latency_ms, status, errorClass: s.error_class ?? (s.policy?.decision === "deny" ? "policy_denial" : undefined),
      prompt: s.prompt, input: s.input, output: s.output, reasoning: s.reasoning,
      policy: s.policy ? { id: s.policy.id, version: s.policy.version, rule: s.policy.rule, decision: s.policy.decision } : undefined,
      conventions: ["zenai4-steps"],
    });
  });
  return { ok: true, batch: { steps, rejected, ignored: 0, total: outer.data.steps.length } };
}

const sumTokens = (a?: number, b?: number) => (a === undefined && b === undefined ? undefined : (a ?? 0) + (b ?? 0));

// ------------------------------------------------------------------ OTLP/HTTP JSON

type AnyValue = {
  stringValue?: string; intValue?: string | number; doubleValue?: number; boolValue?: boolean;
  arrayValue?: { values?: AnyValue[] }; kvlistValue?: { values?: KeyValue[] }; bytesValue?: string;
};
type KeyValue = { key: string; value?: AnyValue };

/** OTLP AnyValue -> plain JS. */
export function anyValue(v: AnyValue | undefined): unknown {
  if (!v || typeof v !== "object") return undefined;
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.intValue !== undefined) return Number(v.intValue);
  if (v.doubleValue !== undefined) return Number(v.doubleValue);
  if (v.boolValue !== undefined) return Boolean(v.boolValue);
  if (v.arrayValue) return (v.arrayValue.values ?? []).map(anyValue);
  if (v.kvlistValue) return attrs(v.kvlistValue.values);
  if (v.bytesValue !== undefined) return "[bytes]";
  return undefined;
}

export function attrs(list: KeyValue[] | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!Array.isArray(list)) return out;
  for (const kv of list.slice(0, 512)) if (kv && typeof kv.key === "string") out[kv.key] = anyValue(kv.value);
  return out;
}

const first = (a: Record<string, unknown>, keys: string[], used: Set<string>): unknown => {
  for (const k of keys) if (a[k] !== undefined && a[k] !== null && a[k] !== "") { used.add(k); return a[k]; }
  return undefined;
};
const str = (v: unknown) => (v === undefined || v === null ? undefined : typeof v === "string" ? v : JSON.stringify(v));
const int = (v: unknown) => {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
};
/** JSON-encoded attribute values (gen_ai.input.messages is often a JSON string). */
const maybeJson = (v: unknown) => {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (!(t.startsWith("[") || t.startsWith("{"))) return v;
  try { return JSON.parse(t); } catch { return v; }
};

const nanosToIso = (n: unknown): string | undefined => {
  if (n === undefined || n === null || n === "") return undefined;
  try {
    const ms = Number(BigInt(String(n)) / 1_000_000n);
    return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : undefined;
  } catch { return undefined; }
};

const GENAI_HINT = /^(gen_ai\.|llm\.|openinference\.|tool\.name$|zenai4\.)/;

/** Pulls "reasoning"/"thinking" parts out of structured messages so they can
 * be dropped (default) or redacted separately from the prompt/output. */
function splitReasoning(messages: unknown): { rest: unknown; reasoning: unknown[] } {
  const reasoning: unknown[] = [];
  const walk = (m: unknown): unknown => {
    if (Array.isArray(m)) return m.map(walk).filter((x) => x !== DROP);
    if (m && typeof m === "object") {
      const o = m as Record<string, unknown>;
      if (o.type === "reasoning" || o.type === "thinking" || o.type === "redacted_thinking") { reasoning.push(o.content ?? o.thinking ?? o.text ?? o); return DROP; }
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(o)) {
        if (k === "reasoning" || k === "reasoning_content" || k === "thinking") { reasoning.push(x); continue; }
        out[k] = walk(x);
      }
      return out;
    }
    return m;
  };
  return { rest: walk(messages), reasoning };
}
const DROP = Symbol("drop");

function operationToType(op: string | undefined, toolName: string | undefined, spanKindHint: string | undefined): StepType {
  const o = (op ?? spanKindHint ?? "").toLowerCase();
  if (o === "execute_tool" || o === "tool" || toolName) return "tool_call";
  if (["chat", "text_completion", "completion", "generate_content", "embeddings", "embedding", "llm", "chain"].includes(o)) return "model_call";
  if (["invoke_agent", "create_agent", "agent"].includes(o)) return "handoff";
  return "other";
}

function errorClassOf(errorType: string | undefined, statusMessage: string | undefined, httpStatus: number | undefined): ErrorClass {
  const s = `${errorType ?? ""} ${statusMessage ?? ""}`.toLowerCase();
  if (httpStatus === 429 || /rate.?limit|too many requests|429/.test(s)) return "rate_limit";
  if (/timeout|timed out|deadline/.test(s)) return "timeout";
  if (httpStatus === 401 || httpStatus === 403 || /unauthori[sz]ed|forbidden|auth/.test(s)) return "auth";
  if (/policy|denied|blocked|guardrail/.test(s)) return "policy_denial";
  if (/tool/.test(s)) return "tool_failure";
  return "other";
}

/** Maps one OTLP span (+ its resource attributes) to a RawStep, or undefined
 * when the span carries no agent telemetry. */
export function mapSpan(span: any, resource: Record<string, unknown>): RawStep | undefined {
  const a = attrs(span?.attributes);
  if (!Object.keys(a).some((k) => GENAI_HINT.test(k))) return undefined;
  const used = new Set<string>();

  const provider = str(first(a, ["gen_ai.provider.name", "gen_ai.system", "llm.vendor", "llm.provider", "llm.system"], used));
  const operation = str(first(a, ["gen_ai.operation.name", "llm.request.type"], used));
  const spanKindHint = str(first(a, ["openinference.span.kind"], used));
  const model = str(first(a, ["gen_ai.request.model", "gen_ai.response.model", "llm.request.model", "llm.model_name", "llm.response.model"], used));
  const inputTokens = int(first(a, ["gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens", "llm.usage.prompt_tokens", "llm.token_count.prompt"], used));
  const outputTokens = int(first(a, ["gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens", "llm.usage.completion_tokens", "llm.token_count.completion"], used));
  const totalTokens = int(first(a, ["llm.usage.total_tokens", "llm.token_count.total", "gen_ai.usage.total_tokens"], used)) ?? sumTokens(inputTokens, outputTokens);
  const toolName = str(first(a, ["gen_ai.tool.name", "tool.name", "llm.tool.name"], used));
  const agentKey = str(first(a, ["zenai4.agent.key", "gen_ai.agent.id", "gen_ai.agent.name"], used)) ?? str(resource["zenai4.agent.key"]) ?? str(resource["service.name"]);
  const sessionKey = str(first(a, ["gen_ai.conversation.id", "session.id", "gen_ai.session.id"], used)) ?? (typeof span?.traceId === "string" && span.traceId ? `trace:${span.traceId}` : undefined);
  const seq = int(first(a, ["zenai4.step.seq"], used));

  // Payloads: newest structured attributes first, then legacy flat ones, then events.
  let prompt: unknown = first(a, ["gen_ai.input.messages"], used);
  const system = first(a, ["gen_ai.system_instructions"], used);
  if (prompt === undefined) prompt = first(a, ["gen_ai.prompt", "llm.prompts", "input.value"], used);
  if (prompt === undefined) {
    const indexed = Object.keys(a).filter((k) => /^gen_ai\.prompt\.\d+\.(content|role)$/.test(k)).sort();
    if (indexed.length) { prompt = indexed.map((k) => ({ [k.split(".").pop()!]: a[k] })); indexed.forEach((k) => used.add(k)); }
  }
  let output: unknown = first(a, ["gen_ai.output.messages", "gen_ai.completion", "output.value"], used);
  if (output === undefined) {
    const indexed = Object.keys(a).filter((k) => /^gen_ai\.completion\.\d+\.(content|role)$/.test(k)).sort();
    if (indexed.length) { output = indexed.map((k) => ({ [k.split(".").pop()!]: a[k] })); indexed.forEach((k) => used.add(k)); }
  }
  const events: any[] = Array.isArray(span?.events) ? span.events.slice(0, 256) : [];
  const evPrompt: unknown[] = [];
  const evOutput: unknown[] = [];
  for (const e of events) {
    const name = String(e?.name ?? "");
    const ea = attrs(e?.attributes);
    if (/^gen_ai\.(user|system|assistant|tool)\.message$/.test(name) || name === "gen_ai.content.prompt") evPrompt.push(ea);
    if (name === "gen_ai.choice" || name === "gen_ai.content.completion") evOutput.push(ea);
    if (name === "gen_ai.client.inference.operation.details") {
      if (ea["gen_ai.input.messages"] !== undefined && prompt === undefined) prompt = ea["gen_ai.input.messages"];
      if (ea["gen_ai.output.messages"] !== undefined && output === undefined) output = ea["gen_ai.output.messages"];
    }
  }
  if (prompt === undefined && evPrompt.length) prompt = evPrompt;
  if (output === undefined && evOutput.length) output = evOutput;
  if (system !== undefined) prompt = { system: maybeJson(system), messages: maybeJson(prompt) };

  const isTool = operationToType(operation, toolName, spanKindHint) === "tool_call";
  let input: unknown = first(a, ["gen_ai.tool.call.arguments", "tool.parameters"], used);
  let toolOutput: unknown = first(a, ["gen_ai.tool.call.result"], used);
  if (isTool && input === undefined && prompt !== undefined) { input = prompt; prompt = undefined; }
  if (isTool && toolOutput === undefined && output !== undefined) { toolOutput = output; output = undefined; }

  const reasoningAttr = first(a, ["gen_ai.reasoning.content", "llm.reasoning"], used);
  const p = splitReasoning(maybeJson(prompt));
  const o = splitReasoning(maybeJson(output));
  const reasoningParts = [...(reasoningAttr !== undefined ? [reasoningAttr] : []), ...p.reasoning, ...o.reasoning];

  const start = nanosToIso(span?.startTimeUnixNano);
  const end = nanosToIso(span?.endTimeUnixNano);
  const latencyMs = start && end ? Math.max(0, Date.parse(end) - Date.parse(start)) : undefined;
  const statusCode = span?.status?.code;
  const isError = statusCode === 2 || statusCode === "STATUS_CODE_ERROR" || a["error.type"] !== undefined;
  const httpStatus = int(a["http.response.status_code"] ?? a["http.status_code"]);
  const policyId = str(first(a, ["zenai4.policy.id"], used));
  const decision = str(first(a, ["zenai4.policy.decision"], used));

  const conventions: string[] = [];
  if (used.has("gen_ai.provider.name") || used.has("gen_ai.input.messages") || used.has("gen_ai.output.messages")) conventions.push("genai>=1.37");
  if (used.has("gen_ai.system") || used.has("gen_ai.usage.input_tokens")) conventions.push("genai-1.27-1.36");
  if (used.has("gen_ai.usage.prompt_tokens") || used.has("gen_ai.prompt") || [...used].some((k) => k.startsWith("llm."))) conventions.push("genai-legacy");
  if (spanKindHint || used.has("input.value")) conventions.push("openinference");

  return {
    sessionKey, seq, spanId: str(span?.spanId), parentSpanId: str(span?.parentSpanId) || undefined, agentKey,
    ts: start ?? new Date().toISOString(),
    stepType: isError && !toolName && !model ? "error" : operationToType(operation, toolName, spanKindHint),
    operation: operation ?? spanKindHint?.toLowerCase() ?? str(span?.name)?.slice(0, 200),
    toolName, model, provider, inputTokens, outputTokens, totalTokens, latencyMs,
    status: isError ? "error" : "ok",
    errorClass: isError ? errorClassOf(str(a["error.type"]), str(span?.status?.message), httpStatus) : decision === "deny" ? "policy_denial" : undefined,
    prompt: p.rest, input, output: isTool ? toolOutput : o.rest, reasoning: reasoningParts.length ? reasoningParts : undefined,
    policy: policyId && (decision === "allow" || decision === "deny" || decision === "hold_for_approval")
      ? { id: policyId, version: int(a["zenai4.policy.version"]), rule: str(a["zenai4.policy.rule"]), decision }
      : undefined,
    conventions,
  };
}

/** Parses an ExportTraceServiceRequest (JSON encoding). */
export function parseOtlpTraces(body: unknown): { ok: true; batch: ParsedBatch } | { ok: false; reason: string } {
  const rs = (body as any)?.resourceSpans;
  if (!Array.isArray(rs)) return { ok: false, reason: "body must be an OTLP/HTTP JSON ExportTraceServiceRequest with resourceSpans" };
  const steps: RawStep[] = [];
  const rejected: ParsedBatch["rejected"] = [];
  let ignored = 0;
  let total = 0;
  for (const r of rs) {
    const resource = attrs(r?.resource?.attributes);
    const scopes = Array.isArray(r?.scopeSpans) ? r.scopeSpans : Array.isArray(r?.instrumentationLibrarySpans) ? r.instrumentationLibrarySpans : [];
    for (const s of scopes) {
      for (const span of Array.isArray(s?.spans) ? s.spans : []) {
        const index = total++;
        try {
          const step = mapSpan(span, resource);
          if (!step) { ignored++; continue; }
          if (!step.spanId) { rejected.push({ index, reason: "span has no spanId" }); continue; }
          steps.push(step);
        } catch {
          rejected.push({ index, reason: "span could not be mapped" });
        }
      }
    }
  }
  return { ok: true, batch: { steps, rejected, ignored, total } };
}

/** Number of items in a body, counted before full parsing (batch limits). */
export function itemCount(endpoint: "steps" | "otlp", body: any): number {
  if (endpoint === "steps") return Array.isArray(body?.steps) ? body.steps.length : 0;
  let n = 0;
  for (const r of Array.isArray(body?.resourceSpans) ? body.resourceSpans : []) {
    for (const s of Array.isArray(r?.scopeSpans) ? r.scopeSpans : []) n += Array.isArray(s?.spans) ? s.spans.length : 0;
  }
  return n;
}
