// Telemetry intake (phase 1.1): the write path from an authenticated caller
// to stored, redacted, registry-linked steps.
//
// Who may send: an intake SOURCE (an OpenTelemetry Collector, a log shipper)
// with its own zsrc token, or a registered, active AGENT with its Phase 1
// credential. Authentication happens in the gateway before anything here
// runs; an unauthenticated request never reaches this module.
//
// Identity: for an agent credential the agent is the credential's subject,
// never what the body says; a step naming a different agent is rejected and
// audited as an identity mismatch. For a source, each step's agent key (an
// OTel gen_ai.agent.id / service.name, or the steps API agent_key) is matched
// against the registry by agent id or manifest id. No match -> the step is
// accepted and stored as UNREGISTERED (agent_id NULL); reconciliation turns
// it into a discovery row. A match is linked; the agent's lifecycle state at
// arrival is stored on the step so a suspended/retired/expired agent's
// activity is provable later.
//
// Capture mode (per source; agent credentials use the configured default):
//   none      no payload information at all (not even sizes)
//   metadata  default: payload presence and sizes only, no text
//   redacted  text kept after the secret scrubber + PII redactor, truncated
// Reasoning/chain-of-thought text is dropped unless captureReasoning is on
// (and then only in "redacted" mode, redacted like everything else).
//
// Every batch, accepted or not, is recorded in intake_batches with its
// counts and written to the audit chain (intake.batch); the batch row holds
// the audit seq, so the two cross-reference. A step that carries a policy
// decision of deny/hold becomes a hash-chained policy violation.

import { createHash } from "node:crypto";
import { nanoid } from "nanoid";
import type { AuditLog } from "../control/audit-log.js";
import type { Ctx } from "../control/registration.js";
import type { AgentRegistry } from "../registry/registry.js";
import type { Agent } from "../types.js";
import type { CaptureMode, TelemetryConfig } from "./config.js";
import { MAPPING_VERSION, type ParsedBatch, type RawStep } from "./mapping.js";
import { cleanIdentifier, payloadChars, redactPayload, type RedactionCounts } from "./redact.js";
import type { BatchRecord, IntakeSource, StepRecord, TelemetryStore } from "./store.js";

export type IntakePrincipal =
  | { kind: "source"; source: IntakeSource }
  | { kind: "agent"; agentId: string };

export interface IntakeResult {
  batchId: string;
  accepted: number;
  duplicates: number;
  rejected: number;
  ignored: number;
  status: BatchRecord["status"];
  /** Per-item reasons safe to return to the caller (validation only). */
  errors: Array<{ index: number; reason: string }>;
}

export class IntakeService {
  constructor(
    private store: TelemetryStore,
    private registry: AgentRegistry,
    private audit: AuditLog,
    private cfg: TelemetryConfig,
    private now: () => Date = () => new Date(),
  ) {}

  private principalId(p: IntakePrincipal) {
    return p.kind === "source" ? `source:${p.source.id}` : `agent:${p.agentId}`;
  }

  private captureMode(p: IntakePrincipal): CaptureMode {
    return p.kind === "source" ? p.source.captureMode : this.cfg.defaultCaptureMode;
  }

  /** Registry match for an agent key reported by a source: agent id, or manifest id. */
  resolveAgentKey(key: string | undefined): Agent | undefined {
    if (!key) return undefined;
    const k = key.startsWith("agent:") ? key.slice(6) : key;
    return this.registry.get(k) ?? this.registry.findByManifestId(k);
  }

  private stateOf(agent: Agent): string {
    return agent.lifecycleState === "active" && this.registry.isExpired(agent) ? "expired" : agent.lifecycleState;
  }

  /** Records a batch that was refused as a whole (too large, malformed). */
  rejectBatch(p: IntakePrincipal, endpoint: "steps" | "otlp", byteCount: number, reason: string, ctx: Ctx = {}, itemCount = 0): IntakeResult {
    const batchId = nanoid(16);
    this.store.tx(() => {
      const ev = this.audit.append({
        stream: "audit", actorType: p.kind === "agent" ? "agent" : "system", actorId: this.principalId(p), action: "intake.batch", targetType: "intake_batch", targetId: batchId,
        outcome: "denied", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
        details: { endpoint, byteCount, items: itemCount, status: "rejected", reason },
      });
      this.store.insertBatch({
        id: batchId, receivedAt: this.now().toISOString(), endpoint, sourceId: p.kind === "source" ? p.source.id : undefined,
        agentId: p.kind === "agent" ? p.agentId : undefined, byteCount, stepCount: itemCount, accepted: 0, duplicates: 0, rejected: itemCount,
        ignored: 0, status: "rejected", reasons: [reason], auditSeq: ev.seq,
      });
    });
    return { batchId, accepted: 0, duplicates: 0, rejected: itemCount, ignored: 0, status: "rejected", errors: [] };
  }

  /** Stores a parsed batch. All writes for the batch are one transaction. */
  ingest(p: IntakePrincipal, endpoint: "steps" | "otlp", parsed: ParsedBatch, raw: Buffer | undefined, ctx: Ctx = {}): IntakeResult {
    const batchId = nanoid(16);
    const receivedAt = this.now().toISOString();
    const mode = this.captureMode(p);
    const scope = this.principalId(p);
    const errors = [...parsed.rejected];
    let accepted = 0, duplicates = 0, violations = 0, unregistered = 0, mismatches = 0;
    const credentialAgent = p.kind === "agent" ? this.registry.get(p.agentId) : undefined;

    this.store.tx(() => {
      parsed.steps.forEach((s, i) => {
        // ---- identity
        let agent: Agent | undefined;
        let observedKey: string;
        if (p.kind === "agent") {
          const named = s.agentKey ? this.resolveAgentKey(s.agentKey) : undefined;
          if (s.agentKey && named?.id !== p.agentId && s.agentKey !== p.agentId) {
            mismatches++;
            errors.push({ index: i, reason: "agent_key does not match the authenticated agent" });
            return;
          }
          agent = credentialAgent;
          observedKey = `agent:${p.agentId}`;
        } else {
          const key = cleanIdentifier(s.agentKey, this.cfg.piiKinds) ?? `source:${p.source.id}`;
          agent = this.resolveAgentKey(key);
          observedKey = key;
        }
        if (!agent) unregistered++;

        const sessionKey = cleanIdentifier(s.sessionKey, this.cfg.piiKinds) ?? `batch:${batchId}`;
        const sessionId = this.store.sessionIdFor(scope, sessionKey);
        const stepKey = s.seq !== undefined ? `seq:${s.seq}` : `span:${s.spanId ?? nanoid()}`;
        const counts: RedactionCounts = {};
        const payload = this.payloads(s, mode, counts);

        const rec: StepRecord = {
          id: nanoid(16), sessionId, stepKey, seq: s.seq, spanId: cleanIdentifier(s.spanId, [], 64), parentSpanId: cleanIdentifier(s.parentSpanId, [], 64),
          batchId, sourceId: p.kind === "source" ? p.source.id : undefined, agentId: agent?.id, observedAgentKey: observedKey,
          agentState: agent ? this.stateOf(agent) : undefined, ts: s.ts, receivedAt, stepType: s.stepType,
          operation: cleanIdentifier(s.operation, this.cfg.piiKinds), toolName: cleanIdentifier(s.toolName, this.cfg.piiKinds),
          model: cleanIdentifier(s.model, this.cfg.piiKinds), provider: cleanIdentifier(s.provider, this.cfg.piiKinds)?.toLowerCase(),
          inputTokens: s.inputTokens, outputTokens: s.outputTokens, totalTokens: s.totalTokens, latencyMs: s.latencyMs,
          status: s.status, errorClass: s.errorClass, captureMode: mode, ...payload.text, payloadMeta: payload.meta,
          redactionCounts: counts as Record<string, number>, mappingVersion: MAPPING_VERSION,
        };
        const outcome = this.store.insertStep(scope, sessionKey, rec);
        if (outcome === "duplicate") { duplicates++; return; }
        accepted++;

        if (s.policy && s.policy.decision !== "allow") {
          violations++;
          this.store.appendViolation({
            agentId: agent?.id, observedAgentKey: observedKey, sessionId, stepId: rec.id, policyId: cleanIdentifier(s.policy.id, this.cfg.piiKinds)!,
            policyVersion: s.policy.version, rule: cleanIdentifier(s.policy.rule, this.cfg.piiKinds), decision: s.policy.decision,
            blockedAction: this.blockedAction(rec, s, mode), source: "intake", ts: s.ts,
            details: { batchId, sourceId: rec.sourceId, agentState: rec.agentState },
          });
        }
      });

      const rejected = errors.length;
      const status: BatchRecord["status"] = accepted + duplicates === 0 && rejected > 0 ? "rejected" : rejected > 0 ? "partial" : "accepted";
      if (mismatches) {
        this.audit.append({
          stream: "audit", actorType: "agent", actorId: (p as { agentId: string }).agentId, action: "identity.mismatch", outcome: "denied",
          sourceIp: ctx.sourceIp, requestId: ctx.requestId, details: { via: "intake", batchId, steps: mismatches },
        });
      }
      const ev = this.audit.append({
        stream: "audit", actorType: p.kind === "agent" ? "agent" : "system", actorId: scope, action: "intake.batch", targetType: "intake_batch", targetId: batchId,
        outcome: status === "rejected" ? "denied" : "success", sourceIp: ctx.sourceIp, requestId: ctx.requestId,
        details: {
          endpoint, byteCount: raw?.length ?? 0, items: parsed.total, accepted, duplicates, rejected, ignored: parsed.ignored,
          unregisteredSteps: unregistered, violations, captureMode: mode, status,
        },
      });
      this.store.insertBatch({
        id: batchId, receivedAt, endpoint, sourceId: p.kind === "source" ? p.source.id : undefined, agentId: p.kind === "agent" ? p.agentId : undefined,
        byteCount: raw?.length ?? 0, payloadSha256: raw ? createHash("sha256").update(raw).digest("hex") : undefined, stepCount: parsed.total,
        accepted, duplicates, rejected, ignored: parsed.ignored, status, reasons: errors.slice(0, 50).map((e) => `#${e.index}: ${e.reason}`), auditSeq: ev.seq,
      });
    });

    const rejected = errors.length;
    const status: BatchRecord["status"] = accepted + duplicates === 0 && rejected > 0 ? "rejected" : rejected > 0 ? "partial" : "accepted";
    return { batchId, accepted, duplicates, rejected, ignored: parsed.ignored, status, errors: errors.slice(0, 100) };
  }

  /** Applies the capture mode. Returns the text columns and the metadata blob. */
  private payloads(s: RawStep, mode: CaptureMode, counts: RedactionCounts): { text: Partial<StepRecord>; meta: Record<string, unknown> } {
    if (mode === "none") return { text: {}, meta: {} };
    const fields = { prompt: s.prompt, input: s.input, output: s.output } as const;
    const meta: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(fields)) {
      const n = payloadChars(v);
      if (n !== undefined) meta[`${k}Chars`] = n;
    }
    if (s.reasoning !== undefined) meta.reasoning = this.cfg.captureReasoning && mode === "redacted" ? "captured" : "dropped";
    if (s.conventions?.length) meta.conventions = s.conventions;
    if (mode === "metadata") return { text: {}, meta };

    const opts = { piiKinds: this.cfg.piiKinds, maxChars: this.cfg.maxPayloadChars };
    const text: Partial<StepRecord> = {};
    const p = redactPayload(s.prompt, opts, counts); if (p) { text.promptRedacted = p.text; if (p.truncated) meta.promptTruncated = true; }
    const i = redactPayload(s.input, opts, counts); if (i) { text.inputRedacted = i.text; if (i.truncated) meta.inputTruncated = true; }
    const o = redactPayload(s.output, opts, counts); if (o) { text.outputRedacted = o.text; if (o.truncated) meta.outputTruncated = true; }
    if (this.cfg.captureReasoning && s.reasoning !== undefined) {
      const r = redactPayload(s.reasoning, opts, counts);
      if (r) { text.reasoningRedacted = r.text; if (r.truncated) meta.reasoningTruncated = true; }
    }
    return { text, meta };
  }

  /** What the policy stopped: tool/operation always; the (redacted) input
   * only when the source captures redacted payloads. */
  private blockedAction(rec: StepRecord, s: RawStep, mode: CaptureMode): string {
    const head = [rec.stepType, rec.toolName ?? rec.operation ?? rec.model].filter(Boolean).join(" ");
    if (mode !== "redacted") return head;
    const body = redactPayload(s.input ?? s.prompt, { piiKinds: this.cfg.piiKinds, maxChars: 512 });
    return body ? `${head}: ${body.text}` : head;
  }
}
