// Telemetry configuration (phase 1.1): one place for every knob the intake,
// redaction, retention and reconciliation code reads, so defaults are visible
// and documented together (docs/phase1.1-telemetry-reconciliation.md).
//
// Defaults are deliberately conservative:
//   - payload capture "metadata": no prompt or tool text is stored unless a
//     source is explicitly set to "redacted";
//   - reasoning / chain-of-thought text is never stored unless switched on;
//   - drift handling "alert_only": telemetry never demotes an agent on its
//     own unless an operator chooses "enforce_review".
// Every value can be set from the environment (ZENAI4_*) or passed in code.

export type CaptureMode = "none" | "metadata" | "redacted";
export const CAPTURE_MODES: readonly CaptureMode[] = ["none", "metadata", "redacted"];
export type DriftMode = "alert_only" | "enforce_review";
export type PiiKind = "email" | "phone" | "card" | "national_id";
export const PII_KINDS: readonly PiiKind[] = ["email", "phone", "card", "national_id"];

export interface TelemetryConfig {
  /** Largest accepted intake body in bytes (after decompression). */
  maxBatchBytes: number;
  /** Most steps (or spans) accepted in one batch. */
  maxBatchSteps: number;
  /** Capture mode for agent-credential intake and new sources without one. */
  defaultCaptureMode: CaptureMode;
  /** Redacted payloads are truncated to this many characters. */
  maxPayloadChars: number;
  /** Store reasoning / chain-of-thought text (redacted). Off by default. */
  captureReasoning: boolean;
  /** PII classes the redactor replaces. */
  piiKinds: PiiKind[];
  /** Step payloads older than this are nulled by the retention sweep. */
  payloadRetentionDays: number;
  /** Reconciliation interval. */
  reconcileIntervalMs: number;
  /** What drift does to an agent: alert, or alert + send to security review. */
  driftMode: DriftMode;
  /** An active agent with no activity for this many days is dormant. */
  dormantDays: number;
  /** Violations in the window at or above which the risk tier is raised. 0 = off. */
  violationThreshold: number;
  violationWindowDays: number;
  /** Tier the violation threshold raises an agent to (system-recorded override). */
  violationRaiseTier: "medium" | "high" | "critical";
  /** A sequence gap is only reported once the session has been quiet this long. */
  gapGraceMs: number;
  /** Intake requests per minute per source or agent. */
  intakeRateLimitPerMin: number;
}

export const DEFAULT_TELEMETRY_CONFIG: TelemetryConfig = {
  maxBatchBytes: 1024 * 1024,
  maxBatchSteps: 1000,
  defaultCaptureMode: "metadata",
  maxPayloadChars: 4096,
  captureReasoning: false,
  piiKinds: [...PII_KINDS],
  payloadRetentionDays: 30,
  reconcileIntervalMs: 60 * 60 * 1000,
  driftMode: "alert_only",
  dormantDays: 30,
  violationThreshold: 5,
  violationWindowDays: 30,
  violationRaiseTier: "high",
  gapGraceMs: 10 * 60 * 1000,
  intakeRateLimitPerMin: 600,
};

const num = (v: string | undefined, min: number, max: number): number | undefined => {
  if (v === undefined || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n >= min && n <= max ? n : undefined;
};

/** Reads ZENAI4_* variables; anything unset or invalid keeps its default. */
export function telemetryConfigFromEnv(env: Record<string, string | undefined> = process.env): TelemetryConfig {
  const c = { ...DEFAULT_TELEMETRY_CONFIG };
  c.maxBatchBytes = num(env.ZENAI4_INTAKE_MAX_BYTES, 1024, 64 * 1024 * 1024) ?? c.maxBatchBytes;
  c.maxBatchSteps = num(env.ZENAI4_INTAKE_MAX_STEPS, 1, 100_000) ?? c.maxBatchSteps;
  if (CAPTURE_MODES.includes(env.ZENAI4_INTAKE_CAPTURE_MODE as CaptureMode)) c.defaultCaptureMode = env.ZENAI4_INTAKE_CAPTURE_MODE as CaptureMode;
  c.maxPayloadChars = num(env.ZENAI4_PAYLOAD_MAX_CHARS, 64, 1_000_000) ?? c.maxPayloadChars;
  c.captureReasoning = env.ZENAI4_CAPTURE_REASONING === "1";
  if (env.ZENAI4_PII_REDACT !== undefined) {
    c.piiKinds = env.ZENAI4_PII_REDACT.split(",").map((s) => s.trim()).filter((s): s is PiiKind => PII_KINDS.includes(s as PiiKind));
  }
  c.payloadRetentionDays = num(env.ZENAI4_PAYLOAD_RETENTION_DAYS, 1, 3650) ?? c.payloadRetentionDays;
  const h = num(env.ZENAI4_RECONCILE_INTERVAL_HOURS, 0.01, 24 * 30);
  if (h !== undefined) c.reconcileIntervalMs = Math.round(h * 3_600_000);
  if (env.ZENAI4_DRIFT_MODE === "alert_only" || env.ZENAI4_DRIFT_MODE === "enforce_review") c.driftMode = env.ZENAI4_DRIFT_MODE;
  c.dormantDays = num(env.ZENAI4_DORMANT_DAYS, 1, 3650) ?? c.dormantDays;
  c.violationThreshold = num(env.ZENAI4_VIOLATION_THRESHOLD, 0, 1_000_000) ?? c.violationThreshold;
  c.violationWindowDays = num(env.ZENAI4_VIOLATION_WINDOW_DAYS, 1, 3650) ?? c.violationWindowDays;
  if (env.ZENAI4_VIOLATION_RAISE_TIER === "medium" || env.ZENAI4_VIOLATION_RAISE_TIER === "high" || env.ZENAI4_VIOLATION_RAISE_TIER === "critical") c.violationRaiseTier = env.ZENAI4_VIOLATION_RAISE_TIER;
  const g = num(env.ZENAI4_GAP_GRACE_MINUTES, 0, 7 * 24 * 60);
  if (g !== undefined) c.gapGraceMs = Math.round(g * 60_000);
  c.intakeRateLimitPerMin = num(env.ZENAI4_INTAKE_RATE_LIMIT_PER_MIN, 1, 1_000_000) ?? c.intakeRateLimitPerMin;
  return c;
}
