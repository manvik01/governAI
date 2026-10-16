// Redaction at intake. Runs before anything is written to the disk queue, so
// nothing below this line ever stores prompts, outputs, secrets or personal data.
//
//   1. Content attributes (prompts, completions, messages, tool arguments) are
//      dropped unless the customer opts a source in to content capture.
//   2. Keys that name a secret are replaced with "[redacted]".
//   3. Secret-shaped and personal-data-shaped substrings in any remaining string
//      are masked.
//   4. User identifiers (enduser.id and the like) are replaced with a stable
//      pseudonym, so reports can still count "for whom" without storing who.
//
// The rules are deliberately broad: a missed field is a data leak, an extra
// dropped field is a slightly thinner report.

import { createHmac } from "node:crypto";

const CONTENT_KEY = new RegExp(
  [
    "^gen_ai\\.(prompt|completion|input\\.messages|output\\.messages|system_instructions|content|tool\\.call\\.(arguments|result))",
    "^llm\\.(input_messages|output_messages|prompts|prompt_template)",
    "^(input|output)\\.value$",
    "^traceloop\\.entity\\.(input|output)$",
    "^ai\\.(prompt|response)(\\.|$)",
    "^(messages|response|prompt|completion|input|output|choices)$",
    // Framework-specific content keys seen in recorded traces.
    "^pydantic_ai\\.(all_messages|new_messages)$",
    "^(final_result|model_request_parameters|logfire\\.msg)$",
  ].join("|"),
);
const CONTENT_EVENT = /^gen_ai\.(system|user|assistant|tool|choice|client\.inference\.operation\.details)/;
const SECRET_KEY = /secret|password|passwd|api[-_]?key|authorization|cookie|credential|(^|[._-])(access|refresh|id|auth|session|bearer)?[._-]?token$/i;
const USER_KEY = /^(enduser\.id|user\.id|user\.email|gen_ai\.request\.user|user|end_user|user_api_key_user_id|user_api_key_user_email|user_api_key_end_user_id)$/;
// LiteLLM key metadata that names, but does not contain, a key. Agent identification needs it.
const KEY_METADATA = /^user_api_key_(alias|hash|team_id|team_alias|org_id|key_alias|request_route)$/;

const MASKS: Array<[RegExp, string]> = [
  [/sk-ant-[A-Za-z0-9_-]{16,}/g, "[secret]"],
  [/sk-[A-Za-z0-9_-]{16,}/g, "[secret]"],
  [/AKIA[0-9A-Z]{16}/g, "[secret]"],
  [/gh[pousr]_[A-Za-z0-9]{30,}/g, "[secret]"],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/g, "[secret]"],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[secret]"],
  [/Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, "Bearer [secret]"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[email]"],
  [/\b[STFGM]\d{7}[A-Z]\b/g, "[nric]"],
  [/\+\d{1,3}[ -]?\d{3,4}[ -]?\d{4}\b/g, "[phone]"],
];

// Card numbers: 13-19 digits with optional separators that pass the Luhn check,
// so order ids and timestamps are not masked by mistake.
const CARD = /\b\d(?:[ -]?\d){12,18}\b/g;
function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

// Any string that looks like a serialised chat transcript is content, whatever its key.
const TRANSCRIPT = /"role"\s*:\s*"(user|assistant|system|tool|developer)"/;

export interface RedactOptions { captureContent?: boolean; salt?: string }

export function maskString(s: string): string {
  let out = s;
  for (const [re, rep] of MASKS) out = out.replace(re, rep);
  return out.replace(CARD, (m) => (luhn(m.replace(/[ -]/g, "")) ? "[card]" : m));
}

export function pseudonym(value: string, salt = process.env.ZENAI4_PSEUDONYM_SALT ?? "zenai4"): string {
  return "user:" + createHmac("sha256", salt).update(value).digest("hex").slice(0, 16);
}

/** Redacts a plain JS value (attribute map, payload) recursively. */
export function redactValue(v: unknown, opts: RedactOptions = {}, key = ""): unknown {
  if (key && !opts.captureContent && CONTENT_KEY.test(key)) return undefined;
  if (key && USER_KEY.test(key) && (typeof v === "string" || typeof v === "number")) return pseudonym(String(v), opts.salt);
  if (key && KEY_METADATA.test(key) && typeof v === "string") return maskString(v);
  if (key && SECRET_KEY.test(key) && typeof v !== "object") return "[redacted]";
  if (typeof v === "string") return !opts.captureContent && TRANSCRIPT.test(v) ? undefined : maskString(v);
  if (Array.isArray(v)) return v.map((x) => redactValue(x, opts)).filter((x) => x !== undefined);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      const r = redactValue(x, opts, k);
      if (r !== undefined) out[k] = r;
    }
    return out;
  }
  return v;
}

export function redactAttributes(attrs: Record<string, unknown>, opts: RedactOptions = {}): Record<string, unknown> {
  return (redactValue(attrs, opts) as Record<string, unknown>) ?? {};
}

export function isContentEvent(name: string | undefined): boolean {
  return !!name && CONTENT_EVENT.test(name);
}
