// Payload redaction for telemetry (phase 1.1).
//
// Every piece of free text that intake may keep - prompts, tool input and
// output, reasoning text (only when switched on), the action a policy
// blocked - goes through the same three steps, in this order:
//   1. secrets: the existing scrubber (provider API keys, ZenAi4 agent, user
//      and intake-source tokens, Bearer/Basic values), plus sensitive-looking
//      object keys (password, token, api_key ...) are replaced wholesale;
//   2. PII (configurable): email addresses, phone numbers, card-number-shaped
//      digit runs that pass the Luhn check, and national-ID shapes (Singapore
//      NRIC/FIN, US SSN);
//   3. truncation to a configured size, AFTER redaction, so a secret can never
//      be split by the cut and slip past the patterns.
// The output records how many of each kind were replaced, never what.
//
// Pattern matching is best effort: it catches the common shapes and errs on
// the side of over-redaction (an eight-digit Singapore phone shape or a
// Luhn-valid 16-digit order number is replaced). Capture mode "metadata"
// (the default) stores no text at all; this module matters when a source is
// switched to "redacted".

import { scrubSecrets } from "../control/secret-patterns.js";
import type { PiiKind } from "./config.js";

export interface RedactionOptions {
  piiKinds: readonly PiiKind[];
  maxChars: number;
}

export type RedactionCounts = Partial<Record<"secret" | PiiKind | "sensitive_key", number>>;

export interface RedactedText {
  text: string;
  truncated: boolean;
  originalChars: number;
  counts: RedactionCounts;
}

const SENSITIVE_KEY = /secret|token|password|passwd|api[-_]?key|authorization|credential|cookie|session[-_]?key|private[-_]?key/i;

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
// Card-number shape: 13-19 digits, optionally grouped by single spaces or hyphens.
const CARD = /(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])/g;
// National IDs: Singapore NRIC/FIN (S/T/F/G/M + 7 digits + letter), US SSN.
const NRIC = /\b[STFGMstfgm]\d{7}[A-Za-z]\b/g;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
// Phones: international (+CC ...), North American (xxx) xxx-xxxx / xxx-xxx-xxxx,
// and Singapore local 8-digit numbers starting 6/8/9 written with a separator.
const PHONE_INTL = /\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}(?:[\s.-]?\d{2,4}){1,4}/g;
const PHONE_NA = /(?:\(\d{3}\)\s?|\b\d{3}[.-])\d{3}[.-]\d{4}\b/g;
const PHONE_SG = /\b[689]\d{3}[ -]\d{4}\b/g;

/** Luhn checksum over the digits of s. */
export function luhnValid(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

function countReplace(s: string, re: RegExp, label: string, kind: keyof RedactionCounts, counts: RedactionCounts, accept?: (m: string) => boolean): string {
  return s.replace(new RegExp(re.source, re.flags), (m) => {
    if (accept && !accept(m)) return m;
    counts[kind] = (counts[kind] ?? 0) + 1;
    return label;
  });
}

/** Secrets, then PII. No truncation (see redactText). */
export function redactString(s: string, piiKinds: readonly PiiKind[], counts: RedactionCounts = {}): string {
  const scrubbed = scrubSecrets(s);
  if (scrubbed !== s) counts.secret = (counts.secret ?? 0) + (scrubbed.match(/\[redacted\]/g)?.length ?? 1) - (s.match(/\[redacted\]/g)?.length ?? 0);
  let out = scrubbed;
  const want = new Set(piiKinds);
  if (want.has("email")) out = countReplace(out, EMAIL, "[email]", "email", counts);
  // Cards before phones: a grouped card number also looks like a long phone number.
  if (want.has("card")) out = countReplace(out, CARD, "[card]", "card", counts, luhnValid);
  if (want.has("national_id")) {
    out = countReplace(out, NRIC, "[national-id]", "national_id", counts);
    out = countReplace(out, SSN, "[national-id]", "national_id", counts);
  }
  if (want.has("phone")) {
    out = countReplace(out, PHONE_INTL, "[phone]", "phone", counts);
    out = countReplace(out, PHONE_NA, "[phone]", "phone", counts);
    out = countReplace(out, PHONE_SG, "[phone]", "phone", counts);
  }
  return out;
}

/** Deep-redacts a JSON-like value: sensitive keys are replaced wholesale,
 * strings are scrubbed. */
export function redactValue(v: unknown, piiKinds: readonly PiiKind[], counts: RedactionCounts = {}, depth = 0): unknown {
  if (depth > 32) return "[too deep]";
  if (typeof v === "string") return redactString(v, piiKinds, counts);
  if (Array.isArray(v)) return v.map((x) => redactValue(x, piiKinds, counts, depth + 1));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      if (SENSITIVE_KEY.test(k)) { out[k] = "[redacted]"; counts.sensitive_key = (counts.sensitive_key ?? 0) + 1; }
      else out[redactString(k, piiKinds, counts)] = redactValue(x, piiKinds, counts, depth + 1);
    }
    return out;
  }
  return v;
}

/** Redacts any payload (string or JSON) and truncates the result. */
export function redactPayload(v: unknown, opts: RedactionOptions, counts: RedactionCounts = {}): RedactedText | undefined {
  if (v === undefined || v === null) return undefined;
  const redacted = redactValue(v, opts.piiKinds, counts);
  const text = typeof redacted === "string" ? redacted : JSON.stringify(redacted);
  if (text === undefined) return undefined;
  const truncated = text.length > opts.maxChars;
  return {
    text: truncated ? `${text.slice(0, opts.maxChars)}…[truncated ${text.length - opts.maxChars} chars]` : text,
    truncated,
    originalChars: text.length,
    counts,
  };
}

/** Size of a payload in characters, without keeping it (capture mode "metadata"). */
export function payloadChars(v: unknown): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v.length;
  try { return JSON.stringify(v)?.length; } catch { return undefined; }
}

/** Short identifiers (tool, model, session ids, agent keys): secrets and PII
 * scrubbed, length capped. */
export function cleanIdentifier(s: unknown, piiKinds: readonly PiiKind[], max = 200): string | undefined {
  if (s === undefined || s === null) return undefined;
  const str = String(s).trim();
  if (!str) return undefined;
  return redactString(str, piiKinds).slice(0, max);
}
