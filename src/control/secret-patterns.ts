// Secret patterns: recognise provider API keys and ZenAi4 credentials in text
// so they can be fingerprinted and dropped, never stored.
//
// Used in three places:
//   - the GitHub discovery connector, to find leaked LLM API keys (it records
//     repo, path, line, provider and a short fingerprint - never the key);
//   - the discovery store, which scrubs every attribute before writing it;
//   - the audit log, which scrubs string values (in addition to redacting
//     sensitive-looking keys), so even a careless caller cannot persist one.
//
// Fingerprint: the first 4 hex chars of SHA-256(key). 16 bits is enough to
// tell "the same key appears in three repos" apart from "three different
// keys" at the scale of one organisation, and far too little to confirm a
// guess of a high-entropy key. It is deliberately not reversible or useful
// as a lookup into anything.

import { createHash } from "node:crypto";

export interface KeyPattern {
  provider: string;
  /** Global regex; order matters (more specific prefixes first). */
  re: RegExp;
  /** Literal fragment GitHub code search can find (it has no regex search). */
  searchHint: string;
}

export const LLM_KEY_PATTERNS: KeyPattern[] = [
  { provider: "anthropic", re: /sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g, searchHint: "sk-ant-" },
  { provider: "openai", re: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/g, searchHint: "sk-proj-" },
  { provider: "openai", re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, searchHint: "T3BlbkFJ" },
  { provider: "google", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, searchHint: "AIza" },
  { provider: "groq", re: /\bgsk_[A-Za-z0-9]{40,}\b/g, searchHint: "gsk_" },
  { provider: "huggingface", re: /\bhf_[A-Za-z0-9]{30,}\b/g, searchHint: "hf_" },
  { provider: "xai", re: /\bxai-[A-Za-z0-9]{40,}\b/g, searchHint: "xai-" },
];

/** ZenAi4's own credential format (gai.<a|u>.<keyId>.<secret>). */
const ZENAI4_TOKEN = /gai\.[au]\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}/g;
/** ZenAi4 intake-source token (zsrc.<sourceId>.<secret>), phase 1.1. */
const ZENAI4_SOURCE_TOKEN = /zsrc\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{16,}/g;
/** Generic bearer / basic auth values. */
const AUTH_HEADER = /\b(Bearer|Basic|SSWS)\s+[A-Za-z0-9._~+/=-]{16,}/g;

export const fingerprintSecret = (secret: string) => createHash("sha256").update(secret).digest("hex").slice(0, 4);

export interface KeyHit {
  provider: string;
  fingerprint: string;
  /** 1-based line number. */
  line: number;
}

/** Finds provider keys in text. Returns only non-secret facts about each hit. */
export function findKeys(text: string): KeyHit[] {
  const hits: KeyHit[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    let line = raw;
    for (const p of LLM_KEY_PATTERNS) {
      for (const m of line.matchAll(new RegExp(p.re.source, "g"))) {
        const fp = fingerprintSecret(m[0]);
        const k = `${i}:${p.provider}:${fp}`;
        if (!seen.has(k)) {
          seen.add(k);
          hits.push({ provider: p.provider, fingerprint: fp, line: i + 1 });
        }
      }
      // Mask so a later, more general pattern does not match the same key again.
      line = line.replace(new RegExp(p.re.source, "g"), (s) => "#".repeat(s.length));
    }
  });
  return hits;
}

/** Replaces anything that looks like a secret with "[redacted]". */
export function scrubSecrets(s: string): string {
  let out = s;
  for (const p of LLM_KEY_PATTERNS) out = out.replace(new RegExp(p.re.source, "g"), "[redacted]");
  return out.replace(ZENAI4_TOKEN, "[redacted]").replace(ZENAI4_SOURCE_TOKEN, "[redacted]").replace(AUTH_HEADER, "$1 [redacted]");
}

/** Deep-scrubs any JSON-like value. */
export function scrubValue<T>(v: T): T {
  if (typeof v === "string") return scrubSecrets(v) as T;
  if (Array.isArray(v)) return v.map(scrubValue) as T;
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, scrubValue(x)])) as T;
  }
  return v;
}
