// Credentials: how agents and humans prove who they are to the gateway.
//
// Token format:  gai.<a|u>.<keyId>.<secret>
//   keyId  public lookup id
//   secret 256 random bits; only its SHA-256 hash is stored, so a database
//          leak does not leak usable credentials. The plaintext is shown
//          exactly once, at issue/rotate time.
// Verification is constant-time, honours expiry and revocation, and returns
// a machine reason that is logged internally but never shown to the caller
// (the gateway answers every failure with the same 401).
//
// Production: agent identity moves to short-lived tokens minted by an
// identity service (mTLS / SPIFFE-style workload identity, OAuth2 client
// credentials), and human tokens become OIDC JWTs. The verify() contract
// below is what the gateway depends on, so that swap is local to this file.

import Database from "better-sqlite3";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { nanoid } from "nanoid";

export type CredentialKind = "agent" | "user";
export type VerifyFailure = "malformed" | "unknown_key" | "bad_secret" | "revoked" | "expired";
export type VerifyResult =
  | { ok: true; kind: CredentialKind; subject: string; keyId: string }
  | { ok: false; reason: VerifyFailure; subject?: string };

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export class CredentialService {
  constructor(
    private db: Database.Database,
    private now: () => Date = () => new Date(),
  ) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS credentials (
        key_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        subject TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        revoked_reason TEXT,
        last_used_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_cred_subject ON credentials(kind, subject);
    `);
  }

  private issue(kind: CredentialKind, subject: string, ttlMs: number) {
    const keyId = nanoid(12);
    const secret = randomBytes(32).toString("base64url");
    const created = this.now();
    const expiresAt = new Date(created.getTime() + ttlMs).toISOString();
    this.db
      .prepare(`INSERT INTO credentials (key_id, kind, subject, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(keyId, kind, subject, sha(secret), created.toISOString(), expiresAt);
    return { token: `gai.${kind === "agent" ? "a" : "u"}.${keyId}.${secret}`, keyId, expiresAt };
  }

  issueAgentCredential(agentId: string, ttlDays = 90) {
    return this.issue("agent", agentId, ttlDays * 86_400_000);
  }

  /** Stand-in for an OIDC login: mints a short-lived token for a directory user. */
  issueUserToken(email: string, ttlMinutes = 8 * 60) {
    return this.issue("user", email.toLowerCase(), ttlMinutes * 60_000);
  }

  /** Issues a fresh credential and revokes every earlier one for the agent. */
  rotateAgentCredential(agentId: string, reason = "rotated", ttlDays = 90) {
    this.revokeAll("agent", agentId, reason);
    return this.issueAgentCredential(agentId, ttlDays);
  }

  revokeAll(kind: CredentialKind, subject: string, reason: string): number {
    return this.db
      .prepare(`UPDATE credentials SET revoked_at = ?, revoked_reason = ? WHERE kind = ? AND subject = ? AND revoked_at IS NULL`)
      .run(this.now().toISOString(), reason, kind, subject).changes;
  }

  verify(token: string | undefined): VerifyResult {
    const parts = (token ?? "").split(".");
    if (parts.length !== 4 || parts[0] !== "gai" || (parts[1] !== "a" && parts[1] !== "u") || !parts[2] || !parts[3]) {
      return { ok: false, reason: "malformed" };
    }
    const [, k, keyId, secret] = parts;
    const row = this.db.prepare(`SELECT * FROM credentials WHERE key_id = ?`).get(keyId) as any;
    if (!row || row.kind !== (k === "a" ? "agent" : "user")) return { ok: false, reason: "unknown_key" };

    const given = Buffer.from(sha(secret), "hex");
    const stored = Buffer.from(row.secret_hash, "hex");
    if (given.length !== stored.length || !timingSafeEqual(given, stored)) return { ok: false, reason: "bad_secret", subject: row.subject };
    if (row.revoked_at) return { ok: false, reason: "revoked", subject: row.subject };
    if (new Date(row.expires_at) <= this.now()) return { ok: false, reason: "expired", subject: row.subject };

    this.db.prepare(`UPDATE credentials SET last_used_at = ? WHERE key_id = ?`).run(this.now().toISOString(), keyId);
    return { ok: true, kind: row.kind, subject: row.subject, keyId };
  }

  /** For tests/inspection only: proves plaintext secrets are never stored. */
  storedHashes(): string[] {
    return (this.db.prepare(`SELECT secret_hash FROM credentials`).all() as any[]).map((r) => r.secret_hash);
  }
}
