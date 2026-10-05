// Identity directory: who is a real, active person, and what roles they hold.
//
// Registration is only as trustworthy as the identity check behind it, so
// owner / sub-owner / reviewer are verified against a directory instead of
// being free-text emails. This SQLite directory is the POC stand-in; the
// production implementation of the same interface is an OIDC/SCIM-backed
// lookup against Entra ID / Okta / Google Workspace (so a leaver is
// deactivated in one place and every agent they own is flagged).

import Database from "better-sqlite3";

export type Role = "admin" | "security_reviewer" | "budget_admin" | "auditor" | "agent_owner";

export interface DirectoryUser {
  email: string;
  displayName: string;
  active: boolean;
  roles: Role[];
  department?: string;
}

export interface IdentityDirectory {
  lookup(email: string): DirectoryUser | undefined;
}

export class SqliteDirectory implements IdentityDirectory {
  constructor(private db: Database.Database) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS directory_users (
        email TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        active INTEGER NOT NULL,
        roles TEXT NOT NULL,
        department TEXT
      );
    `);
  }

  upsert(user: DirectoryUser) {
    this.db
      .prepare(
        `INSERT INTO directory_users (email, display_name, active, roles, department) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(email) DO UPDATE SET display_name = excluded.display_name, active = excluded.active,
           roles = excluded.roles, department = excluded.department`,
      )
      .run(user.email.toLowerCase(), user.displayName, user.active ? 1 : 0, JSON.stringify(user.roles), user.department ?? null);
  }

  deactivate(email: string) {
    this.db.prepare(`UPDATE directory_users SET active = 0 WHERE email = ?`).run(email.toLowerCase());
  }

  lookup(email: string): DirectoryUser | undefined {
    const r = this.db.prepare(`SELECT * FROM directory_users WHERE email = ?`).get(email.toLowerCase()) as any;
    return r ? { email: r.email, displayName: r.display_name, active: r.active === 1, roles: JSON.parse(r.roles), department: r.department ?? undefined } : undefined;
  }
}

export function hasRole(user: DirectoryUser | undefined, ...roles: Role[]): boolean {
  return Boolean(user && user.active && roles.some((r) => user.roles.includes(r)));
}
