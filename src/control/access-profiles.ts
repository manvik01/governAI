// Access profiles: the ceiling an agent's requested access must fit under.
//
// A profile is defined by administrators, not by the agent's owner. At
// registration the requested tools, data classes, models and autonomy are
// checked against the chosen profile; anything outside it is refused with a
// reason, so least privilege is enforced at the door instead of reviewed
// after the fact. A profile can also force a human security review.

import Database from "better-sqlite3";
import type { AutonomyLevel } from "../types.js";

export interface AccessProfile {
  id: string;
  name: string;
  description: string;
  /** Tool names, or ["*"] for any. */
  allowedTools: string[];
  allowedDataClasses: string[];
  allowedModels: string[];
  maxAutonomy: AutonomyLevel;
  /** If true, a human security reviewer must approve before activation. */
  requiresSecurityReview: boolean;
}

const AUTONOMY_ORDER: AutonomyLevel[] = ["A0", "A1", "A2", "A3", "A4"];

export class AccessProfileStore {
  constructor(private db: Database.Database) {
    db.exec(`CREATE TABLE IF NOT EXISTS access_profiles (id TEXT PRIMARY KEY, data TEXT NOT NULL);`);
  }
  upsert(p: AccessProfile) {
    this.db.prepare(`INSERT INTO access_profiles (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`).run(p.id, JSON.stringify(p));
  }
  get(id: string): AccessProfile | undefined {
    const r = this.db.prepare(`SELECT data FROM access_profiles WHERE id = ?`).get(id) as any;
    return r ? (JSON.parse(r.data) as AccessProfile) : undefined;
  }
  list(): AccessProfile[] {
    return (this.db.prepare(`SELECT data FROM access_profiles ORDER BY id`).all() as any[]).map((r) => JSON.parse(r.data));
  }
}

/** Returns human-readable violations; empty means the request fits the profile. */
export function profileViolations(
  profile: AccessProfile,
  req: { tools: Array<{ toolName: string; dataClasses: string[] }>; models: string[]; autonomy: AutonomyLevel },
): string[] {
  const v: string[] = [];
  const anyTool = profile.allowedTools.includes("*");
  for (const t of req.tools) {
    if (!anyTool && !profile.allowedTools.includes(t.toolName)) v.push(`tool "${t.toolName}" is not permitted by profile "${profile.id}"`);
    for (const dc of t.dataClasses) {
      if (!profile.allowedDataClasses.includes(dc)) v.push(`data class "${dc}" (tool "${t.toolName}") is not permitted by profile "${profile.id}"`);
    }
  }
  for (const m of req.models) {
    if (!profile.allowedModels.includes(m)) v.push(`model "${m}" is not permitted by profile "${profile.id}"`);
  }
  if (AUTONOMY_ORDER.indexOf(req.autonomy) > AUTONOMY_ORDER.indexOf(profile.maxAutonomy)) {
    v.push(`autonomy ${req.autonomy} exceeds profile maximum ${profile.maxAutonomy}`);
  }
  return v;
}
