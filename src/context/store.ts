// Context Store: the shared, external memory every agent reads from and
// writes to, instead of any agent holding state in its own conversation.
//
// One SQLite table, one row-shape, every kind of context entity (workflow,
// persona, condition, policy, goal, milestone, timeline, fact) stored the
// same way: versioned, append-only (a write never overwrites a row — it
// closes the old version and inserts a new one), with a source and a
// validity window. This mirrors the Ledger's append-only discipline, for
// the same reason: you must be able to prove what an agent believed to be
// true at the moment it acted, not just what's true now.
//
// "The Master Agent reads the same memory sub-agents write to" means,
// concretely: everyone reads and writes THIS table. There is no per-agent
// scratchpad. A sub-agent's job output is itself written here (as a `fact`
// or back onto the owning `goal`/`milestone`), so the Master Agent's
// summary is a query over this store, not a re-explanation from its own
// context window.

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type { ContextEntity, ContextKind } from "./types.js";

export class ContextStore {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS context_entities (
        row_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        domain TEXT NOT NULL,
        data TEXT NOT NULL,
        version INTEGER NOT NULL,
        source TEXT NOT NULL,
        confidence REAL,
        valid_from TEXT NOT NULL,
        valid_to TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_context_current
        ON context_entities(kind, domain, entity_id, valid_to);
      CREATE INDEX IF NOT EXISTS idx_context_entity_history
        ON context_entities(entity_id, version);
    `);
  }

  /** Writes a new version of an entity. Closes whichever version was
   * current (if any) as of now, then inserts the new one. Never mutates a
   * prior version in place — that history is what makes "what did this
   * agent believe when it acted" answerable later. */
  upsert<T>(input: {
    entityId: string;
    kind: ContextKind;
    domain: string;
    data: T;
    source: string;
    confidence?: number;
  }): ContextEntity<T> {
    const now = new Date().toISOString();
    const current = this.getCurrentRow(input.entityId);
    const nextVersion = (current?.version ?? 0) + 1;

    const tx = this.db.transaction(() => {
      if (current) {
        this.db
          .prepare(`UPDATE context_entities SET valid_to = ? WHERE row_id = ?`)
          .run(now, current.row_id);
      }
      const rowId = nanoid();
      this.db
        .prepare(
          `INSERT INTO context_entities
           (row_id, entity_id, kind, domain, data, version, source, confidence, valid_from, valid_to, created_at)
           VALUES (@rowId, @entityId, @kind, @domain, @data, @version, @source, @confidence, @validFrom, NULL, @createdAt)`,
        )
        .run({
          rowId,
          entityId: input.entityId,
          kind: input.kind,
          domain: input.domain,
          data: JSON.stringify(input.data),
          version: nextVersion,
          source: input.source,
          confidence: input.confidence ?? null,
          validFrom: now,
          createdAt: now,
        });
      return rowId;
    });

    const rowId = tx();
    return {
      rowId,
      entityId: input.entityId,
      kind: input.kind,
      domain: input.domain,
      data: input.data,
      version: nextVersion,
      source: input.source,
      confidence: input.confidence,
      validFrom: now,
      createdAt: now,
    };
  }

  private getCurrentRow(entityId: string): any | undefined {
    return this.db
      .prepare(`SELECT * FROM context_entities WHERE entity_id = ? AND valid_to IS NULL`)
      .get(entityId) as any | undefined;
  }

  /** The one call every agent makes before acting: "what's true right now
   * for this entity" — never answered from the agent's own memory. */
  getCurrent<T>(entityId: string): ContextEntity<T> | undefined {
    const row = this.getCurrentRow(entityId);
    return row ? rowToEntity<T>(row) : undefined;
  }

  /** Every current entity of a kind within a domain — how a sub-agent asks
   * "what workflows/policies/conditions apply to me". */
  listCurrent<T>(kind: ContextKind, domain: string): ContextEntity<T>[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM context_entities WHERE kind = ? AND domain = ? AND valid_to IS NULL ORDER BY entity_id`,
      )
      .all(kind, domain) as any[];
    return rows.map((r) => rowToEntity<T>(r));
  }

  /** Full version history for one entity, oldest first — the audit trail
   * for "what did we believe, and when did it change". */
  history<T>(entityId: string): ContextEntity<T>[] {
    const rows = this.db
      .prepare(`SELECT * FROM context_entities WHERE entity_id = ? ORDER BY version ASC`)
      .all(entityId) as any[];
    return rows.map((r) => rowToEntity<T>(r));
  }

  /** As-of query: what was current for this entity at a given timestamp.
   * Used to reconstruct exactly what an agent could have known when it
   * made a past decision, for audit replay. */
  asOf<T>(entityId: string, atIso: string): ContextEntity<T> | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM context_entities
         WHERE entity_id = ? AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)
         ORDER BY version DESC LIMIT 1`,
      )
      .get(entityId, atIso, atIso) as any | undefined;
    return row ? rowToEntity<T>(row) : undefined;
  }

  close() {
    this.db.close();
  }
}

function rowToEntity<T>(r: any): ContextEntity<T> {
  return {
    rowId: r.row_id,
    entityId: r.entity_id,
    kind: r.kind,
    domain: r.domain,
    data: JSON.parse(r.data) as T,
    version: r.version,
    source: r.source,
    confidence: r.confidence ?? undefined,
    validFrom: r.valid_from,
    validTo: r.valid_to ?? undefined,
    createdAt: r.created_at,
  };
}
