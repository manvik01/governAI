// Task Graph: where "every agent has its own sub-task" becomes a real,
// queryable structure instead of one agent silently doing everything in
// one long turn.
//
// A goal's workflow (read from the Context Store) is expanded into one
// Task row per step, each owned by exactly one sub-agent role, wired
// together by dependsOn. A sub-agent only ever sees its own task's scoped
// input; it writes its result back as that task's output — into the same
// storage the Master Agent reads, not into a private transcript. Nothing
// here is an LLM call: this is the deterministic scaffolding an LLM-backed
// sub-agent is invoked *inside of*, one task at a time.

import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import type { Task, TaskStatus } from "./types.js";

export class TaskGraph {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        goal_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        step_id TEXT NOT NULL,
        role TEXT NOT NULL,
        title TEXT NOT NULL,
        depends_on TEXT NOT NULL,
        status TEXT NOT NULL,
        input TEXT NOT NULL,
        output TEXT,
        assigned_agent_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tasks_goal ON tasks(goal_id);
      CREATE INDEX IF NOT EXISTS idx_tasks_role ON tasks(role, status);
    `);
  }

  createTask(input: {
    goalId: string;
    domain: string;
    stepId: string;
    role: string;
    title: string;
    dependsOn: string[];
    input: Record<string, unknown>;
  }): Task {
    const now = new Date().toISOString();
    const task: Task = {
      id: nanoid(),
      goalId: input.goalId,
      domain: input.domain,
      stepId: input.stepId,
      role: input.role,
      title: input.title,
      dependsOn: input.dependsOn,
      status: input.dependsOn.length === 0 ? "ready" : "pending",
      input: input.input,
      createdAt: now,
      updatedAt: now,
    };
    this.db
      .prepare(
        `INSERT INTO tasks (id, goal_id, domain, step_id, role, title, depends_on, status, input, output, assigned_agent_id, created_at, updated_at)
         VALUES (@id, @goalId, @domain, @stepId, @role, @title, @dependsOn, @status, @input, NULL, NULL, @createdAt, @updatedAt)`,
      )
      .run({
        ...task,
        dependsOn: JSON.stringify(task.dependsOn),
        input: JSON.stringify(task.input),
      });
    return task;
  }

  /** Every task for a goal, in creation order — what the Master Agent and
   * any dashboard read to see the whole run at a glance. */
  listByGoal(goalId: string): Task[] {
    const rows = this.db
      .prepare(`SELECT * FROM tasks WHERE goal_id = ? ORDER BY rowid ASC`)
      .all(goalId) as any[];
    return rows.map(rowToTask);
  }

  /** Tasks a given role can pick up right now: status "ready" and assigned
   * to that role. This is how a sub-agent asks "what's my next job" —
   * never "what was I doing last time we spoke". */
  readyForRole(role: string): Task[] {
    const rows = this.db
      .prepare(`SELECT * FROM tasks WHERE role = ? AND status = 'ready' ORDER BY rowid ASC`)
      .all(role) as any[];
    return rows.map(rowToTask);
  }

  claim(taskId: string, agentId: string): Task {
    const now = new Date().toISOString();
    this.db
      .prepare(`UPDATE tasks SET status = 'in_progress', assigned_agent_id = ?, updated_at = ? WHERE id = ?`)
      .run(agentId, now, taskId);
    return this.mustGet(taskId);
  }

  /** Sub-agent writes its result here — this IS "writing to shared memory",
   * not a message the agent remembers privately. Also promotes any
   * dependent tasks whose dependencies are now all done. */
  complete(taskId: string, output: Record<string, unknown>): Task {
    const now = new Date().toISOString();
    this.db
      .prepare(`UPDATE tasks SET status = 'done', output = ?, updated_at = ? WHERE id = ?`)
      .run(JSON.stringify(output), now, taskId);
    const task = this.mustGet(taskId);
    this.promoteReadyTasks(task.goalId);
    return task;
  }

  fail(taskId: string, reason: string): Task {
    const now = new Date().toISOString();
    this.db
      .prepare(`UPDATE tasks SET status = 'failed', output = ?, updated_at = ? WHERE id = ?`)
      .run(JSON.stringify({ error: reason }), now, taskId);
    return this.mustGet(taskId);
  }

  /** Moves every "pending" task in a goal to "ready" once all of its
   * dependsOn tasks are "done". Deterministic dependency resolution — no
   * agent has to remember or infer what unblocked it. */
  private promoteReadyTasks(goalId: string) {
    const tasks = this.listByGoal(goalId);
    const doneIds = new Set(tasks.filter((t) => t.status === "done").map((t) => t.id));
    for (const t of tasks) {
      if (t.status !== "pending") continue;
      if (t.dependsOn.every((d) => doneIds.has(d))) {
        this.db
          .prepare(`UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ?`)
          .run(new Date().toISOString(), t.id);
      }
    }
  }

  isGoalComplete(goalId: string): boolean {
    const tasks = this.listByGoal(goalId);
    return tasks.length > 0 && tasks.every((t) => t.status === "done");
  }

  private mustGet(id: string): Task {
    const row = this.db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(id) as any;
    if (!row) throw new Error(`Unknown task: ${id}`);
    return rowToTask(row);
  }

  close() {
    this.db.close();
  }
}

function rowToTask(r: any): Task {
  return {
    id: r.id,
    goalId: r.goal_id,
    domain: r.domain,
    stepId: r.step_id,
    role: r.role,
    title: r.title,
    dependsOn: JSON.parse(r.depends_on),
    status: r.status as TaskStatus,
    input: JSON.parse(r.input),
    output: r.output ? JSON.parse(r.output) : undefined,
    assignedAgentId: r.assigned_agent_id ?? undefined,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}
