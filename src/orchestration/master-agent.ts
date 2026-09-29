// Master Agent: decomposes a goal into per-role sub-tasks, and later rolls
// up their outputs into a summary. Neither half is "the master agent
// remembers what happened" — both are reads/writes against the Context
// Store and Task Graph. If this process restarts, or a different model
// serves the next call, decomposeGoal() and summarizeGoal() behave
// identically, because nothing lives in a conversation.
//
// Where an LLM belongs here: turning a Task's `output.summary` fields into
// readable prose for a human, or (inside a sub-agent, not here) turning an
// ambiguous inbound event into the structured `input` a task needs. Which
// steps exist, which role owns which step, and what "done" rolls up to —
// none of that is delegated to an LLM's judgment; it's read straight off
// the WorkflowDef and the Task rows.

import type { ContextStore } from "../context/store.js";
import type { GoalDef, MilestoneDef, TimelineEventDef, WorkflowDef } from "../context/types.js";
import type { TaskGraph } from "./task-graph.js";
import type { Task } from "./types.js";

/** Expands a goal's workflow into one Task per step, each scoped to the
 * one role that owns it. Call once per goal (idempotent re-runs would need
 * a guard — omitted here since a goal is decomposed once, at creation). */
export function decomposeGoal(store: ContextStore, graph: TaskGraph, goalId: string): Task[] {
  const goal = store.getCurrent<GoalDef>(goalId);
  if (!goal) throw new Error(`Unknown goal: ${goalId}`);

  const workflow = store.getCurrent<WorkflowDef>(goal.data.workflowId);
  if (!workflow) throw new Error(`Goal ${goalId} references unknown workflow: ${goal.data.workflowId}`);

  // Map workflow-local step ids to the task ids we create, so dependsOn
  // (expressed in step ids in the WorkflowDef) can be translated to real
  // task ids for the graph.
  const stepIdToTaskId = new Map<string, string>();
  const tasks: Task[] = [];

  for (const step of workflow.data.steps) {
    const dependsOn = step.dependsOn.map((sid) => stepIdToTaskId.get(sid)).filter((x): x is string => Boolean(x));
    const task = graph.createTask({
      goalId,
      domain: goal.domain,
      stepId: step.id,
      role: step.role,
      title: step.title,
      dependsOn,
      // Scoped input: only this step's id, the goal it serves, and the
      // condition ids it must satisfy — not the whole context store. A
      // sub-agent fetches anything else it needs itself, at act-time.
      input: {
        goalId,
        goalTitle: goal.data.title,
        stepId: step.id,
        requiredConditions: step.requiredConditions,
      },
    });
    stepIdToTaskId.set(step.id, task.id);
    tasks.push(task);
  }

  return tasks;
}

export interface GoalSummary {
  goalId: string;
  goalTitle: string;
  status: "not_started" | "in_progress" | "complete" | "blocked";
  tasks: Array<{ role: string; title: string; status: string; headline?: string }>;
  milestones: Array<{ title: string; status: string; targetDate: string }>;
  nextTimelineEvent?: { label: string; occurredAt: string };
  blockers: string[];
}

/** Deterministic rollup: reads the goal, its tasks, its milestones and its
 * next timeline event straight from shared storage. This is the entire
 * "Master Agent reads the same memory sub-agents wrote to, and produces a
 * summarized output" loop — an LLM may be handed this object afterward
 * purely to phrase it as prose; it never generates the facts inside it. */
export function summarizeGoal(store: ContextStore, graph: TaskGraph, goalId: string): GoalSummary {
  const goal = store.getCurrent<GoalDef>(goalId);
  if (!goal) throw new Error(`Unknown goal: ${goalId}`);

  const tasks = graph.listByGoal(goalId);
  const blockers = tasks
    .filter((t) => t.status === "failed" || t.status === "blocked")
    .map((t) => `${t.role}/${t.title}: ${t.status}${t.output?.error ? ` — ${t.output.error}` : ""}`);

  const status: GoalSummary["status"] =
    tasks.length === 0
      ? "not_started"
      : blockers.length > 0
        ? "blocked"
        : tasks.every((t) => t.status === "done")
          ? "complete"
          : "in_progress";

  const milestones = store
    .listCurrent<MilestoneDef>("milestone", goal.domain)
    .filter((m) => m.data.goalId === goalId)
    .map((m) => ({ title: m.data.title, status: m.data.status, targetDate: m.data.targetDate }));

  const timelineEvents = store
    .listCurrent<TimelineEventDef>("timeline", goal.domain)
    .filter((e) => e.data.goalId === goalId && e.data.kind === "scheduled")
    .sort((a, b) => a.data.occurredAt.localeCompare(b.data.occurredAt));
  const nextTimelineEvent = timelineEvents[0]
    ? { label: timelineEvents[0].data.label, occurredAt: timelineEvents[0].data.occurredAt }
    : undefined;

  return {
    goalId,
    goalTitle: goal.data.title,
    status,
    tasks: tasks.map((t) => ({
      role: t.role,
      title: t.title,
      status: t.status,
      headline: typeof t.output?.headline === "string" ? (t.output.headline as string) : undefined,
    })),
    milestones,
    nextTimelineEvent,
    blockers,
  };
}
