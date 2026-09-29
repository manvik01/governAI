// End-to-end demo of the context layer + multi-agent task graph, wired
// exactly as the pattern is meant to run in production:
//
//   1. Seed the Context Store with a Workflow, a Persona per role, a
//      Condition, a decision-matrix Policy rule, a Goal, Milestones and
//      Timeline events — all as rows, none of it in a prompt.
//   2. decomposeGoal(): Master Agent expands the goal's workflow into one
//      Task per step, each owned by exactly one sub-agent role.
//   3. Each "sub-agent" (simulated here — swap for a real Claude Agent SDK
//      call per role in production) claims its ready task(s), evaluates
//      the decision matrix for its own routing decision, and writes its
//      result back as the task's output. It never touches another role's
//      task.
//   4. summarizeGoal(): Master Agent rolls up the shared store/graph into
//      a summary — a read, not a recollection.
//
// No LLM calls are made here (same convention as src/demo/scenario.ts) so
// the demo runs with no API key and proves the deterministic scaffolding
// on its own. Each sub-agent step below is exactly where a real model call
// plugs in: given this task's scoped `input`, decide/draft, then call
// graph.complete() with the result.

import { existsSync, unlinkSync } from "node:fs";
import { ContextStore } from "../context/store.js";
import { evaluateMatrix } from "../context/matrix.js";
import { TaskGraph } from "../orchestration/task-graph.js";
import { decomposeGoal, summarizeGoal } from "../orchestration/master-agent.js";
import type {
  ConditionDef,
  GoalDef,
  MilestoneDef,
  PersonaDef,
  PolicyRuleDef,
  TimelineEventDef,
  WorkflowDef,
} from "../context/types.js";

const CONTEXT_DB = "./context-demo.db";
const TASK_DB = "./tasks-demo.db";

function freshDb(path: string) {
  for (const suffix of ["", "-wal", "-shm"]) {
    const p = path + suffix;
    if (existsSync(p)) unlinkSync(p);
  }
}

async function main() {
  freshDb(CONTEXT_DB);
  freshDb(TASK_DB);
  const store = new ContextStore(CONTEXT_DB);
  const graph = new TaskGraph(TASK_DB);

  section("1. Seed the context layer (workflow, persona, condition, policy, goal, milestones, timeline)");

  store.upsert<WorkflowDef>({
    entityId: "wf-enterprise-deal",
    kind: "workflow",
    domain: "sales",
    source: "stated",
    data: {
      id: "wf-enterprise-deal",
      domain: "sales",
      title: "Enterprise deal: qualify -> quote -> finance review -> close",
      steps: [
        { id: "qualify", title: "Qualify lead against discovery checklist", role: "sales", dependsOn: [], requiredConditions: ["cond-has-budget-holder"] },
        { id: "quote", title: "Draft quote", role: "sales", dependsOn: ["qualify"], requiredConditions: [] },
        { id: "finance-review", title: "Finance review of discount", role: "finance", dependsOn: ["quote"], requiredConditions: [] },
        { id: "close", title: "Close and hand off to Ops for onboarding", role: "ops", dependsOn: ["finance-review"], requiredConditions: [] },
      ],
    },
  });

  store.upsert<PersonaDef>({
    entityId: "persona-sales-agent",
    kind: "persona",
    domain: "sales",
    source: "stated",
    data: {
      id: "persona-sales-agent",
      domain: "sales",
      role: "sales",
      title: "Sales Development Agent",
      voice: "Direct, consultative, never overstates certainty about pricing",
      authorityLimits: ["Cannot approve discounts > 10% without Finance", "Cannot commit delivery dates"],
    },
  });

  store.upsert<ConditionDef>({
    entityId: "cond-has-budget-holder",
    kind: "condition",
    domain: "sales",
    source: "stated",
    data: {
      id: "cond-has-budget-holder",
      domain: "sales",
      title: "A confirmed budget holder is identified on the account",
      predicate: { path: "account.budgetHolderConfirmed", op: "eq", value: true },
    },
  });

  // Decision matrix: routing rule for the finance-review step, evaluated in
  // code (evaluateMatrix), never left to an LLM to eyeball.
  store.upsert<PolicyRuleDef>({
    entityId: "rule-discount-approval",
    kind: "policy",
    domain: "sales",
    source: "stated",
    data: {
      id: "rule-discount-approval",
      domain: "sales",
      ruleType: "approval_threshold",
      version: 1,
      when: [{ path: "discountPct", op: "gt", value: 10 }],
      action: { decision: "hold_for_approval", approver: "finance-lead" },
    },
  });

  store.upsert<GoalDef>({
    entityId: "goal-acme-q4",
    kind: "goal",
    domain: "sales",
    source: "stated",
    data: {
      id: "goal-acme-q4",
      domain: "sales",
      title: "Close Acme Corp — Q4 enterprise deal",
      ownerPersona: "persona-sales-agent",
      workflowId: "wf-enterprise-deal",
      targetMetric: "closed_won_arr",
      targetValue: 120_000,
      dueDate: "2026-12-15",
    },
  });

  store.upsert<MilestoneDef>({
    entityId: "milestone-acme-quote-sent",
    kind: "milestone",
    domain: "sales",
    source: "stated",
    data: { id: "milestone-acme-quote-sent", goalId: "goal-acme-q4", title: "Quote sent", targetDate: "2026-10-10", status: "pending" },
  });

  store.upsert<TimelineEventDef>({
    entityId: "timeline-acme-review-call",
    kind: "timeline",
    domain: "sales",
    source: "stated",
    data: {
      id: "timeline-acme-review-call",
      goalId: "goal-acme-q4",
      milestoneId: "milestone-acme-quote-sent",
      label: "Executive review call",
      occurredAt: "2026-10-08T09:00:00+08:00",
      kind: "scheduled",
    },
  });

  console.log("Seeded 1 workflow (4 steps), 1 persona, 1 condition, 1 decision-matrix rule, 1 goal, 1 milestone, 1 timeline event.");

  section("2. Master Agent decomposes the goal's workflow into per-role tasks");
  const tasks = decomposeGoal(store, graph, "goal-acme-q4");
  for (const t of tasks) {
    console.log(`  [${t.status.padEnd(9)}] ${t.role.padEnd(8)} ${t.title}  (task ${t.id}, depends on ${t.dependsOn.length ? t.dependsOn.length : "nothing"})`);
  }

  section("3. Sub-agents pick up their ready tasks and work independently");

  // --- Sales sub-agent: step "qualify" ---
  runSubAgent(graph, "sales", (task) => {
    // A real sub-agent would call get_context/conditionsHold here before
    // proceeding; the account fact would come from the Context Store too.
    console.log(`  [sales]   claimed "${task.title}" — checking required condition cond-has-budget-holder`);
    store.upsert({ entityId: "fact-acme-budget-holder", kind: "fact", domain: "sales", source: "discovery_call", data: { path: "account.budgetHolderConfirmed", value: true } });
    return { headline: "Qualified: CFO confirmed as budget holder on 2026-09-22 discovery call.", qualified: true };
  });

  // --- Sales sub-agent: step "quote" ---
  runSubAgent(graph, "sales", (task) => {
    console.log(`  [sales]   claimed "${task.title}"`);
    const discountPct = 15; // drafted quote requests a 15% discount
    const routing = evaluateMatrix(store, "sales", "approval_threshold", { discountPct });
    console.log(`            decision matrix on discountPct=${discountPct}: ${routing.matched ? JSON.stringify(routing.action) : "no rule matched"}`);
    return { headline: `Quote drafted at ${discountPct}% discount — routed to Finance for approval.`, discountPct, routedTo: routing.action?.approver };
  });

  // --- Finance sub-agent: step "finance-review" ---
  runSubAgent(graph, "finance", (task) => {
    console.log(`  [finance] claimed "${task.title}"`);
    return { headline: "Discount approved at 15% — within quarterly exception budget.", approved: true };
  });

  // --- Ops sub-agent: step "close" ---
  runSubAgent(graph, "ops", (task) => {
    console.log(`  [ops]     claimed "${task.title}"`);
    return { headline: "Deal closed-won; onboarding kicked off, CSM assigned.", onboardingStarted: true };
  });

  section("4. Master Agent reads the SAME shared store/graph to produce a summary (no private memory)");
  const summary = summarizeGoal(store, graph, "goal-acme-q4");
  console.log(JSON.stringify(summary, null, 2));

  console.log(`\nGoal complete: ${graph.isGoalComplete("goal-acme-q4")}`);
  console.log("\nEvery fact, rule, task and output above lives in context-demo.db / tasks-demo.db — nothing was held only in this process's memory. Kill this process and re-run summarizeGoal() from a fresh one and you'd get the identical object.");

  store.close();
  graph.close();
}

function runSubAgent(graph: TaskGraph, role: string, work: (task: ReturnType<TaskGraph["readyForRole"]>[number]) => Record<string, unknown>) {
  const [task] = graph.readyForRole(role);
  if (!task) {
    console.log(`  [${role}] no ready task (dependencies not yet satisfied)`);
    return;
  }
  graph.claim(task.id, `${role}-agent-1`);
  const output = work(task);
  graph.complete(task.id, output);
}

function section(title: string) {
  console.log("\n" + "=".repeat(78));
  console.log(title);
  console.log("=".repeat(78));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
