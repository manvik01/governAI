// Acceptance tests for "Governed Token Consumption and Cost Management".
// Each of the PRD's five acceptance criteria has a named test below, plus
// tests for the behaviours the PRD requires but does not phrase as criteria
// (unresolved usage, shared budgets across retries/fallbacks, exhaustion).
//
// Run: npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine } from "../policy/engine.js";
import { Gateway } from "../gateway/gateway.js";
import { BudgetStore } from "./budget-store.js";
import { Billing } from "./billing.js";
import { DEFAULT_PRICING } from "./pricing.js";
import { GovernedModelGateway, ProviderError, type ModelRequest, type ProviderFn } from "./model-gateway.js";

// ------------------------------------------------------------------ fixtures

function mkWorld() {
  const dir = mkdtempSync(join(tmpdir(), "governai-budget-"));
  const registry = new AgentRegistry();
  const ledger = new Ledger(join(dir, "ledger.db"));
  const engine = new PolicyEngine(registry, ledger);
  const gateway = new Gateway(registry, engine, ledger, { request: async () => {} });
  const budgets = new BudgetStore(join(dir, "budget.db"));
  const billing = new Billing(budgets, DEFAULT_PRICING);
  const models = new GovernedModelGateway(registry, gateway, budgets, billing, DEFAULT_PRICING);

  engine.setPolicy({
    id: "pol-llm",
    version: 3,
    toolName: "llm_invoke",
    defaultDecision: "allow",
    rules: [
      { kind: "parameter_threshold", field: "maxOutputTokens", greaterThan: 4000, thenDecision: "deny", reason: "max output above 4000 tokens is not allowed" },
      { kind: "parameter_threshold", field: "estimatedMicro", greaterThan: 50_000, thenDecision: "hold_for_approval", reason: "single call above $0.05 needs approval" },
    ],
  });

  const mkAgent = (name: string, extraTools: Array<{ toolName: string; reversible: boolean; dataClasses: string[] }> = []) => {
    const a = registry.register({
      name,
      purpose: "test agent",
      ownerEmail: "owner@example.com",
      businessUnit: "test",
      platform: "custom",
      modelProvider: "anthropic",
      modelVersion: "claude-sonnet-5",
      autonomyDefault: "A1",
      mode: "enforcement",
      permittedModels: ["claude-sonnet-5", "claude-haiku-4-5"],
      budgetPolicy: {},
      tools: [{ toolName: "llm_invoke", reversible: true, dataClasses: [] }, ...extraTools],
    });
    return a;
  };

  return { dir, registry, ledger, engine, gateway, budgets, billing, models, mkAgent };
}
type World = ReturnType<typeof mkWorld>;

const PROMPT = "x".repeat(400); // ~100 input tokens
const EST_OK_CALL = 300 + 15_000; // 100 in @ $3/M + 1000 out @ $15/M, micro-USD
const ACTUAL_OK_CALL = 300 + 6_000; // 100 in, 400 out

function req(w: World, over: Partial<ModelRequest> & { agentId: string }): ModelRequest {
  return {
    requestId: `r-${Math.random().toString(36).slice(2)}`,
    tenantId: "tenant-1",
    principal: "alice@example.com",
    taskId: "T1",
    models: ["claude-sonnet-5"],
    prompt: PROMPT,
    maxOutputTokens: 1000,
    ...over,
  };
}

function counting(opts: { delayMs?: number; usageEventId?: (n: number) => string | undefined } = {}) {
  const state = { calls: 0 };
  const fn: ProviderFn = async (c) => {
    state.calls++;
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
    return { text: "ok", usage: { inputTokens: 100, outputTokens: 400 }, usageEventId: opts.usageEventId?.(state.calls) ?? `ue-${c.idempotencyKey}` };
  };
  return { state, fn };
}

function budgetOf(w: World, type: "org" | "project" | "agent" | "task", id: string) {
  return w.budgets.getBudget({ type, id })!;
}

// ------------------------------------------------- AC1: denied never reaches provider

test("AC1: a policy-denied call never reaches the model provider and never touches budget", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("a1");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const p = counting();

  // (a) rule-based deny: maxOutputTokens above the policy cap
  const denied = await w.models.invoke(req(w, { agentId: agent.id, maxOutputTokens: 5000 }), p.fn);
  assert.equal(denied.status, "blocked");
  assert.equal((denied as any).reason, "policy_deny");

  // (b) model not on the agent's permitted list
  const wrongModel = await w.models.invoke(req(w, { agentId: agent.id, models: ["some-other-model"] }), p.fn);
  assert.equal((wrongModel as any).reason, "model_not_permitted");

  // (c) agent without the llm_invoke grant (default-deny capability check)
  const noGrant = w.registry.register({
    name: "no-grant", purpose: "x", ownerEmail: "o@example.com", businessUnit: "t", platform: "custom",
    modelProvider: "anthropic", modelVersion: "claude-sonnet-5", autonomyDefault: "A1", mode: "enforcement",
    budgetPolicy: {}, tools: [],
  });
  const ng = await w.models.invoke(req(w, { agentId: noGrant.id }), p.fn);
  assert.equal((ng as any).reason, "policy_deny");

  // (d) suspended agent
  w.registry.suspend(agent.id, "test");
  const susp = await w.models.invoke(req(w, { agentId: agent.id }), p.fn);
  assert.equal((susp as any).reason, "agent_inactive");

  assert.equal(p.state.calls, 0, "provider must never be called for a blocked request");
  const b = budgetOf(w, "task", "T1");
  assert.equal(b.reservedMicro, 0);
  assert.equal(b.spentMicro, 0);
  // Every blocked attempt is in the consumption ledger and billed at zero.
  const inv = w.billing.invoice("tenant-1");
  assert.equal(inv.totalMicro, 0);
  assert.ok(inv.lines >= 4);
});

// ------------------------------------------------- AC2: parallel children can't over-allocate

test("AC2: parallel child agents cannot over-allocate a shared task budget (in-process)", async () => {
  const w = mkWorld();
  const limit = 3 * EST_OK_CALL + 100; // room for exactly 3 concurrent worst-case reservations
  w.budgets.setBudget({ type: "task", id: "T1" }, limit);
  w.budgets.registerTask("T1");
  const agents = [0, 1, 2, 3].map((i) => w.mkAgent(`child-${i}`));
  const p = counting({ delayMs: 30 });

  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      w.models.invoke(req(w, { agentId: agents[i % 4].id, taskId: `T1.${i}`, parentTaskId: "T1", requestId: `par-${i}` }), p.fn),
    ),
  );
  const done = results.filter((r) => r.status === "completed").length;
  const exhausted = results.filter((r) => r.status === "budget_exhausted").length;
  assert.equal(done, 3);
  assert.equal(exhausted, 5);
  assert.equal(p.state.calls, 3, "only admitted calls reach the provider");

  const b = budgetOf(w, "task", "T1");
  assert.ok(b.spentMicro + b.reservedMicro <= limit);
  assert.equal(b.reservedMicro, 0, "all reservations settled");
  assert.equal(b.spentMicro, 3 * ACTUAL_OK_CALL);
});

test("AC2: parallel workers in SEPARATE OS processes cannot over-allocate either", async () => {
  const w = mkWorld();
  const est = 10_000;
  const limit = 95_000; // floor(95000/10000) = 9 admissible reservations in total
  w.budgets.setBudget({ type: "task", id: "T-race" }, limit);
  w.budgets.registerTask("T-race");
  const dbPath = join(w.dir, "budget.db");
  const worker = fileURLToPath(new URL("./race-worker.js", import.meta.url));

  const runWorker = (id: number) =>
    new Promise<number>((resolve, reject) => {
      const child = spawn(process.execPath, [worker, dbPath, String(id), "10", String(est)]);
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("close", (code) => (code === 0 ? resolve(Number(out.trim())) : reject(new Error(err))));
    });

  const wins = await Promise.all([0, 1, 2, 3, 4, 5].map(runWorker));
  const total = wins.reduce((a, b) => a + b, 0);
  assert.equal(total, 9, `expected exactly 9 reservations across 6 processes, got ${total} (${wins.join(",")})`);
  const b = budgetOf(w, "task", "T-race");
  assert.equal(b.reservedMicro, 9 * est);
  assert.ok(b.reservedMicro <= limit);
});

test("hierarchy: every level must admit; the tightest scope wins", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("h1");
  w.budgets.setBudget({ type: "org", id: "tenant-1" }, 1_000_000);
  w.budgets.setBudget({ type: "project", id: "proj-1" }, 20_000); // tightest: one call fits, two do not
  w.budgets.setBudget({ type: "agent", id: agent.id }, 500_000);
  w.budgets.setBudget({ type: "task", id: "T1" }, 500_000);
  const p = counting();
  const a = await w.models.invoke(req(w, { agentId: agent.id, projectId: "proj-1", requestId: "h-a" }), p.fn);
  assert.equal(a.status, "completed");
  const b = await w.models.invoke(req(w, { agentId: agent.id, projectId: "proj-1", requestId: "h-b" }), p.fn);
  // spent 6300 + new reservation 15300 = 21600 > 20000
  assert.equal(b.status, "budget_exhausted");
  assert.deepEqual((b as any).scope, { type: "project", id: "proj-1" });
  // Nothing was reserved at the looser scopes by the refused call.
  assert.equal(budgetOf(w, "org", "tenant-1").reservedMicro, 0);
  assert.equal(budgetOf(w, "agent", agent.id).reservedMicro, 0);
});

// ------------------------------------------------- AC3: duplicate usage => single charge

test("AC3: duplicate usage events do not create duplicate charges", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("d1");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const p = counting({ usageEventId: () => "ue-fixed" });
  const r = await w.models.invoke(req(w, { agentId: agent.id, requestId: "dup-1" }), p.fn);
  assert.equal(r.status, "completed");

  const key = "dup-1#1";
  const before = budgetOf(w, "task", "T1");
  // Replay the very same usage event several times (webhook retry, at-least-once delivery).
  for (let i = 0; i < 5; i++) {
    const out = w.budgets.reconcile({ requestId: key, usageEventId: "ue-fixed", inputTokens: 100, outputTokens: 400, actualMicro: ACTUAL_OK_CALL });
    assert.equal(out.outcome, "duplicate_ignored");
    w.billing.billReconciled(key);
  }
  const after = budgetOf(w, "task", "T1");
  assert.deepEqual(after, before, "replays must not move budget");
  assert.equal(w.billing.list("tenant-1").length, 1, "exactly one billing record");
  assert.equal(w.billing.invoice("tenant-1").providerMicro, ACTUAL_OK_CALL);

  // A DIFFERENT usage event for an already-settled request is rejected, not charged.
  const conflict = w.budgets.reconcile({ requestId: key, usageEventId: "ue-other", inputTokens: 999, outputTokens: 999, actualMicro: 999_999 });
  assert.equal(conflict.outcome, "rejected");
  assert.equal(w.billing.list("tenant-1").length, 1);

  // Replaying the same CALLER request id never calls the provider twice.
  const again = await w.models.invoke(req(w, { agentId: agent.id, requestId: "dup-1" }), p.fn);
  assert.equal(again.status, "duplicate");
  assert.equal(p.state.calls, 1);
  const ev = w.budgets.ledgerForRequest(key).map((e) => e.eventType);
  assert.ok(ev.includes("duplicate_usage_ignored"));
  assert.ok(ev.includes("conflicting_usage_rejected"));
});

// ------------------------------------------------- AC4: budget approval grants no permissions

test("AC4: a budget increase does not grant tool permissions or bypass approvals", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("p1"); // holds llm_invoke only; NO issue_refund grant
  const tight = EST_OK_CALL + 10;
  w.budgets.setBudget({ type: "task", id: "T1" }, tight);
  w.budgets.addBudgetAdmin("cfo@example.com", "task", "*");
  const p = counting();

  assert.equal((await w.models.invoke(req(w, { agentId: agent.id, requestId: "p-1" }), p.fn)).status, "completed");
  const ex = await w.models.invoke(req(w, { agentId: agent.id, requestId: "p-2" }), p.fn);
  assert.equal(ex.status, "budget_exhausted");

  const grantsBefore = JSON.stringify(w.registry.grantsFor(agent.id));
  const policyBefore = JSON.stringify(w.engine.getPolicy("llm_invoke"));

  // Only an authorised approver, and never the requester themself.
  assert.throws(() => w.budgets.increaseBudget({ scope: { type: "task", id: "T1" }, addMicro: 1_000_000, requestedBy: "alice@example.com", approver: "mallory@example.com", reason: "x" }), /not an authorised budget approver/);
  assert.throws(() => w.budgets.increaseBudget({ scope: { type: "task", id: "T1" }, addMicro: 1_000_000, requestedBy: "cfo@example.com", approver: "cfo@example.com", reason: "x" }), /Separation of duties/);
  w.budgets.increaseBudget({ scope: { type: "task", id: "T1" }, addMicro: 1_000_000, requestedBy: "alice@example.com", approver: "cfo@example.com", reason: "launch week" });

  // Spending resumes...
  assert.equal((await w.models.invoke(req(w, { agentId: agent.id, requestId: "p-3" }), p.fn)).status, "completed");
  // ...but grants and policy are byte-for-byte unchanged, and a tool the agent was never granted is still denied.
  assert.equal(JSON.stringify(w.registry.grantsFor(agent.id)), grantsBefore);
  assert.equal(JSON.stringify(w.engine.getPolicy("llm_invoke")), policyBefore);
  const refund = await w.gateway.call({ agentId: agent.id, principal: "alice@example.com", toolName: "issue_refund", parameters: { amount: 1 } });
  assert.equal(refund.allowed, false);
  assert.equal(refund.event.decision, "deny");

  // A call that policy holds for human approval stays held no matter how much budget exists.
  const held = await w.models.invoke(req(w, { agentId: agent.id, requestId: "p-4", maxOutputTokens: 4000 }), p.fn);
  assert.equal((held as any).reason, "approval_required");
  assert.equal(p.state.calls, 2);
});

// ------------------------------------------------- AC5: billed amounts trace to evidence

test("AC5: every billed amount traces to usage evidence and the applicable pricing version", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("t1");
  w.budgets.setBudget({ type: "task", id: "T1" }, 10_000_000);
  const p = counting();
  for (let i = 0; i < 4; i++) await w.models.invoke(req(w, { agentId: agent.id, requestId: `tr-${i}`, models: [i % 2 ? "claude-haiku-4-5" : "claude-sonnet-5"] }), p.fn);

  const records = w.billing.list("tenant-1");
  assert.equal(records.length, 4);
  for (const r of records) {
    const t = w.billing.trace(r.id)!;
    assert.ok(t.usage, "usage evidence exists");
    assert.ok(t.pricing && t.pricing.version === r.pricingVersion, "pricing snapshot exists for the billed version");
    assert.equal(t.recomputedProviderMicro, r.providerMicro, "provider cost recomputes from usage x snapshot rates");
    const rec = t.ledger.find((e) => e.eventType === "reconciled")!;
    assert.equal(rec.reconciledMicro, r.providerMicro);
    assert.equal(rec.pricingVersion, r.pricingVersion);
    assert.equal(rec.policyVersion, 3, "policy version is on the ledger row");
    assert.ok(rec.actionEventId, "links to the governance evidence ledger event");
    // The three components are separate and sum to the total.
    assert.equal(r.providerMicro + r.governanceMicro + r.platformMicro, r.totalMicro);
    assert.ok(r.governanceMicro > 0 && r.platformMicro > 0);
  }
});

// ------------------------------------------------- unresolved usage is never zero

test("missing usage stays unresolved: held, unbilled, null in the ledger, resolvable later", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("u1");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const noUsage: ProviderFn = async () => ({ text: "answer without usage block" });
  const r = await w.models.invoke(req(w, { agentId: agent.id, requestId: "u-1" }), noUsage);
  assert.equal(r.status, "completed_usage_unresolved");

  const b = budgetOf(w, "task", "T1");
  assert.equal(b.reservedMicro, EST_OK_CALL, "estimate stays held, not released and not zeroed");
  assert.equal(b.spentMicro, 0);
  assert.equal(w.billing.list("tenant-1").length, 0, "not billed — and not billed as zero");
  assert.equal(w.billing.invoice("tenant-1").pendingUsage.length, 1);
  const ev = w.budgets.ledgerForRequest("u-1#1").find((e) => e.eventType === "unresolved")!;
  assert.equal(ev.inputTokens, null);
  assert.equal(ev.outputTokens, null);
  assert.equal(ev.reconciledMicro, null);

  // Later the provider's usage report arrives; it resolves the reservation.
  w.budgets.reconcile({ requestId: "u-1#1", usageEventId: "late-1", inputTokens: 100, outputTokens: 400, actualMicro: ACTUAL_OK_CALL });
  w.billing.billReconciled("u-1#1");
  assert.equal(budgetOf(w, "task", "T1").reservedMicro, 0);
  assert.equal(w.billing.list("tenant-1").length, 1);
  assert.equal(w.billing.invoice("tenant-1").pendingUsage.length, 0);
});

test("an expired reservation becomes unresolved rather than being silently released", async () => {
  const w = mkWorld();
  w.budgets.setBudget({ type: "task", id: "T9" }, 1_000_000);
  w.budgets.registerTask("T9");
  w.budgets.reserve({ requestId: "exp-1#1", attempt: 1, tenantId: "tenant-1", agentId: "a", taskId: "T9", rootTaskId: "T9", provider: "anthropic", model: "claude-sonnet-5", estimatedMicro: 5_000, pricingVersion: "2026-10-v1", ttlSeconds: -1 });
  assert.equal(w.budgets.sweepExpired(), 1);
  assert.equal(w.budgets.getReservation("exp-1#1")!.status, "unresolved");
  assert.equal(budgetOf(w, "task", "T9").reservedMicro, 5_000);
});

// ------------------------------------------------- shared task budget: retries and fallbacks

test("retries and fallback-model calls charge the originating task's budget, and fallbacks still pass every check", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("f1");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const log: string[] = [];
  const flaky: ProviderFn = async (c) => {
    log.push(c.model);
    if (c.model === "claude-sonnet-5") throw new ProviderError("503 overloaded", true, true); // confirmed no usage
    return { text: "from haiku", usage: { inputTokens: 100, outputTokens: 200 }, usageEventId: `ue-${c.idempotencyKey}` };
  };
  const r = await w.models.invoke(req(w, { agentId: agent.id, requestId: "fb-1", models: ["claude-sonnet-5", "claude-haiku-4-5"] }), flaky);
  assert.equal(r.status, "completed");
  assert.deepEqual(log, ["claude-sonnet-5", "claude-sonnet-5", "claude-haiku-4-5"], "1 try + 1 retry on primary, then fallback");
  assert.equal((r as any).attempts, 3);

  // Failed-without-usage attempts are released and unbilled; the successful fallback is billed once, all on task T1.
  const b = budgetOf(w, "task", "T1");
  assert.equal(b.reservedMicro, 0);
  assert.equal(b.spentMicro, 100 + 1000); // haiku: 100in@$1/M + 200out@$5/M
  const treatments = w.billing.list("tenant-1").map((x) => x.treatment).sort();
  assert.deepEqual(treatments, ["completed", "failed_no_usage", "failed_no_usage"]);
  const rootLedger = w.budgets.ledgerForRootTask("T1");
  assert.equal(new Set(rootLedger.map((e) => e.requestId)).size, 3, "all three attempts are on the ONE root task ledger");

  // A fallback that is not on the permitted list is blocked, not quietly used to save money.
  const sneaky = await w.models.invoke(req(w, { agentId: agent.id, requestId: "fb-2", models: ["claude-sonnet-5", "cheap-unvetted-model"] }), flaky);
  assert.equal(sneaky.status, "blocked");
  assert.equal((sneaky as any).reason, "model_not_permitted");
});

test("failed call that reported partial usage is billed for that usage", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("f2");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const dropsMidStream: ProviderFn = async (c) => {
    throw new ProviderError("stream reset", false, false, { inputTokens: 100, outputTokens: 50 }, `ue-${c.idempotencyKey}`);
  };
  const r = await w.models.invoke(req(w, { agentId: agent.id, requestId: "pu-1" }), dropsMidStream);
  assert.equal(r.status, "failed");
  const rec = w.billing.list("tenant-1");
  assert.equal(rec.length, 1);
  assert.equal(rec[0].treatment, "failed_with_usage");
  assert.equal(rec[0].providerMicro, 300 + 750);
});

test("a failure with unknown usage outcome is held as unresolved, not released", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("f3");
  w.budgets.setBudget({ type: "task", id: "T1" }, 1_000_000);
  const timeout: ProviderFn = async () => {
    throw new ProviderError("timeout", false, false);
  };
  await w.models.invoke(req(w, { agentId: agent.id, requestId: "to-1" }), timeout);
  assert.equal(w.budgets.getReservation("to-1#1")!.status, "unresolved");
  assert.equal(budgetOf(w, "task", "T1").reservedMicro, EST_OK_CALL);
});

// ------------------------------------------------- budget exhaustion behaviour

test("exhaustion pauses new calls, offers increase or cancel, warns about in-flight charges; cancel stops new calls only", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("x1");
  w.budgets.setBudget({ type: "task", id: "T1" }, EST_OK_CALL + 10);
  const slow = counting({ delayMs: 40 });

  const inflight = w.models.invoke(req(w, { agentId: agent.id, requestId: "x-1" }), slow.fn);
  await new Promise((r) => setTimeout(r, 5)); // let call 1 take its reservation
  const refused = await w.models.invoke(req(w, { agentId: agent.id, requestId: "x-2" }), slow.fn);
  assert.equal(refused.status, "budget_exhausted");
  const ex = refused as Extract<typeof refused, { status: "budget_exhausted" }>;
  assert.match(ex.notice, /already in progress may still complete and incur charges/);
  assert.deepEqual(ex.options.map((o) => o.action).sort(), ["cancel_task", "increase_budget"]);
  assert.equal(slow.state.calls <= 1, true, "the refused call never reached the provider");

  // Cancel the task: new calls are blocked, but the in-flight one still settles and bills.
  w.budgets.cancelTask("T1", "alice@example.com");
  const after = await w.models.invoke(req(w, { agentId: agent.id, requestId: "x-3" }), slow.fn);
  assert.equal((after as any).reason, "task_cancelled");
  assert.equal((await inflight).status, "completed");
  assert.equal(w.billing.list("tenant-1").filter((r) => r.totalMicro > 0).length, 1);
});

// ------------------------------------------------- registration requirements

test("registration requires an owner, an approved purpose, permitted models and a budget policy", () => {
  const w = mkWorld();
  const base = {
    name: "r", purpose: "p", ownerEmail: "o@example.com", businessUnit: "t", platform: "custom", modelProvider: "anthropic",
    modelVersion: "claude-sonnet-5", autonomyDefault: "A0" as const, mode: "enforcement" as const, tools: [], budgetPolicy: {},
  };
  assert.throws(() => w.registry.register({ ...base, ownerEmail: "" }), /owner/);
  assert.throws(() => w.registry.register({ ...base, purpose: " " }), /purpose/);
  assert.throws(() => w.registry.register({ ...base, budgetPolicy: undefined as any }), /budget policy/);
  assert.throws(() => w.registry.register({ ...base, permittedModels: [] }), /permitted model/);
  assert.throws(() => w.registry.register({ ...base, budgetPolicy: { agentLimitMicro: 1.5 } }), /integer/);
  assert.deepEqual(w.registry.register(base).permittedModels, ["claude-sonnet-5"]);
});

test("registration-time budget defaults apply lazily and never overwrite an administrator's limit", async () => {
  const w = mkWorld();
  const a = w.registry.register({
    name: "bd", purpose: "p", ownerEmail: "o@example.com", businessUnit: "t", platform: "custom", modelProvider: "anthropic",
    modelVersion: "claude-sonnet-5", autonomyDefault: "A0", mode: "enforcement",
    tools: [{ toolName: "llm_invoke", reversible: true, dataClasses: [] }],
    budgetPolicy: { agentLimitMicro: 100_000, defaultTaskLimitMicro: 40_000 },
  });
  w.budgets.setBudget({ type: "task", id: "T-admin" }, 900_000); // admin-set before first use
  const p = counting();
  await w.models.invoke(req(w, { agentId: a.id, taskId: "T-default", requestId: "bd-1" }), p.fn);
  await w.models.invoke(req(w, { agentId: a.id, taskId: "T-admin", requestId: "bd-2" }), p.fn);
  assert.equal(budgetOf(w, "task", "T-default").limitMicro, 40_000);
  assert.equal(budgetOf(w, "task", "T-admin").limitMicro, 900_000);
  assert.equal(budgetOf(w, "agent", a.id).limitMicro, 100_000);
});

test("calls without a bounded maxOutputTokens are refused outright", async () => {
  const w = mkWorld();
  const agent = w.mkAgent("m1");
  await assert.rejects(() => w.models.invoke(req(w, { agentId: agent.id, maxOutputTokens: 0 }), counting().fn), /maxOutputTokens is required/);
});
