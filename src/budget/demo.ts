// Walkthrough of governed token consumption: one parent task fans out to
// three child agents under a shared $0.05 task budget. Shows, in order:
// admission, a fallback after a provider failure, budget exhaustion, an
// authorised top-up that grants no permissions, a policy-denied call that
// never reaches the provider, and the final itemised invoice with a trace.
//
// No API key needed: the "provider" is a local stub.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentRegistry } from "../registry/registry.js";
import { Ledger } from "../ledger/ledger.js";
import { PolicyEngine } from "../policy/engine.js";
import { Gateway } from "../gateway/gateway.js";
import { ConsoleApprovalChannel } from "../gateway/approvals.js";
import { BudgetStore } from "./budget-store.js";
import { Billing } from "./billing.js";
import { DEFAULT_PRICING } from "./pricing.js";
import { GovernedModelGateway, ProviderError, type ProviderFn } from "./model-gateway.js";

const usd = (micro: number) => `$${(micro / 1_000_000).toFixed(6)}`;
const section = (t: string) => console.log(`\n${"=".repeat(74)}\n${t}\n${"=".repeat(74)}`);

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "governai-budget-demo-"));
  const registry = new AgentRegistry();
  const ledger = new Ledger(join(dir, "ledger.db"));
  const engine = new PolicyEngine(registry, ledger);
  const gateway = new Gateway(registry, engine, ledger, new ConsoleApprovalChannel());
  const budgets = new BudgetStore(join(dir, "budget.db"));
  const billing = new Billing(budgets, DEFAULT_PRICING);
  const models = new GovernedModelGateway(registry, gateway, budgets, billing, DEFAULT_PRICING);

  engine.setPolicy({
    id: "pol-llm", version: 1, toolName: "llm_invoke", defaultDecision: "allow",
    rules: [{ kind: "parameter_threshold", field: "maxOutputTokens", greaterThan: 4000, thenDecision: "deny", reason: "max output above 4000 tokens is not allowed" }],
  });

  const mk = (name: string) =>
    registry.register({
      name, purpose: "Research sub-task", ownerEmail: "owner@example.com", businessUnit: "Ops", platform: "custom",
      modelProvider: "anthropic", modelVersion: "claude-sonnet-5", autonomyDefault: "A1", mode: "enforcement",
      permittedModels: ["claude-sonnet-5", "claude-haiku-4-5"],
      budgetPolicy: { agentLimitMicro: 5_000_000 },
      tools: [{ toolName: "llm_invoke", reversible: true, dataClasses: [] }],
    });
  const [researcher, analyst, writer] = [mk("Researcher"), mk("Analyst"), mk("Writer")];

  budgets.setBudget({ type: "task", id: "T-report" }, 50_000); // $0.05 shared by the whole task tree
  budgets.addBudgetAdmin("cfo@example.com");

  let providerCalls = 0;
  const provider: ProviderFn = async (c) => {
    providerCalls++;
    await new Promise((r) => setTimeout(r, 10));
    return { text: `answer from ${c.model}`, usage: { inputTokens: 200, outputTokens: 500 }, usageEventId: `ue-${c.idempotencyKey}` };
  };
  const base = { tenantId: "acme", principal: "alice@acme.com", taskId: "T-report.x", parentTaskId: "T-report", prompt: "p".repeat(800), maxOutputTokens: 1000 };
  budgets.registerTask("T-report");

  section("1. Three child agents run in parallel under one shared $0.05 task budget");
  const results = await Promise.all(
    [researcher, analyst, writer].map((a, i) =>
      models.invoke({ ...base, agentId: a.id, taskId: `T-report.${i}`, requestId: `fan-${i}`, models: ["claude-sonnet-5"] }, provider),
    ),
  );
  results.forEach((r, i) => console.log(`  child ${i}: ${r.status}${r.status === "completed" ? ` cost ${usd(r.costMicro)}` : ""}`));
  const b1 = budgets.getBudget({ type: "task", id: "T-report" })!;
  console.log(`  task budget: limit ${usd(b1.limitMicro!)}, spent ${usd(b1.spentMicro)}, reserved ${usd(b1.reservedMicro)}`);

  section("2. Primary model fails (no usage); fallback runs and charges the SAME task");
  const flaky: ProviderFn = async (c) => {
    if (c.model === "claude-sonnet-5") throw new ProviderError("503 overloaded", true, true);
    return provider(c);
  };
  const fb = await models.invoke({ ...base, agentId: researcher.id, taskId: "T-report.0", requestId: "fb-1", models: ["claude-sonnet-5", "claude-haiku-4-5"] }, flaky);
  console.log(`  ${fb.status} after ${"attempts" in fb ? fb.attempts : "?"} attempts`);

  section("3. Keep going until the shared budget runs out");
  let r;
  for (let i = 0; i < 6; i++) {
    r = await models.invoke({ ...base, agentId: writer.id, taskId: "T-report.2", requestId: `more-${i}`, models: ["claude-sonnet-5"] }, provider);
    if (r.status === "budget_exhausted") break;
  }
  if (r?.status === "budget_exhausted") {
    console.log(`  BUDGET EXHAUSTED at ${r.scope.type}:${r.scope.id} (limit ${usd(r.limitMicro)}, spent ${usd(r.spentMicro)}, requested ${usd(r.requestedMicro)})`);
    console.log(`  Notice : ${r.notice}`);
    console.log(`  Options: ${r.options.map((o) => `${o.action} [needs ${o.requires}]`).join("\n           ")}`);
  }

  section("4. Authorised top-up: spending resumes, permissions do NOT change");
  const grantsBefore = JSON.stringify(registry.grantsFor(writer.id));
  budgets.increaseBudget({ scope: { type: "task", id: "T-report" }, addMicro: 100_000, requestedBy: "alice@acme.com", approver: "cfo@example.com", reason: "board report deadline" });
  const resumed = await models.invoke({ ...base, agentId: writer.id, taskId: "T-report.2", requestId: "resumed", models: ["claude-sonnet-5"] }, provider);
  console.log(`  after top-up: ${resumed.status}`);
  const refund = await gateway.call({ agentId: writer.id, principal: "alice@acme.com", toolName: "issue_refund", parameters: { amount: 1 } });
  console.log(`  grants unchanged: ${JSON.stringify(registry.grantsFor(writer.id)) === grantsBefore}; ungranted tool issue_refund -> ${refund.event.decision}`);

  section("5. Policy-denied call: never reaches the provider, never touches budget");
  const callsBefore = providerCalls;
  const denied = await models.invoke({ ...base, agentId: writer.id, taskId: "T-report.2", requestId: "too-big", models: ["claude-sonnet-5"], maxOutputTokens: 9000 }, provider);
  console.log(`  ${denied.status}${denied.status === "blocked" ? ` (${denied.reason}: ${denied.detail})` : ""}`);
  console.log(`  provider calls made by this request: ${providerCalls - callsBefore}`);

  section("6. Itemised invoice (provider / governance / platform shown separately)");
  const inv = billing.invoice("acme");
  console.log(`  provider cost    ${usd(inv.providerMicro)}`);
  console.log(`  governance cost  ${usd(inv.governanceMicro)}`);
  console.log(`  platform fee     ${usd(inv.platformMicro)}`);
  console.log(`  TOTAL            ${usd(inv.totalMicro)}   (${inv.lines} billing lines, ${inv.pendingUsage.length} awaiting usage)`);
  for (const rec of billing.list("acme")) console.log(`    ${rec.requestId.padEnd(12)} ${rec.treatment.padEnd(18)} ${usd(rec.totalMicro)}`);

  const sample = billing.list("acme").find((x) => x.treatment === "completed")!;
  const t = billing.trace(sample.id)!;
  console.log(`\n  Trace of ${sample.requestId}: pricing ${t.record.pricingVersion}, usage ${t.usage.input_tokens} in / ${t.usage.output_tokens} out,`);
  console.log(`  recomputed provider cost ${usd(t.recomputedProviderMicro!)} == billed ${usd(t.record.providerMicro)}: ${t.recomputedProviderMicro === t.record.providerMicro}`);
  console.log(`  governance ledger chain intact: ${ledger.verifyChain() === -1}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
