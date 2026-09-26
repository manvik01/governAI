// Demo scenario: "a support agent issuing refunds" — the exact flow from
// the product spec's user-flow #3, run end to end against real code.
//
// It shows:
//   1. Registering an agent with a capability grant (default-deny elsewhere).
//   2. A policy with three rule types: a simple allow, a parameter threshold
//      that requires approval, and a STATEFUL daily cumulative cap (the
//      main technical differentiator described in the spec).
//   3. An approval being requested and then resolved by a human.
//   4. The evidence ledger answering an audit question and verifying its
//      own hash chain has not been tampered with.

import { ConsoleApprovalChannel } from "../gateway/approvals.js";
import type { ActionRequest } from "../types.js";
import type { Gateway } from "../gateway/gateway.js";
import { buildDemoWorld } from "./setup.js";
import { unlinkSync, existsSync } from "node:fs";

const DB_PATH = "./demo-ledger.db";

async function main() {
  // Fresh ledger each run so the demo is repeatable.
  if (existsSync(DB_PATH)) unlinkSync(DB_PATH);

  section("1. Register the agent and its policy");
  const { registry, ledger, gateway, agent, policy } = buildDemoWorld(
    DB_PATH,
    new ConsoleApprovalChannel(),
  );
  console.log(`Registered agent ${agent.id} (${agent.name})`);
  console.log(`Risk tier: ${agent.riskTier} | Lifecycle: ${agent.lifecycleState}`);
  console.log(`Policy ${policy.id} v${policy.version} set for tool "issue_refund"`);
  console.log("  Rule 1: refunds > SGD 200 -> hold for approval (per-call)");
  console.log("  Rule 2 (stateful): cumulative approved refunds > SGD 1,000/day -> deny");
  // buildDemoWorld already registers, risk-tiers, security-approves the
  // agent, and installs the policy above — see src/demo/setup.ts, which is
  // shared with the MCP server so both paths govern identically.

  section("2. Run refund requests through the gateway");
  const runId = "run-" + Date.now();

  await runCall(gateway, agent.id, runId, 150, "cust-001"); // -> allow
  await runCall(gateway, agent.id, runId, 800, "cust-002"); // -> hold for approval

  // Resolve that hold as a human would in Slack/Teams.
  const held = await runCall(gateway, agent.id, runId, 900, "cust-003"); // -> hold (another one)
  if (held.pendingApproval) {
    section("3a. A manager approves the SGD 900 refund in Slack/Teams");
    gateway.resolveApproval(
      held.pendingApproval.id,
      "manager@example.com",
      true,
      "Verified against the original order; approved.",
      { agentId: agent.id, principal: "cust-003", toolName: "issue_refund", parameters: { amount: 900 } },
      runId,
    );
    console.log("Approval resolved: APPROVED by manager@example.com");
  }

  // Running total so far: 150 (allowed) + 900 (approved) = 1,050.
  // Another refund now must be blocked automatically by the stateful rule,
  // even though 150 alone was well under the per-call threshold.
  await runCall(gateway, agent.id, runId, 100, "cust-004"); // -> deny (cumulative cap)

  section("4. Ask the ledger an audit question");
  const events = ledger.forAgent(agent.id);
  console.log(`Total events logged for ${agent.name}: ${events.length}`);
  console.log("\nDate/time                 | Decision           | Rule triggered                          | Latency");
  console.log("-".repeat(110));
  for (const e of [...events].reverse()) {
    console.log(
      `${e.timestamp} | ${pad(e.decision, 18)} | ${pad(e.ruleTriggered ?? "-", 40)} | ${e.latencyMs.toFixed(2)}ms`,
    );
  }

  section("5. Verify the evidence ledger has not been tampered with");
  const brokenAt = ledger.verifyChain();
  if (brokenAt === -1) {
    console.log("Hash chain intact: every event's hash matches its recorded predecessor.");
  } else {
    console.log(`TAMPER DETECTED at event index ${brokenAt}`);
  }

  section("6. Kill switch");
  registry.suspend(agent.id, "Demo: showing kill switch");
  console.log(`Agent lifecycle is now "${registry.get(agent.id)!.lifecycleState}"`);
  const afterSuspend = await gateway.call({
    agentId: agent.id,
    principal: "cust-005",
    toolName: "issue_refund",
    parameters: { amount: 50 },
  }, runId);
  console.log(
    `Call after suspend -> allowed: ${afterSuspend.allowed} (reason logged in ledger event ${afterSuspend.event.id})`,
  );

  ledger.close();
  console.log("\nDemo complete. Ledger written to " + DB_PATH);
}

async function runCall(
  gateway: Gateway,
  agentId: string,
  runId: string,
  amount: number,
  principal: string,
) {
  const request: ActionRequest = {
    agentId,
    principal,
    toolName: "issue_refund",
    parameters: { amount },
  };
  const result = await gateway.call(request, runId);
  console.log(
    `Refund SGD ${amount} for ${principal} -> ${result.event.decision.toUpperCase()}` +
      (result.event.ruleTriggered ? ` (${result.event.ruleTriggered})` : ""),
  );
  return result;
}

function section(title: string) {
  console.log("\n" + "=".repeat(70));
  console.log(title);
  console.log("=".repeat(70));
}

function pad(s: string, len: number) {
  return s.length >= len ? s.slice(0, len) : s + " ".repeat(len - s.length);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
