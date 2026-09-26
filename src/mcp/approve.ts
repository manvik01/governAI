// Out-of-band approval CLI: simulates the manager who approves or rejects a
// held refund from OUTSIDE the agent process — the same separation of
// duties the product spec calls for (the agent cannot approve its own
// request). This talks directly to the shared SQLite ledger, not through
// MCP, because a human approving in Slack/Teams is a separate system from
// the agent's tool calls in the real architecture too (see the gateway
// section of the product spec: "Approval requests sent to Slack or Teams").
//
// Usage:
//   npm run mcp:approve -- list
//   npm run mcp:approve -- decide <approvalId> approve [approver] [reason]
//   npm run mcp:approve -- decide <approvalId> reject  [approver] [reason]

import { Ledger } from "../ledger/ledger.js";
import type { ActionRequest } from "../types.js";

const DB_PATH = process.env.GOVERNAI_DB_PATH ?? "./mcp-ledger.db";

function usage(): never {
  console.error("Usage:");
  console.error("  npm run mcp:approve -- list");
  console.error("  npm run mcp:approve -- decide <approvalId> approve|reject [approver] [reason]");
  process.exit(1);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const ledger = new Ledger(DB_PATH);

  if (cmd === "list") {
    const pending = ledger.listPendingApprovals();
    if (pending.length === 0) {
      console.log("No pending approvals.");
    } else {
      console.log("Pending approvals:");
      for (const p of pending) {
        const event = ledger.getEventById(p.actionEventId);
        console.log(
          `  ${p.id}  requested ${p.requestedAt}  ` +
            (event
              ? `agent=${event.agentId} principal=${event.principal} tool=${event.toolName} params=${event.parametersRedacted}`
              : "(original event not found)"),
        );
      }
    }
    ledger.close();
    return;
  }

  if (cmd === "decide") {
    const [approvalId, decisionArg, approver = "manager@example.com", ...reasonParts] = rest;
    if (!approvalId || (decisionArg !== "approve" && decisionArg !== "reject")) usage();
    const approved = decisionArg === "approve";
    const reason = reasonParts.join(" ") || (approved ? "Approved via CLI" : "Rejected via CLI");

    const approval = ledger.getApproval(approvalId);
    if (!approval) {
      console.error(`No approval found with id ${approvalId}`);
      process.exit(1);
    }
    if (approval.status !== "pending") {
      console.error(`Approval ${approvalId} is already "${approval.status}", not pending.`);
      process.exit(1);
    }
    const originalEvent = ledger.getEventById(approval.actionEventId);
    if (!originalEvent) {
      console.error(`Original action event ${approval.actionEventId} not found.`);
      process.exit(1);
    }

    const originalParams = JSON.parse(originalEvent.parametersRedacted) as Record<string, unknown>;
    const originalRequest: ActionRequest = {
      agentId: originalEvent.agentId,
      principal: originalEvent.principal,
      toolName: originalEvent.toolName,
      parameters: originalParams,
    };

    // Mirrors Gateway.resolveApproval: record the human decision, then
    // append a follow-up ledger event so the outcome (not just the hold)
    // is in the evidence trail.
    ledger.decideApproval(approvalId, approver, approved, reason);
    const followUp = ledger.append({
      runId: originalEvent.runId,
      agentId: originalEvent.agentId,
      principal: originalEvent.principal,
      toolName: originalEvent.toolName,
      parameters: originalParams,
      decision: approved ? "allow" : "deny",
      policyId: "approval",
      policyVersion: 1,
      ruleTriggered: approved ? "human_approval:approved" : "human_approval:rejected",
      latencyMs: 0,
      approvalId,
    });

    console.log(
      `Approval ${approvalId} ${approved ? "APPROVED" : "REJECTED"} by ${approver}. ` +
        `Logged as ledger event ${followUp.id}.`,
    );
    ledger.close();
    return;
  }

  usage();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
