#!/usr/bin/env node
// Out-of-band approval CLI. Runs as a *separate OS process* from the MCP
// server and writes directly to the shared SQLite ledger — the separation-
// of-duties control from the product spec, proven across process boundaries.
//
// Usage:
//   npm run mcp:approve -- decide <approvalId> approve|reject [approver] [reason]
//   npm run mcp:approve -- status <approvalId>
//   npm run mcp:approve -- verify

import { resolve } from "node:path";
import { Ledger } from "../ledger/ledger.js";

const DB_PATH = resolve(process.env.LEDGER_DB ?? "./mcp-ledger.db");

function usage(): never {
  console.error(`Usage:
  npm run mcp:approve -- decide <approvalId> approve|reject [approver] [reason]
  npm run mcp:approve -- status <approvalId>
  npm run mcp:approve -- verify

LEDGER_DB defaults to ./mcp-ledger.db (resolved against cwd).`);
  process.exit(2);
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd) usage();

  const ledger = new Ledger(DB_PATH);

  try {
    if (cmd === "verify") {
      const brokenAt = ledger.verifyChain();
      console.log(
        brokenAt === -1
          ? `Hash chain intact (${DB_PATH})`
          : `TAMPER at index ${brokenAt} (${DB_PATH})`,
      );
      process.exit(brokenAt === -1 ? 0 : 1);
    }

    if (cmd === "status") {
      const [approvalId] = rest;
      if (!approvalId) usage();
      const approval = ledger.getApproval(approvalId);
      if (!approval) {
        console.error(`Unknown approval: ${approvalId}`);
        process.exit(1);
      }
      console.log(JSON.stringify(approval, null, 2));
      return;
    }

    if (cmd === "decide") {
      const [approvalId, decision, approver = "manager@example.com", ...reasonParts] = rest;
      if (!approvalId || (decision !== "approve" && decision !== "reject")) usage();
      const reason = reasonParts.join(" ") || undefined;
      const { approval, event } = ledger.resolveApprovalOutOfBand(
        approvalId,
        approver,
        decision === "approve",
        reason,
      );
      console.log(
        JSON.stringify(
          {
            approval,
            followUpEvent: {
              id: event.id,
              decision: event.decision,
              ruleTriggered: event.ruleTriggered,
            },
            ledger: DB_PATH,
          },
          null,
          2,
        ),
      );
      return;
    }

    usage();
  } finally {
    ledger.close();
  }
}

main();
