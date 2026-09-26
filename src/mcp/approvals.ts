// Approval channel that writes to stderr only. MCP stdio servers must keep
// stdout reserved for the JSON-RPC protocol stream.

import type { ApprovalChannel, ApprovalRequestPayload } from "../gateway/approvals.js";

export class StderrApprovalChannel implements ApprovalChannel {
  async request(payload: ApprovalRequestPayload): Promise<void> {
    const lines = [
      "",
      "  ┌─ APPROVAL REQUESTED " + "─".repeat(40),
      `  │ Agent:       ${payload.agentId}`,
      `  │ Acting for:  ${payload.principal}`,
      `  │ Tool:        ${payload.toolName}`,
      `  │ Params:      ${JSON.stringify(payload.parameters)}`,
      `  │ Why held:    ${payload.reason}`,
      `  │ Approval ID: ${payload.approvalId}`,
      "  └" + "─".repeat(62),
      "",
      `  Resolve with:`,
      `    npm run mcp:approve -- decide ${payload.approvalId} approve`,
      "",
    ];
    for (const line of lines) console.error(line);
  }
}
