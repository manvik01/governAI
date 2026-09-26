// Approval channel: where a hold-for-approval decision is sent for a human
// to act on. The interface is shaped like a Slack/Teams message payload so
// that swapping this console implementation for a real Slack webhook later
// (roadmap weeks 7-8) touches only this file, not the gateway.

export interface ApprovalRequestPayload {
  approvalId: string;
  agentId: string;
  principal: string;
  toolName: string;
  parameters: Record<string, unknown>;
  reason: string;
}

export interface ApprovalChannel {
  request(payload: ApprovalRequestPayload): Promise<void>;
}

/** Demo-only stand-in: prints what a Slack approval card would show. */
export class ConsoleApprovalChannel implements ApprovalChannel {
  async request(payload: ApprovalRequestPayload): Promise<void> {
    console.log("\n  ┌─ APPROVAL REQUESTED " + "─".repeat(40));
    console.log(`  │ Agent:     ${payload.agentId}`);
    console.log(`  │ Acting for: ${payload.principal}`);
    console.log(`  │ Tool:      ${payload.toolName}`);
    console.log(`  │ Params:    ${JSON.stringify(payload.parameters)}`);
    console.log(`  │ Why held:  ${payload.reason}`);
    console.log(`  │ Approval ID: ${payload.approvalId}`);
    console.log("  └" + "─".repeat(62));
  }
}
