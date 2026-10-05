// Worker process for the cross-process over-allocation test. Each worker is a
// separate OS process opening the SAME budget database file and hammering
// reserve() until the shared task budget refuses it. If reservation were not
// atomic across processes, the combined successes would exceed the limit.
//
// argv: <dbPath> <workerId> <attempts> <estimatedMicro>
// stdout: number of reservations this worker won.

import { BudgetStore } from "./budget-store.js";

const [dbPath, workerId, attemptsArg, estArg] = process.argv.slice(2);
const attempts = Number(attemptsArg);
const estimatedMicro = Number(estArg);

const store = new BudgetStore(dbPath);
let won = 0;
for (let i = 0; i < attempts; i++) {
  const r = store.reserve({
    requestId: `race-${workerId}-${i}`,
    attempt: 1,
    tenantId: "tenant-race",
    agentId: `agent-${workerId}`,
    taskId: `child-${workerId}-${i}`,
    parentTaskId: "T-race",
    rootTaskId: "T-race",
    provider: "anthropic",
    model: "claude-sonnet-5",
    estimatedMicro,
    pricingVersion: "2026-10-v1",
  });
  if (r.ok) won++;
}
store.close();
console.log(won);
