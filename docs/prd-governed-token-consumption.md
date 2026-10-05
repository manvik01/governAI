# PRD: Governed Token Consumption and Cost Management

Status: implemented in the POC (`src/budget/`), 16 acceptance tests passing (`npm test`).
Demo: `npm run budget:demo`.

**Objective.** Let organisations control, attribute and monetise AI consumption while
keeping permission checks, human accountability and auditable execution intact.

This document is the original PRD tightened for build. Section 1 lists what the original
left open and the decision taken for each; sections 2-5 are the resulting requirements.

---

## 1. Fine-tuning: gaps in the original PRD and the decisions taken

| # | Gap in the original | Decision |
|---|---|---|
| 1 | Order of controls was implied, not stated. "Budget must never override security" is only testable if the order is fixed. | Fixed order: agent state -> permitted model -> policy/grant/approval -> **budget** -> provider -> reconcile -> bill. Security checks run before budget is read, so budget can only add restriction. No code path lets available budget turn a deny or hold into an allow. |
| 2 | "Estimate consumption" undefined. | Reserve the **worst case**: estimated input tokens + the *full* `maxOutputTokens` at the model's rate. `maxOutputTokens` is mandatory; an unbounded call cannot be reserved against, so it is refused. Reconcile then only releases headroom. |
| 3 | Hierarchy semantics (org/project/agent/task) unspecified. | A call is admitted only if **every configured level** has room; the tightest level wins and the refusal names it. A level with no limit is skipped. A refused call reserves nothing at any level. |
| 4 | "Originating task" for child agents undefined. | Every task records its parent; all descendants resolve to one **root task**, and the root task's budget is charged by all child calls, retries and fallbacks. |
| 5 | Atomicity not defined. | Check-and-hold is one write-locked transaction across all levels, idempotent on the attempt key. Verified across 6 separate OS processes (exactly `floor(limit/estimate)` reservations win, never more, never fewer). Production: Postgres row locks / `SELECT ... FOR UPDATE`. |
| 6 | Reconcile when actual > reserved (provider exceeds `max_tokens`) unspecified. | Record the true cost (spend already happened), flag the overrun on the ledger, and let the level go over its limit; subsequent calls are refused. We never under-record to stay inside a limit. |
| 7 | "Missing usage must remain unresolved" - what happens to the held amount? | Reservation becomes `unresolved`: the **estimate stays held** (conservative), ledger tokens/cost are `NULL` (never 0), the item is not billed and appears under "awaiting usage". Resolved later by a real usage report. Reservations past their TTL become `unresolved`, never silently released. |
| 8 | Failed / retried / blocked billing "to be specified". | See the treatment table in section 4. |
| 9 | "Duplicate usage events" - what is the key? | `usage_event_id` is unique forever (dedupe table). A replay is ignored and logged. A *different* usage event for an already-settled request is rejected and logged, not charged. Billing has a second guard: unique `idempotency_key` per request attempt. |
| 10 | Who may authorise an increase, and what does it touch? | Only principals registered as budget approvers for that scope; the requester cannot approve their own increase (separation of duties). An increase edits one spending limit and nothing else - grants, policies and approvals are untouched. Cancelled tasks cannot be topped up. |
| 11 | Fallback models could be used to dodge controls. | Each retry and fallback re-runs the full control order. A fallback not in `permittedModels` is blocked, not quietly used to save money. There is no switch to disable a check for cost reasons. |
| 12 | Money representation. | Integer micro-USD everywhere, rounding **up** on estimates and bills. No floats in any budget or billing path. |
| 13 | Pricing traceability. | Pricing is versioned and immutable; the full book is snapshotted on first use. Each billing row and ledger row carries the version, and cost is recomputable from usage x snapshot (asserted in the tests). |
| 14 | Registration fields were listed but not enforced. | Registration is refused without an owner, approved purpose, at least one permitted model, and a budget policy. Registration-time budget defaults are applied lazily and never overwrite an administrator-set limit. |

## 2. Functional requirements (as built)

1. **Agent registration.** Owner, approved purpose, risk tier (computed), `permittedModels`, `budgetPolicy` (`agentLimitMicro`, `defaultTaskLimitMicro`). Enforced at `AgentRegistry.register`.
2. **Budget enforcement.** Limits at org, project, agent and task level. Pre-call: policy check -> estimate -> atomic reservation -> provider -> reconcile. (`BudgetStore.reserve/reconcile`)
3. **Shared task budgets.** Child calls, retries and fallbacks all charge the root task. Concurrent agents cannot over-allocate (in-process and cross-process tests).
4. **Independent security controls.** Section 1, decisions 1 and 11.
5. **Consumption ledger.** Append-only; one row per state transition. Fields: tenant, project, agent, task, parent task, root task, request ID (per attempt), provider, model, input/output tokens (nullable), estimated cost, reconciled cost (nullable), policy version, approval reference, link to the governance evidence event, execution status, pricing version.
6. **Transparent billing.** Provider cost, governance-processing cost and platform fee stored and shown separately; idempotent records.
7. **Budget exhaustion.** New calls pause; the response names the exhausted level and offers *increase budget* (authorised approver) or *cancel task*; it states that calls already in progress may still incur charges. Cancelling a task blocks new calls only; in-flight calls still settle and bill.

## 3. Request lifecycle

```
invoke(request)
  1 agent active?                       no -> blocked:agent_inactive      (no budget touched)
  2 model in permittedModels?           no -> blocked:model_not_permitted (no budget touched)
  3 policy engine: grant/rules/approval deny -> blocked:policy_deny
                                        hold -> blocked:approval_required (no budget touched)
  4 reserve worst case at org+project+agent+root task, atomically
                                        no -> budget_exhausted (reserves nothing)
  5 provider call                       fail, confirmed no usage -> release, bill nothing, retry/fallback
                                        fail, partial usage      -> bill that usage
                                        fail, outcome unknown    -> unresolved (estimate held)
  6 usage reported -> reconcile (idempotent) -> bill (idempotent)
    usage missing  -> unresolved (estimate held, not billed, not zero)
```

## 4. Billing treatment

| Outcome | Provider cost | Governance cost | Platform fee | Budget effect |
|---|---|---|---|---|
| Completed, usage reported | billed | billed | billed | reservation -> actual spend |
| Failed, provider reported usage | billed (reported usage) | billed | billed | actual spend |
| Failed, provider confirmed none | 0 | 0 | 0 | reservation released |
| Failed, outcome unknown | pending | pending | pending | estimate held (unresolved) |
| Retry / fallback attempt | its own usage, like any call | per billed attempt | per billed attempt | same root task |
| Blocked before provider (deny, hold, unpermitted model, inactive, cancelled, budget exhausted) | 0 | 0 by default; `chargeGovernanceOnBlocked` flag in the pricing version | 0 | none |
| Usage missing | pending, never 0 | pending | pending | estimate held |

Every request, including zero-rated ones, has a billing row so an auditor can see that it was considered.

## 5. Acceptance criteria and where they are proven

| Criterion | Test (`src/budget/budget.test.ts`) |
|---|---|
| A policy-denied call never reaches the model provider | `AC1` - rule deny, unpermitted model, missing grant, suspended agent: 0 provider calls, 0 budget movement |
| Parallel child agents cannot over-allocate the shared budget | `AC2` in-process (8 parallel children, exactly 3 admitted) and across 6 OS processes (exactly 9 of 60 attempts win) |
| Duplicate usage events do not create duplicate charges | `AC3` - 5 replays + a conflicting event + a replayed request id: one billing row, budget unmoved, provider called once |
| Budget approval does not grant additional tool permissions | `AC4` - grants and policy byte-identical after an increase; ungranted tool still denied; held call stays held with ample budget |
| Every billed amount traces to usage evidence and the pricing version | `AC5` - billing -> reservation -> usage event -> pricing snapshot; provider cost recomputed from snapshot equals billed |

Added criteria (behaviour the PRD requires but did not phrase as a criterion): missing usage stays unresolved and unbilled; expired reservations become unresolved; fallbacks cannot bypass `permittedModels`; failed calls with partial usage are billed; exhaustion offers both options plus the in-flight warning; registration refuses incomplete agents; registration defaults never overwrite administrator limits.

## 6. Open questions for the next iteration

1. **Non-LLM costs.** Should tool executions (e.g. a paid search API) draw from the same task budget? The reservation model supports it; pricing and metering do not yet.
2. **Cached / batch / reasoning tokens.** Usage categories beyond input/output need rates in the pricing version and columns on the ledger.
3. **Provider-reported vs platform-counted tokens.** If they disagree, which is billed? Proposal: provider-reported is authoritative, with a discrepancy flag when platform count differs by more than a tolerance.
4. **Streaming and client cancellation.** Partial usage on cancel is handled for errors; the cancel-mid-stream path needs a provider-specific usage fetch.
5. **Top-up expiry.** Time-boxed increases (revert at end of period) are not built.
6. **Period budgets.** Daily/monthly rolling windows per level; today's limits are lifetime-of-scope. The existing stateful velocity rules in the policy engine are the natural home.
7. **Currency and tax.** Out of scope; all amounts are USD micro-units.
8. **Scale-out.** Move from SQLite to Postgres with row-level locking; keep the contract (atomic check-and-hold, idempotent keys) and re-run the cross-process race test against it.
9. **Evidence chain.** The consumption ledger is append-only but not yet hash-chained like the governance ledger; chaining it, or anchoring both under one chain, is a small follow-up.
