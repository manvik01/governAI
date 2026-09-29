// Decision Matrix evaluator: generalizes the governance PolicyEngine's
// "evaluate structured fields against versioned rules in order" pattern to
// any domain (sales routing, ops triage, marketing spend gates), reading
// its rules from the Context Store instead of being hand-wired in code.
//
// The split this file exists to enforce: an LLM is trusted to turn an
// unstructured event into structured `facts` (classification, extraction —
// judgment calls only it can make). It is never trusted to decide what
// happens next. That's this function: pure, deterministic, replayable.

import type { ContextStore } from "./store.js";
import type { ConditionDef, PolicyRuleDef } from "./types.js";

export interface MatrixDecision {
  matched: boolean;
  rule?: PolicyRuleDef;
  action?: Record<string, unknown>;
}

/** Reads a value out of a flat or dotted-path fact bag, e.g. "deal.amount". */
function readPath(facts: Record<string, unknown>, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object") return (acc as Record<string, unknown>)[key];
    return undefined;
  }, facts);
}

function conditionHolds(predicate: ConditionDef["predicate"], facts: Record<string, unknown>): boolean {
  const actual = readPath(facts, predicate.path);
  switch (predicate.op) {
    case "eq":
      return actual === predicate.value;
    case "neq":
      return actual !== predicate.value;
    case "gt":
      return typeof actual === "number" && actual > (predicate.value as number);
    case "gte":
      return typeof actual === "number" && actual >= (predicate.value as number);
    case "lt":
      return typeof actual === "number" && actual < (predicate.value as number);
    case "lte":
      return typeof actual === "number" && actual <= (predicate.value as number);
    case "in":
      return Array.isArray(predicate.value) && predicate.value.includes(actual);
    case "exists":
      return actual !== undefined && actual !== null;
    default:
      return false;
  }
}

/** Evaluates the current decision_rules for one domain+ruleType against a
 * structured fact bag, first-match-wins, exactly like PolicyEngine. Rules
 * are read fresh from the Context Store on every call — nothing about the
 * matrix is cached in the caller's memory across turns. */
export function evaluateMatrix(
  store: ContextStore,
  domain: string,
  ruleType: PolicyRuleDef["ruleType"],
  facts: Record<string, unknown>,
): MatrixDecision {
  const rules = store
    .listCurrent<PolicyRuleDef>("policy", domain)
    .map((e) => e.data)
    .filter((r) => r.ruleType === ruleType)
    .sort((a, b) => a.id.localeCompare(b.id)); // insertion-stable ordering by id

  for (const rule of rules) {
    const allHold = rule.when.every((predicate) => conditionHolds(predicate, facts));
    if (allHold) {
      return { matched: true, rule, action: rule.action };
    }
  }
  return { matched: false };
}

/** Checks whether every named condition entity currently holds against a
 * fact bag — how a sub-agent asks "am I allowed to start this workflow
 * step" before doing any work. */
export function conditionsHold(
  store: ContextStore,
  domain: string,
  conditionIds: string[],
  facts: Record<string, unknown>,
): { holds: boolean; failing: string[] } {
  const failing: string[] = [];
  for (const id of conditionIds) {
    const entity = store.getCurrent<ConditionDef>(id);
    if (!entity) {
      failing.push(id);
      continue;
    }
    if (!conditionHolds(entity.data.predicate, facts)) failing.push(id);
  }
  return { holds: failing.length === 0, failing };
}
