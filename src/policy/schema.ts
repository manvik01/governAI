// Runtime validation for policies submitted over the API or MCP. Strict: unknown
// fields are rejected so a typo in a rule cannot silently weaken it.
import { z } from "zod";
import type { Policy } from "./engine.js";

const decision = z.enum(["allow", "deny", "hold_for_approval"]);

const parameterRule = z.strictObject({
  kind: z.literal("parameter_threshold"),
  field: z.string().min(1),
  lessThanOrEqual: z.number().optional(),
  greaterThan: z.number().optional(),
  thenDecision: decision,
  reason: z.string().min(1),
});

const velocityRule = z.strictObject({
  kind: z.literal("velocity"),
  windowMinutes: z.number().positive(),
  maxCount: z.number().int().positive().optional(),
  maxCumulativeField: z.strictObject({ field: z.string().min(1), max: z.number() }).optional(),
  thenDecision: decision,
  reason: z.string().min(1),
});

export const policySchema = z.strictObject({
  id: z.string().min(1),
  version: z.number().int().positive(),
  toolName: z.string().min(1),
  defaultDecision: decision,
  rules: z.array(z.union([parameterRule, velocityRule])),
});

export function parsePolicy(input: unknown): { ok: true; policy: Policy } | { ok: false; errors: string[] } {
  const r = policySchema.safeParse(input);
  if (r.success) return { ok: true, policy: r.data as Policy };
  return { ok: false, errors: r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`) };
}
