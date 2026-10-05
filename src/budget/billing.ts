// Billing: turns reconciled consumption into customer-facing charges.
//
// Three cost components are always stored and shown separately:
//   provider_micro    pass-through cost of the model provider's usage
//   governance_micro  cost of governance processing (policy, ledger, approvals)
//   platform_micro    platform fee (basis points of provider cost)
//
// Idempotency: billing_records.idempotency_key is UNIQUE and derived from
// (tenant, request attempt). INSERT OR IGNORE means a replayed event, a
// retried job or two racing workers produce exactly one charge.
//
// Treatment of non-standard outcomes (the PRD asks this be specified):
//   completed, usage reported        -> bill provider + governance + platform fee
//   failed, provider reported usage  -> bill the reported usage (we were charged)
//   failed, provider confirmed none  -> no charge (treatment "failed_no_usage")
//   blocked before the provider      -> no provider cost; governance cost only if
//                                       pricing.chargeGovernanceOnBlocked (default off)
//   retry / fallback attempt         -> its own attempt key; billed on its own
//                                       usage like any call; counts to task budget
//   usage missing / unresolved       -> NOT billed yet and NEVER billed as zero;
//                                       appears in pendingUsage() until resolved

import { nanoid } from "nanoid";
import type { BudgetStore } from "./budget-store.js";
import { platformFeeMicro, type PricingBook } from "./pricing.js";

export type BillingTreatment =
  | "completed"
  | "failed_with_usage"
  | "failed_no_usage"
  | "blocked_no_charge"
  | "blocked_governance_only";

export interface BillingRecord {
  id: string;
  idempotencyKey: string;
  tenantId: string;
  requestId: string;
  reservationId: string | null;
  pricingVersion: string;
  providerMicro: number;
  governanceMicro: number;
  platformMicro: number;
  totalMicro: number;
  treatment: BillingTreatment;
  createdAt: string;
}

export class Billing {
  constructor(
    private store: BudgetStore,
    private pricing: PricingBook,
  ) {
    store.snapshotPricing(pricing);
  }

  /** Bills a reconciled reservation. Safe to call any number of times. */
  billReconciled(requestId: string, failedWithUsage = false): { created: boolean; record?: BillingRecord } {
    const res = this.store.getReservation(requestId);
    if (!res) throw new Error(`No reservation for ${requestId}`);
    if (res.status !== "reconciled" || res.actualMicro === null) {
      // Unresolved / still in flight: do not bill, do not bill zero.
      return { created: false };
    }
    // Always price with the version recorded on the reservation, not "current".
    const book = this.store.getPricingSnapshot(res.pricingVersion) ?? this.pricing;
    const provider = res.actualMicro;
    const governance = book.governanceMicroPerCall;
    const platform = platformFeeMicro(book, provider);
    return this.insert({
      key: `bill:${res.tenantId}:${requestId}`,
      tenantId: res.tenantId,
      requestId,
      reservationId: res.id,
      pricingVersion: book.version,
      provider,
      governance,
      platform,
      treatment: failedWithUsage ? "failed_with_usage" : "completed",
    });
  }

  /** Records a zero-rated (or governance-only) outcome so every request has a
   * billing row an auditor can find, including the ones that cost nothing. */
  billNoCharge(input: { tenantId: string; requestId: string; treatment: "failed_no_usage" | "blocked_no_charge" }) {
    const chargeGov = input.treatment === "blocked_no_charge" && this.pricing.chargeGovernanceOnBlocked;
    return this.insert({
      key: `bill:${input.tenantId}:${input.requestId}`,
      tenantId: input.tenantId,
      requestId: input.requestId,
      reservationId: this.store.getReservation(input.requestId)?.id ?? null,
      pricingVersion: this.pricing.version,
      provider: 0,
      governance: chargeGov ? this.pricing.governanceMicroPerCall : 0,
      platform: 0,
      treatment: chargeGov ? "blocked_governance_only" : input.treatment,
    });
  }

  private insert(r: {
    key: string;
    tenantId: string;
    requestId: string;
    reservationId: string | null;
    pricingVersion: string;
    provider: number;
    governance: number;
    platform: number;
    treatment: BillingTreatment;
  }): { created: boolean; record?: BillingRecord } {
    const id = nanoid();
    const now = new Date().toISOString();
    const res = this.store.database
      .prepare(
        `INSERT OR IGNORE INTO billing_records
         (id, idempotency_key, tenant_id, request_id, reservation_id, pricing_version,
          provider_micro, governance_micro, platform_micro, total_micro, treatment, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(id, r.key, r.tenantId, r.requestId, r.reservationId, r.pricingVersion, r.provider, r.governance, r.platform, r.provider + r.governance + r.platform, r.treatment, now);
    if (res.changes === 0) return { created: false };
    return { created: true, record: this.getByKey(r.key) };
  }

  getByKey(key: string): BillingRecord | undefined {
    const r = this.store.database.prepare(`SELECT * FROM billing_records WHERE idempotency_key = ?`).get(key) as any;
    return r ? rowToBilling(r) : undefined;
  }

  list(tenantId: string): BillingRecord[] {
    return (this.store.database.prepare(`SELECT * FROM billing_records WHERE tenant_id = ? ORDER BY created_at, rowid`).all(tenantId) as any[]).map(rowToBilling);
  }

  /** Invoice view: the three components separately, plus what is still unbilled. */
  invoice(tenantId: string) {
    const rows = this.list(tenantId);
    const sum = (f: (r: BillingRecord) => number) => rows.reduce((a, r) => a + f(r), 0);
    return {
      tenantId,
      providerMicro: sum((r) => r.providerMicro),
      governanceMicro: sum((r) => r.governanceMicro),
      platformMicro: sum((r) => r.platformMicro),
      totalMicro: sum((r) => r.totalMicro),
      lines: rows.length,
      pendingUsage: this.store.listUnresolved().filter((u) => u.tenantId === tenantId).map((u) => ({ requestId: u.requestId, heldMicro: u.estimatedMicro })),
    };
  }

  /** Audit trace: billing row -> reservation -> usage evidence -> pricing
   * snapshot, plus a recomputation check against that snapshot. */
  trace(billingId: string) {
    const b = this.store.database.prepare(`SELECT * FROM billing_records WHERE id = ?`).get(billingId) as any;
    if (!b) return undefined;
    const record = rowToBilling(b);
    const reservation = this.store.getReservation(record.requestId);
    const ledger = this.store.ledgerForRequest(record.requestId);
    const usage = reservation
      ? (this.store.database.prepare(`SELECT * FROM usage_events WHERE reservation_id = ?`).get(reservation.id) as any | undefined)
      : undefined;
    const pricing = this.store.getPricingSnapshot(record.pricingVersion);
    let recomputedProviderMicro: number | undefined;
    if (usage && pricing && reservation) {
      const rate = pricing.models[reservation.model];
      if (rate) {
        recomputedProviderMicro =
          Math.ceil((usage.input_tokens * rate.inputPerMTokMicro) / 1_000_000) +
          Math.ceil((usage.output_tokens * rate.outputPerMTokMicro) / 1_000_000);
      }
    }
    return { record, reservation, ledger, usage, pricing, recomputedProviderMicro };
  }
}

function rowToBilling(r: any): BillingRecord {
  return {
    id: r.id,
    idempotencyKey: r.idempotency_key,
    tenantId: r.tenant_id,
    requestId: r.request_id,
    reservationId: r.reservation_id,
    pricingVersion: r.pricing_version,
    providerMicro: r.provider_micro,
    governanceMicro: r.governance_micro,
    platformMicro: r.platform_micro,
    totalMicro: r.total_micro,
    treatment: r.treatment,
    createdAt: r.created_at,
  };
}
