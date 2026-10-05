// Pricing versions. A PricingBook is immutable once used: billing records
// reference its `version`, and the full book is snapshotted into the
// pricing_versions table the first time it is used, so any billed amount can
// be recomputed from the exact rates that applied — even after rates change.
//
// All money is integer micro-USD (1 USD = 1_000_000). Rates below are
// ILLUSTRATIVE placeholders for the POC, not real provider list prices.

export interface ModelRate {
  /** micro-USD per 1,000,000 input tokens */
  inputPerMTokMicro: number;
  /** micro-USD per 1,000,000 output tokens */
  outputPerMTokMicro: number;
}

export interface PricingBook {
  version: string;
  models: Record<string, ModelRate>;
  /** Fixed governance-processing cost per governed call that reached a provider. */
  governanceMicroPerCall: number;
  /** Platform fee in basis points of provider cost (500 = 5%). */
  platformFeeBps: number;
  /** If true, blocked requests (policy deny, budget exhausted, ...) are also
   * charged the governance-processing cost. Default false: blocked = free. */
  chargeGovernanceOnBlocked: boolean;
}

export const DEFAULT_PRICING: PricingBook = {
  version: "2026-10-v1",
  models: {
    "claude-sonnet-5": { inputPerMTokMicro: 3_000_000, outputPerMTokMicro: 15_000_000 },
    "claude-haiku-4-5": { inputPerMTokMicro: 1_000_000, outputPerMTokMicro: 5_000_000 },
  },
  governanceMicroPerCall: 200,
  platformFeeBps: 500,
  chargeGovernanceOnBlocked: false,
};

/** Rounds UP so reservations and bills never under-count by a fraction of a micro-dollar. */
export function tokensToMicro(tokens: number, ratePerMTokMicro: number): number {
  return Math.ceil((tokens * ratePerMTokMicro) / 1_000_000);
}

export function costMicro(book: PricingBook, model: string, inputTokens: number, outputTokens: number): number {
  const rate = book.models[model];
  if (!rate) throw new Error(`No price for model "${model}" in pricing version ${book.version}`);
  return tokensToMicro(inputTokens, rate.inputPerMTokMicro) + tokensToMicro(outputTokens, rate.outputPerMTokMicro);
}

/** Worst-case cost of a call: estimated prompt tokens plus the FULL output
 * allowance. Reserving the worst case is what lets reconcile only ever
 * release headroom, never discover an overspend after the fact (barring a
 * provider exceeding max_tokens, which reconcile records as an overrun). */
export function worstCaseMicro(book: PricingBook, model: string, estInputTokens: number, maxOutputTokens: number): number {
  return costMicro(book, model, estInputTokens, maxOutputTokens);
}

export function platformFeeMicro(book: PricingBook, providerMicro: number): number {
  return Math.ceil((providerMicro * book.platformFeeBps) / 10_000);
}
