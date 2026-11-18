// Compensation for making data available to a data recipient (Art. 9). The user never pays (Art. 5(1)).

export interface CompensationInput {
  /** Costs of making the data available (Art. 9(2)(a)), in euro cents. */
  readonly formattingCents: number;
  readonly disseminationCents: number;
  readonly storageCents: number;
  /** Share of investment in collecting/producing the data (Art. 9(2)(b)), in euro cents. */
  readonly investmentShareCents: number;
  /** Margin as a fraction of the base, e.g. 0.1 for 10% (Art. 9(1) "may include a margin"). */
  readonly marginRate: number;
  /** SME or not-for-profit research organisation without non-SME partner or linked enterprises (Art. 9(4)). */
  readonly recipientCostCapped: boolean;
}

export interface CompensationLine { readonly label: string; readonly cents: number; readonly basis: string }

export interface CompensationQuote {
  readonly lines: readonly CompensationLine[];
  readonly totalCents: number;
  readonly capped: boolean;
  /** Plain statement of the calculation basis, disclosed to the recipient (Art. 9(7)). */
  readonly basis: string;
}

function assertCents(name: string, v: number): void {
  if (!Number.isInteger(v) || v < 0) throw new RangeError(`${name} must be a non-negative integer number of cents`);
}

export function quoteCompensation(i: CompensationInput): CompensationQuote {
  assertCents('formattingCents', i.formattingCents);
  assertCents('disseminationCents', i.disseminationCents);
  assertCents('storageCents', i.storageCents);
  assertCents('investmentShareCents', i.investmentShareCents);
  if (!Number.isFinite(i.marginRate) || i.marginRate < 0) throw new RangeError('marginRate must be a non-negative number');

  const costs: CompensationLine[] = [
    { label: 'Formatting', cents: i.formattingCents, basis: 'Art. 9(2)(a)' },
    { label: 'Dissemination via electronic means', cents: i.disseminationCents, basis: 'Art. 9(2)(a)' },
    { label: 'Storage', cents: i.storageCents, basis: 'Art. 9(2)(a)' },
  ];
  const costTotal = costs.reduce((s, l) => s + l.cents, 0);
  if (i.recipientCostCapped) {
    return {
      lines: costs, totalCents: costTotal, capped: true,
      basis: 'Recipient is an SME or not-for-profit research organisation without non-SME partner or linked ' +
        'enterprises, so compensation is limited to the costs of making the data available (Art. 9(4)).',
    };
  }
  const base = costTotal + i.investmentShareCents;
  const margin = Math.round(base * i.marginRate);
  const lines = [
    ...costs,
    { label: 'Share of investment in data collection', cents: i.investmentShareCents, basis: 'Art. 9(2)(b)' },
    { label: `Margin (${(i.marginRate * 100).toFixed(2)}%)`, cents: margin, basis: 'Art. 9(1)' },
  ];
  return {
    lines, totalCents: base + margin, capped: false,
    basis: 'Costs of making the data available plus a share of the investment in collecting the data and a ' +
      'margin, applied identically to comparable recipients (Art. 8(3), Art. 9(1)–(3)).',
  };
}
