// Access and sharing requests: state machine and deadline alerts (design §5.8, R4, R8).
import type { ReasonCode } from './policy.ts';

export type RequestState = 'received' | 'evaluated' | 'granted' | 'withheld' | 'refused';
export type RequestOutcome = 'granted' | 'withheld' | 'refused';

const TRANSITIONS: Readonly<Record<RequestState, readonly RequestState[]>> = {
  received: ['evaluated'],
  evaluated: ['granted', 'withheld', 'refused'],
  granted: ['withheld'], // e.g. trade-secret measures later not maintained (Art. 4(7), 5(10))
  withheld: ['granted'], // sharing resumes once measures are agreed
  refused: [],
};

export function canTransition(from: RequestState, to: RequestState): boolean {
  return TRANSITIONS[from].includes(to);
}

/** Legal grounds for withholding or refusing; each requires a written, substantiated decision. */
export const REFUSAL_GROUNDS = {
  security_risk: 'Art. 4(2): sharing could undermine security requirements with serious adverse effect on health, safety or security',
  trade_secret_measures_missing: 'Art. 4(7) / 5(10): necessary confidentiality measures not agreed, not implemented or undermined',
  trade_secret_serious_damage: 'Art. 4(8) / 5(11): highly likely serious economic damage from disclosure of trade secrets',
} as const;
export type RefusalGround = keyof typeof REFUSAL_GROUNDS;

/** Art. 4(2) and 4(8)/5(11) speak of refusing; Art. 4(7)/5(10) of withholding or suspending. */
const OUTCOME_FOR_GROUND: Readonly<Record<RefusalGround, 'withheld' | 'refused'>> = {
  security_risk: 'refused',
  trade_secret_measures_missing: 'withheld',
  trade_secret_serious_damage: 'refused',
};

export interface DecisionInput {
  readonly outcome: RequestOutcome;
  readonly ground: RefusalGround | null;
  readonly justification: string;
  readonly datapointIds: readonly string[];
}

/** Validates a decision before it is recorded. Returns problems; empty means valid. */
export function validateDecision(d: DecisionInput): string[] {
  const problems: string[] = [];
  if (d.outcome === 'granted') {
    if (d.ground !== null) problems.push('A granted request has no refusal ground');
    return problems;
  }
  if (d.ground === null) {
    problems.push('Withholding or refusing requires a legal ground');
  } else if (OUTCOME_FOR_GROUND[d.ground] !== d.outcome) {
    problems.push(`Ground ${d.ground} permits '${OUTCOME_FOR_GROUND[d.ground]}', not '${d.outcome}'`);
  }
  // "Duly substantiated" is a legal judgement made by the approving legal officer; the system only
  // ensures a justification exists and is recorded.
  if (d.justification.trim() === '') problems.push('The decision must be substantiated in writing');
  if (d.datapointIds.length === 0) problems.push('Name the affected data points');
  return problems;
}

/** Maps policy denial reasons that require a written decision to the matching legal ground. */
export function groundForDenial(reason: ReasonCode): RefusalGround | null {
  return reason === 'trade_secret_without_nda' ? 'trade_secret_measures_missing' : null;
}

export interface DeadlineAlert { readonly threshold: 50 | 90; readonly at: Date }

export function deadlineAlerts(receivedAt: Date, dueAt: Date): DeadlineAlert[] {
  const span = dueAt.getTime() - receivedAt.getTime();
  if (span <= 0) throw new RangeError('dueAt must be after receivedAt');
  return ([50, 90] as const).map((threshold) => ({
    threshold, at: new Date(receivedAt.getTime() + Math.round(span * threshold / 100)),
  }));
}
