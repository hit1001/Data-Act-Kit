// Policy decision point (design §5.5). Pure and deny-by-default: every read of machine data,
// on any channel, is decided here from facts the caller loads. It never performs I/O.
import type { Channel, DatapointFacts, GrantFacts, MachineFacts, Principal } from './types.ts';

export type Purpose = 'customer_access' | 'recipient_access' | 'maker_internal';

export type ReasonCode =
  | 'not_authenticated_role'
  | 'machine_not_owned'
  | 'machine_unlinked'
  | 'datapoint_not_in_model'
  | 'datapoint_unpublished'
  | 'trade_secret_without_nda'
  | 'personal_data_without_legal_basis'
  | 'no_active_grant'
  | 'grant_channel_not_allowed'
  | 'grant_terms_not_accepted'
  | 'grant_scope_missing'
  | 'recipient_is_gatekeeper'
  | 'no_data_use_agreement';

export interface PolicyFacts {
  readonly machine: MachineFacts;
  readonly datapoints: readonly DatapointFacts[];
  /** Datapoint ids covered by an NDA accepted by the requesting organisation (R7). */
  readonly ndaCoveredDatapointIds: ReadonlySet<string>;
  /** Datapoint ids with a recorded GDPR legal basis for this customer (R9). */
  readonly legalBasisDatapointIds: ReadonlySet<string>;
  /** Grants from the machine owner to the requesting organisation (R11, R12). */
  readonly grants: readonly GrantFacts[];
  /** The requesting organisation is on the gatekeeper blocklist (R13). */
  readonly requesterIsGatekeeper: boolean;
  /** The maker holds a data-use agreement with the machine owner (R10). */
  readonly dataUseAgreement: boolean;
}

export interface PolicyRequest {
  readonly principal: Principal;
  readonly purpose: Purpose;
  readonly channel: Channel;
  readonly requestedDatapointIds: readonly string[];
  readonly now: Date;
}

export interface Denial { readonly datapointId: string | null; readonly reason: ReasonCode }

export interface PolicyDecision {
  /** Datapoints the principal may read; empty means nothing is released. */
  readonly allowed: readonly string[];
  readonly denials: readonly Denial[];
  /** Grant that authorised a recipient read, for fingerprinting and records. */
  readonly grantId: string | null;
}

const deny = (reason: ReasonCode, datapointId: string | null = null): Denial => ({ datapointId, reason });

function grantIsActive(g: GrantFacts, now: Date): boolean {
  return g.revokedAt === null && g.expiresAt.getTime() > now.getTime();
}

export function decide(req: PolicyRequest, facts: PolicyFacts): PolicyDecision {
  const { principal: p, purpose, channel, now } = req;
  const none = (reason: ReasonCode): PolicyDecision => ({ allowed: [], denials: [deny(reason)], grantId: null });

  if (facts.machine.ownerOrgId === null) return none('machine_unlinked');

  let grant: GrantFacts | null = null;
  switch (purpose) {
    case 'customer_access': {
      if (p.orgKind !== 'customer' || !p.roles.some((r) => r === 'customer_admin' || r === 'customer_user')) {
        return none('not_authenticated_role');
      }
      if (facts.machine.ownerOrgId !== p.orgId) return none('machine_not_owned');
      break;
    }
    case 'recipient_access': {
      if (p.orgKind !== 'recipient' || !p.roles.includes('recipient')) return none('not_authenticated_role');
      if (facts.requesterIsGatekeeper) return none('recipient_is_gatekeeper');
      const candidates = facts.grants.filter((g) =>
        g.recipientOrgId === p.orgId && g.customerOrgId === facts.machine.ownerOrgId && grantIsActive(g, now));
      if (candidates.length === 0) return none('no_active_grant');
      const withTerms = candidates.filter((g) => g.termsAccepted);
      if (withTerms.length === 0) return none('grant_terms_not_accepted');
      const onChannel = withTerms.filter((g) => g.channels.includes(channel));
      if (onChannel.length === 0) return none('grant_channel_not_allowed');
      const scoped = p.isMachineClient ? onChannel.filter((g) => p.scopes.includes(`grant:${g.id}`)) : onChannel;
      if (scoped.length === 0) return none('grant_scope_missing');
      // Use the grant that covers the most requested datapoints; ties resolve to the earliest expiry
      // so a request never silently depends on a longer-lived grant than necessary.
      grant = [...scoped].sort((a, b) =>
        coverage(b, req.requestedDatapointIds) - coverage(a, req.requestedDatapointIds) ||
        a.expiresAt.getTime() - b.expiresAt.getTime())[0] ?? null;
      break;
    }
    case 'maker_internal': {
      if (p.orgKind !== 'maker' || !p.roles.some((r) => r === 'maker_admin' || r === 'catalogue_reviewer')) {
        return none('not_authenticated_role');
      }
      if (!facts.dataUseAgreement) return none('no_data_use_agreement');
      break;
    }
  }

  const byId = new Map(facts.datapoints.map((d) => [d.id, d]));
  const allowed: string[] = [];
  const denials: Denial[] = [];
  for (const id of new Set(req.requestedDatapointIds)) {
    const dp = byId.get(id);
    if (!dp || dp.modelId !== facts.machine.modelId) { denials.push(deny('datapoint_not_in_model', id)); continue; }
    if (dp.status !== 'published') { denials.push(deny('datapoint_unpublished', id)); continue; }
    if (grant && !grant.datapointIds.includes(id)) { denials.push(deny('no_active_grant', id)); continue; }
    if (dp.personalData && !facts.legalBasisDatapointIds.has(id)) {
      denials.push(deny('personal_data_without_legal_basis', id)); continue;
    }
    // The maker holds its own trade secrets; customers and recipients need the agreed NDA first.
    if (dp.tradeSecret && purpose !== 'maker_internal' && !facts.ndaCoveredDatapointIds.has(id)) {
      denials.push(deny('trade_secret_without_nda', id)); continue;
    }
    allowed.push(id);
  }
  return { allowed, denials, grantId: grant?.id ?? null };
}

function coverage(g: GrantFacts, requested: readonly string[]): number {
  return requested.filter((id) => g.datapointIds.includes(id)).length;
}
