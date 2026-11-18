// The only path to machine data (design §4 "single policy decision point"): load facts, decide, record
// a minimal access-log entry (R6), then read.
import { decide, type Channel, type DatapointFacts, type GrantFacts, type PolicyDecision, type Principal, type Purpose } from '@dak/core';
import type pg from 'pg';
import type { GatekeeperList } from './config.ts';
import { withScope, type Scope, type Tx } from './db.ts';

export function isGatekeeper(list: GatekeeperList, org: { name: string; group_identifier: string | null }): boolean {
  const name = org.name.trim().toLowerCase();
  return list.entries.some((e) => e.name.trim().toLowerCase() === name ||
    (org.group_identifier !== null && e.identifiers.includes(org.group_identifier)));
}

export function purposeFor(p: Principal): Purpose {
  switch (p.orgKind) {
    case 'customer': return 'customer_access';
    case 'recipient': return 'recipient_access';
    case 'maker': return 'maker_internal';
  }
}

export function scopeFor(p: Principal): Scope {
  return p.orgKind;
}

/** Loads every fact the policy needs for one machine, as seen by the system (not the caller). */
export async function loadFacts(tx: Tx, gatekeepers: GatekeeperList, principal: Principal, machineId: string) {
  const machine = (await tx.query<{ id: string; model_id: string; owner_org_id: string | null }>(
    'SELECT id::text, model_id::text, owner_org_id::text FROM machine WHERE id::text=$1', [machineId])).rows[0];
  if (!machine) return null;
  const owner = machine.owner_org_id;
  const datapoints = (await tx.query<{ id: string; model_id: string; trade_secret: boolean; personal_data: boolean; status: 'draft' | 'published' }>(
    'SELECT id::text, model_id::text, trade_secret, personal_data, status::text AS status FROM datapoint WHERE model_id=$1', [machine.model_id])).rows;
  // NDA coverage: the requesting organisation's NDAs with the maker of this model.
  const nda = (await tx.query<{ id: string }>(
    `SELECT DISTINCT unnest(c.datapoint_ids)::text AS id FROM contract c JOIN product_model pm ON pm.maker_org_id = c.counterparty_org_id
      WHERE c.kind='nda' AND c.org_id=$1 AND pm.id=$2`, [principal.orgId, machine.model_id])).rows.map((r) => r.id);
  const legalBasis = owner ? (await tx.query<{ datapoint_id: string }>(
    'SELECT datapoint_id::text FROM legal_basis WHERE customer_org_id=$1', [owner])).rows.map((r) => r.datapoint_id) : [];
  const grants: GrantFacts[] = owner && principal.orgKind === 'recipient' ? (await tx.query<{
    id: string; customer_org_id: string; recipient_org_id: string; datapoint_ids: string[]; channels: Channel[];
    expires_at: Date; revoked_at: Date | null; terms_accepted: boolean;
  }>(`SELECT g.id::text, g.customer_org_id::text, g.recipient_org_id::text, g.datapoint_ids::text[] AS datapoint_ids, g.channels,
        g.expires_at, g.revoked_at,
        EXISTS (SELECT 1 FROM contract c JOIN organisation o ON o.id = g.recipient_org_id JOIN recipient_category rc ON rc.id = o.recipient_category_id
          WHERE c.kind='recipient_terms' AND c.org_id = g.recipient_org_id AND c.template_id = rc.terms_template_id
            AND c.template_version = rc.terms_template_version) AS terms_accepted
      FROM "grant" g WHERE g.customer_org_id=$1 AND g.recipient_org_id=$2`, [owner, principal.orgId])).rows.map((g) => ({
    id: g.id, customerOrgId: g.customer_org_id, recipientOrgId: g.recipient_org_id, datapointIds: g.datapoint_ids, channels: g.channels,
    expiresAt: g.expires_at, revokedAt: g.revoked_at, termsAccepted: g.terms_accepted,
  })) : [];
  const org = (await tx.query<{ name: string; group_identifier: string | null }>(
    'SELECT name, group_identifier FROM organisation WHERE id=$1', [principal.orgId])).rows[0];
  const dataUse = owner ? (await tx.query(
    `SELECT 1 FROM contract c JOIN product_model pm ON pm.maker_org_id = c.counterparty_org_id
      WHERE c.kind='data_use' AND c.org_id=$1 AND pm.id=$2`, [owner, machine.model_id])).rowCount : 0;
  return {
    machine: { id: machine.id, modelId: machine.model_id, ownerOrgId: owner },
    datapoints: datapoints.map((d): DatapointFacts => ({ id: d.id, modelId: d.model_id, tradeSecret: d.trade_secret, personalData: d.personal_data, status: d.status })),
    ndaCoveredDatapointIds: new Set(nda), legalBasisDatapointIds: new Set(legalBasis), grants,
    requesterIsGatekeeper: org ? isGatekeeper(gatekeepers, org) : true,
    dataUseAgreement: Boolean(dataUse),
  };
}

export interface AccessContext { readonly pool: pg.Pool; readonly gatekeepers: GatekeeperList }

export interface Authorised { readonly decision: PolicyDecision; readonly machineFound: boolean }

/** Decides one read. Logs only principal, optional request id and time (Art. 4(5), 5(4)). */
export async function authorise(ctx: AccessContext, principal: Principal, machineId: string, channel: Channel,
  datapointIds: readonly string[], requestId: string | null = null): Promise<Authorised> {
  return withScope(ctx.pool, 'system', null, async (tx) => {
    const facts = await loadFacts(tx, ctx.gatekeepers, principal, machineId);
    if (!facts) return { decision: { allowed: [], denials: [], grantId: null }, machineFound: false };
    const decision = decide({ principal, purpose: purposeFor(principal), channel, requestedDatapointIds: datapointIds, now: new Date() }, facts);
    if (decision.allowed.length > 0) {
      await tx.query('INSERT INTO access_log (principal_id, request_id) VALUES ($1,$2)', [principal.id, requestId]);
    }
    return { decision, machineFound: true };
  });
}
