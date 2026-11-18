// Legal records and workflows (design §5.8). Contracts, grants, requests and decisions are kept as
// legal records, separate from the minimal access log.
import {
  CHANNELS, quoteCompensation, validateDecision, canTransition, type Channel, type DecisionInput, type Principal, type RequestState,
} from '@dak/core';
import type { Config } from './config.ts';
import type { Tx } from './db.ts';
import { isGatekeeper } from './access.ts';
import { partiesContext, render, storeDocument, type DocumentKind, type TemplateStore } from './documents.ts';

export class RecordError extends Error {
  override readonly name = 'RecordError';
  readonly status: 400 | 403 | 404 | 409;
  constructor(message: string, status: 400 | 403 | 404 | 409 = 400) { super(message); this.status = status; }
}

const CONTRACT_DOC: Readonly<Record<'data_use' | 'nda' | 'recipient_terms', DocumentKind>> =
  { data_use: 'data_use_agreement', nda: 'nda', recipient_terms: 'recipient_terms' };

export interface Deps { readonly config: Config; readonly templates: TemplateStore }

/**
 * Prepares a contract for a party. No document reaches a counterparty unapproved (design §5.9), so the
 * offer starts as a draft that a legal officer approves before it can be accepted.
 */
export async function offerContract(tx: Tx, deps: Deps, p: Principal, kind: 'data_use' | 'nda' | 'recipient_terms',
  counterpartyOrgId: string, datapointIds: readonly string[], language: string): Promise<string> {
  if (kind === 'nda' && datapointIds.length === 0) throw new RecordError('An NDA must name the trade-secret data points it covers');
  if (kind !== 'nda' && datapointIds.length > 0) throw new RecordError('Only NDAs cover specific data points');
  if (kind === 'data_use' && p.orgKind !== 'customer') throw new RecordError('Data-use agreements are concluded by the machine owner', 403);
  if (kind === 'recipient_terms' && p.orgKind !== 'recipient') throw new RecordError('Recipient terms are accepted by recipients', 403);
  const counterparty = (await tx.query<{ kind: string }>('SELECT kind::text FROM organisation WHERE id::text=$1', [counterpartyOrgId])).rows[0];
  if (counterparty?.kind !== 'maker') throw new RecordError('The counterparty must be the maker', 400);
  let template = deps.templates.current(CONTRACT_DOC[kind], language);
  if (kind === 'recipient_terms') {
    const cat = (await tx.query<{ terms_template_id: string; terms_template_version: string }>(
      `SELECT rc.terms_template_id, rc.terms_template_version FROM organisation o JOIN recipient_category rc ON rc.id = o.recipient_category_id
        WHERE o.id=$1`, [p.orgId])).rows[0];
    if (!cat) throw new RecordError('Recipient has no category; ask the maker to classify it first', 409);
    template = deps.templates.get(cat.terms_template_id, cat.terms_template_version); // terms bound to the category (R14)
  }
  if (kind === 'nda') {
    const ok = (await tx.query(`SELECT count(*)::int AS n FROM datapoint WHERE id::text = ANY($1) AND trade_secret`, [datapointIds])).rows[0] as { n: number };
    if (ok.n !== new Set(datapointIds).size) throw new RecordError('NDAs only cover data points flagged as trade secrets');
  }
  const ctx = await partiesContext(tx, p.orgId, counterpartyOrgId, datapointIds);
  const rendered = await render(template, ctx, deps.config.documentFont);
  return storeDocument(tx, template, { contract: kind, orgId: p.orgId, counterpartyOrgId, datapointIds }, rendered);
}

export async function approveDocument(tx: Tx, p: Principal, documentId: string): Promise<void> {
  const r = await tx.query(`UPDATE document SET status='approved', approved_by=$2, approved_at=now() WHERE id::text=$1 AND status='draft'`, [documentId, p.id]);
  if (!r.rowCount) throw new RecordError('Document not found or already approved', 404);
}

/** Records acceptance of an approved contract document by the party it was prepared for (R7, R10, R14). */
export async function acceptContract(tx: Tx, p: Principal, documentId: string): Promise<string> {
  const d = (await tx.query<{ status: string; template_id: string; template_version: string; sha256: string; subject: { contract?: string; orgId?: string; counterpartyOrgId?: string; datapointIds?: string[] } }>(
    'SELECT status::text, template_id, template_version, sha256, subject FROM document WHERE id::text=$1 FOR UPDATE', [documentId])).rows[0];
  if (!d || !d.subject.contract) throw new RecordError('Contract document not found', 404);
  if (d.subject.orgId !== p.orgId) throw new RecordError('This contract was prepared for another organisation', 403);
  if (d.status !== 'approved') throw new RecordError('The contract has not been approved yet', 409);
  const dup = await tx.query('SELECT 1 FROM contract WHERE document_id::text=$1', [documentId]);
  if (dup.rowCount) throw new RecordError('Already accepted', 409);
  return (await tx.query<{ id: string }>(`INSERT INTO contract (kind, template_id, template_version, org_id, counterparty_org_id, datapoint_ids, document_id, doc_sha256, accepted_by)
      VALUES ($1,$2,$3,$4,$5,$6::uuid[],$7,$8,$9) RETURNING id::text`,
    [d.subject.contract, d.template_id, d.template_version, p.orgId, d.subject.counterpartyOrgId, d.subject.datapointIds ?? [], documentId, d.sha256, p.id])).rows[0]!.id;
}

export interface GrantInput {
  readonly recipientOrgId: string; readonly datapointIds: readonly string[]; readonly channels: readonly Channel[];
  readonly purpose: string; readonly expiresAt: Date;
}

/** Creates a customer's grant to a third party (R12) with its Art. 9 quote; gatekeepers are refused (R13). */
export async function createGrant(tx: Tx, deps: Deps, p: Principal, g: GrantInput): Promise<{ id: string; compensation: unknown }> {
  if (p.orgKind !== 'customer') throw new RecordError('Only machine owners grant access', 403);
  if (g.datapointIds.length === 0 || g.channels.length === 0) throw new RecordError('Choose data points and at least one channel');
  if (!g.channels.every((c) => CHANNELS.includes(c))) throw new RecordError('Unknown channel');
  if (g.purpose.trim() === '') throw new RecordError('State the purpose agreed with the recipient (Art. 6(1))');
  if (!(g.expiresAt.getTime() > Date.now())) throw new RecordError('The expiry must be in the future');
  const rec = (await tx.query<{ kind: string; name: string; group_identifier: string | null; sme_flag: boolean; non_profit_research: boolean;
    has_non_sme_partner_or_linked: boolean; verified_at: Date | null; formatting_cents: number | null; dissemination_cents: number | null;
    storage_cents: number | null; investment_share_cents: number | null; margin_rate: string | null }>(
    `SELECT o.kind::text, o.name, o.group_identifier, o.sme_flag, o.non_profit_research, o.has_non_sme_partner_or_linked, o.verified_at,
       rc.formatting_cents, rc.dissemination_cents, rc.storage_cents, rc.investment_share_cents, rc.margin_rate::text
     FROM organisation o LEFT JOIN recipient_category rc ON rc.id = o.recipient_category_id WHERE o.id::text=$1`, [g.recipientOrgId])).rows[0];
  if (!rec || rec.kind !== 'recipient') throw new RecordError('Recipient not found', 404);
  if (isGatekeeper(deps.config.gatekeepers, rec)) throw new RecordError('Designated gatekeepers are not eligible third parties (Art. 5(3))', 403);
  if (!rec.verified_at || rec.formatting_cents === null) throw new RecordError('The recipient has not been verified and classified by the maker yet', 409);
  const owned = (await tx.query(`SELECT 1 FROM datapoint d JOIN machine m ON m.model_id = d.model_id
      WHERE d.id::text = ANY($1) AND d.status='published' AND m.owner_org_id=$2 GROUP BY d.id`, [g.datapointIds, p.orgId])).rowCount;
  if (owned !== new Set(g.datapointIds).size) throw new RecordError('Grants may only cover published data points of your machines');
  const compensation = quoteCompensation({
    formattingCents: rec.formatting_cents, disseminationCents: rec.dissemination_cents ?? 0, storageCents: rec.storage_cents ?? 0,
    investmentShareCents: rec.investment_share_cents ?? 0, marginRate: Number(rec.margin_rate),
    recipientCostCapped: (rec.sme_flag || rec.non_profit_research) && !rec.has_non_sme_partner_or_linked,
  });
  const id = (await tx.query<{ id: string }>(`INSERT INTO "grant" (customer_org_id, recipient_org_id, datapoint_ids, channels, purpose, expires_at, compensation, created_by)
      VALUES ($1,$2,$3::uuid[],$4,$5,$6,$7,$8) RETURNING id::text`,
    [p.orgId, g.recipientOrgId, g.datapointIds, g.channels, g.purpose.trim(), g.expiresAt, JSON.stringify(compensation), p.id])).rows[0]!.id;
  return { id, compensation };
}

export async function revokeGrant(tx: Tx, p: Principal, grantId: string): Promise<void> {
  const r = await tx.query('UPDATE "grant" SET revoked_at=now() WHERE id::text=$1 AND customer_org_id=$2 AND revoked_at IS NULL', [grantId, p.orgId]);
  if (!r.rowCount) throw new RecordError('Active grant not found', 404);
}

export async function recordLegalBasis(tx: Tx, p: Principal, customerOrgId: string, datapointId: string, basis: string): Promise<void> {
  if (basis.trim() === '') throw new RecordError('State the GDPR legal basis (Art. 4(12), 5(7))');
  const dp = (await tx.query<{ personal_data: boolean }>('SELECT personal_data FROM datapoint WHERE id::text=$1', [datapointId])).rows[0];
  if (!dp?.personal_data) throw new RecordError('Only personal-data points need a legal basis');
  await tx.query(`INSERT INTO legal_basis (customer_org_id, datapoint_id, basis, recorded_by) VALUES ($1,$2,$3,$4)
      ON CONFLICT (customer_org_id, datapoint_id) DO UPDATE SET basis=EXCLUDED.basis, recorded_by=EXCLUDED.recorded_by, recorded_at=now()`,
    [customerOrgId, datapointId, basis.trim(), p.id]);
}

// ── Requests and decisions ────────────────────────────────────────────────────────────────────────

export async function createRequest(tx: Tx, deps: Deps, p: Principal, kind: 'access' | 'share', machineId: string,
  datapointIds: readonly string[], recipientOrgId: string | null): Promise<string> {
  if (p.orgKind !== 'customer') throw new RecordError('Requests are made by the machine owner', 403);
  if ((kind === 'share') !== (recipientOrgId !== null)) throw new RecordError('Share requests name a recipient; access requests do not');
  const owned = await tx.query('SELECT 1 FROM machine WHERE id::text=$1 AND owner_org_id=$2', [machineId, p.orgId]);
  if (!owned.rowCount) throw new RecordError('Machine not found', 404);
  const due = new Date(Date.now() + deps.config.requestDeadlineHours * 3_600_000);
  return (await tx.query<{ id: string }>(`INSERT INTO request (kind, requester_principal_id, requester_org_id, machine_id, datapoint_ids, recipient_org_id, due_at)
      VALUES ($1,$2,$3,$4,$5::uuid[],$6,$7) RETURNING id::text`, [kind, p.id, p.orgId, machineId, datapointIds, recipientOrgId, due])).rows[0]!.id;
}

export async function transition(tx: Tx, requestId: string, to: RequestState): Promise<void> {
  const cur = (await tx.query<{ state: RequestState }>('SELECT state::text AS state FROM request WHERE id::text=$1 FOR UPDATE', [requestId])).rows[0];
  if (!cur) throw new RecordError('Request not found', 404);
  if (!canTransition(cur.state, to)) throw new RecordError(`Cannot move a request from ${cur.state} to ${to}`, 409);
  await tx.query(`UPDATE request SET state=$2, decided_at = CASE WHEN $2 IN ('granted','withheld','refused') THEN now() ELSE decided_at END
      WHERE id::text=$1`, [requestId, to]);
}

/** Automatic grant after the policy decision point allowed everything requested. */
export async function recordAutomaticGrant(tx: Tx, requestId: string, datapointIds: readonly string[]): Promise<void> {
  await transition(tx, requestId, 'granted');
  await tx.query(`INSERT INTO decision (request_id, outcome, justification, datapoint_ids) VALUES ($1,'granted','Allowed by policy',$2::uuid[])`,
    [requestId, datapointIds]);
}

/**
 * A legal officer withholds or refuses. Generates the decision letter and the authority notification as
 * drafts for approval (R8, Art. 4(2),(7),(8), 5(10),(11)).
 */
export async function decide(tx: Tx, deps: Deps, p: Principal, requestId: string, d: DecisionInput, language: string): Promise<string> {
  const problems = validateDecision(d);
  if (problems.length) throw new RecordError(problems.join('; '));
  const r = (await tx.query<{ requester_org_id: string; recipient_org_id: string | null; maker_org_id: string; state: RequestState }>(
    `SELECT rq.requester_org_id::text, rq.recipient_org_id::text, pm.maker_org_id::text, rq.state::text AS state FROM request rq
       JOIN machine m ON m.id = rq.machine_id JOIN product_model pm ON pm.id = m.model_id WHERE rq.id::text=$1`, [requestId])).rows[0];
  if (!r) throw new RecordError('Request not found', 404);
  if (r.state === 'received') await transition(tx, requestId, 'evaluated');
  await transition(tx, requestId, d.outcome);
  let letter: string | null = null, notice: string | null = null;
  if (d.outcome !== 'granted') {
    const addressee = r.recipient_org_id ?? r.requester_org_id;
    const ctx = { ...(await partiesContext(tx, addressee, r.maker_org_id, d.datapointIds)),
      'decision.outcome': d.outcome, 'decision.ground': d.ground ?? '', 'decision.justification': d.justification.trim(), 'request.id': requestId };
    for (const kind of ['decision_letter', 'authority_notice'] as const) {
      const t = deps.templates.current(kind, language);
      const id = await storeDocument(tx, t, { request: requestId, kind }, await render(t, ctx, deps.config.documentFont));
      if (kind === 'decision_letter') letter = id; else notice = id;
    }
  }
  return (await tx.query<{ id: string }>(`INSERT INTO decision (request_id, outcome, ground, justification, datapoint_ids, letter_document_id, authority_document_id, decided_by)
      VALUES ($1,$2,$3,$4,$5::uuid[],$6,$7,$8) RETURNING id::text`,
    [requestId, d.outcome, d.ground, d.justification.trim(), d.datapointIds, letter, notice, p.id])).rows[0]!.id;
}

/** Evidence that comparable recipients get identical terms and compensation (R14, Art. 8(3)). */
export async function nonDiscriminationReport(tx: Tx, categoryId: string) {
  return (await tx.query(`SELECT o.id, o.name, o.sme_flag, o.non_profit_research, rc.terms_template_id, rc.terms_template_version,
      (SELECT json_agg(json_build_object('template_version', c.template_version, 'accepted_at', c.accepted_at))
         FROM contract c WHERE c.org_id = o.id AND c.kind = 'recipient_terms') AS accepted_terms,
      (SELECT json_agg(json_build_object('grant', g.id, 'total_cents', (g.compensation->>'totalCents')::int, 'capped', (g.compensation->>'capped')::boolean))
         FROM "grant" g WHERE g.recipient_org_id = o.id) AS grants
    FROM organisation o JOIN recipient_category rc ON rc.id = o.recipient_category_id WHERE rc.id::text=$1 ORDER BY o.name`, [categoryId])).rows;
}
