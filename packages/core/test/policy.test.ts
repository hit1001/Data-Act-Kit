import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { decide, type PolicyFacts, type PolicyRequest } from '../src/policy.ts';
import type { Channel, DatapointFacts, GrantFacts, Principal, Role } from '../src/types.ts';

const now = new Date('2026-11-18T12:00:00Z');
const later = new Date('2027-01-01T00:00:00Z');
const dp = (id: string, o: Partial<DatapointFacts> = {}): DatapointFacts =>
  ({ id, modelId: 'm1', tradeSecret: false, personalData: false, status: 'published', ...o });
const principal = (o: Partial<Principal>): Principal =>
  ({ id: 'p', orgId: 'cust', orgKind: 'customer', roles: ['customer_user'], isMachineClient: false, scopes: [], ...o });
const grant = (o: Partial<GrantFacts> = {}): GrantFacts => ({
  id: 'g1', customerOrgId: 'cust', recipientOrgId: 'rec', datapointIds: ['a', 'b'], channels: ['rest'],
  expiresAt: later, revokedAt: null, termsAccepted: true, ...o,
});
const facts = (o: Partial<PolicyFacts> = {}): PolicyFacts => ({
  machine: { id: 'mac', modelId: 'm1', ownerOrgId: 'cust' },
  datapoints: [dp('a'), dp('b'), dp('secret', { tradeSecret: true }), dp('person', { personalData: true }), dp('draft', { status: 'draft' })],
  ndaCoveredDatapointIds: new Set(), legalBasisDatapointIds: new Set(), grants: [grant()],
  requesterIsGatekeeper: false, dataUseAgreement: false, ...o,
});
const req = (p: Principal, ids: string[], o: Partial<PolicyRequest> = {}): PolicyRequest =>
  ({ principal: p, purpose: 'customer_access', channel: 'rest', requestedDatapointIds: ids, now, ...o });
const reasons = (d: ReturnType<typeof decide>) => d.denials.map((x) => `${x.datapointId}:${x.reason}`);

test('customer reads own published data; secrets, personal data and drafts are excluded by default', () => {
  const d = decide(req(principal({}), ['a', 'secret', 'person', 'draft', 'nope']), facts());
  assert.deepEqual(d.allowed, ['a']);
  assert.deepEqual(reasons(d), ['secret:trade_secret_without_nda', 'person:personal_data_without_legal_basis',
    'draft:datapoint_unpublished', 'nope:datapoint_not_in_model']);
});

test('NDA releases trade secrets; a legal basis releases personal data', () => {
  const d = decide(req(principal({}), ['secret', 'person']),
    facts({ ndaCoveredDatapointIds: new Set(['secret']), legalBasisDatapointIds: new Set(['person']) }));
  assert.deepEqual(d.allowed, ['secret', 'person']);
});

test('customers cannot read machines of another organisation, or unlinked machines', () => {
  assert.deepEqual(reasons(decide(req(principal({ orgId: 'other' }), ['a']), facts())), ['null:machine_not_owned']);
  assert.deepEqual(reasons(decide(req(principal({}), ['a']), facts({ machine: { id: 'mac', modelId: 'm1', ownerOrgId: null } }))),
    ['null:machine_unlinked']);
});

test('recipients need an active grant with accepted terms on the right channel, limited to granted points', () => {
  const r = principal({ orgId: 'rec', orgKind: 'recipient', roles: ['recipient'] });
  const asRecipient = (f: Partial<PolicyFacts>, ch: Channel = 'rest', ids = ['a', 'secret', 'x']) =>
    decide(req(r, ids, { purpose: 'recipient_access', channel: ch }), facts(f));
  const ok = asRecipient({});
  assert.deepEqual(ok.allowed, ['a']);
  assert.equal(ok.grantId, 'g1');
  assert.deepEqual(reasons(asRecipient({ grants: [grant({ revokedAt: now })] })), ['null:no_active_grant']);
  assert.deepEqual(reasons(asRecipient({ grants: [grant({ expiresAt: now })] })), ['null:no_active_grant']);
  assert.deepEqual(reasons(asRecipient({ grants: [grant({ termsAccepted: false })] })), ['null:grant_terms_not_accepted']);
  assert.deepEqual(reasons(asRecipient({}, 'sse')), ['null:grant_channel_not_allowed']);
  assert.deepEqual(reasons(asRecipient({ requesterIsGatekeeper: true })), ['null:recipient_is_gatekeeper']);
});

test('machine clients must carry the grant scope', () => {
  const m = principal({ orgId: 'rec', orgKind: 'recipient', roles: ['recipient'], isMachineClient: true });
  const asClient = (scopes: string[]) => decide(req({ ...m, scopes }, ['a'], { purpose: 'recipient_access' }), facts());
  assert.deepEqual(reasons(asClient([])), ['null:grant_scope_missing']);
  assert.deepEqual(asClient(['grant:g1']).allowed, ['a']);
});

test('maker internal use requires a data-use agreement and never releases personal data without a basis', () => {
  const m = principal({ orgId: 'maker', orgKind: 'maker', roles: ['maker_admin'] });
  const asMaker = (f: Partial<PolicyFacts>) => decide(req(m, ['a', 'secret', 'person'], { purpose: 'maker_internal' }), facts(f));
  assert.deepEqual(reasons(asMaker({})), ['null:no_data_use_agreement']);
  assert.deepEqual(asMaker({ dataUseAgreement: true }).allowed, ['a', 'secret']);
});

// ── Properties (design §5.5, §11) ───────────────────────────────────────────────
const roleArb = fc.subarray<Role>(['maker_admin', 'catalogue_reviewer', 'legal_officer', 'customer_admin', 'customer_user', 'recipient']);
const principalArb = fc.record({
  id: fc.constant('p'), orgId: fc.constantFrom('cust', 'rec', 'maker', 'other'),
  orgKind: fc.constantFrom('maker', 'customer', 'recipient') as fc.Arbitrary<Principal['orgKind']>,
  roles: roleArb, isMachineClient: fc.boolean(), scopes: fc.subarray(['grant:g1', 'grant:g2']),
});
const grantArb = fc.record({
  id: fc.constantFrom('g1', 'g2'), customerOrgId: fc.constantFrom('cust', 'other'), recipientOrgId: fc.constantFrom('rec', 'other'),
  datapointIds: fc.subarray(['a', 'b', 'secret', 'person']), channels: fc.subarray<Channel>(['rest', 'sse', 'webhook', 'mqtt']),
  expiresAt: fc.constantFrom(now, later), revokedAt: fc.constantFrom(null, now), termsAccepted: fc.boolean(),
});
const factsArb = fc.record({
  machine: fc.record({ id: fc.constant('mac'), modelId: fc.constant('m1'), ownerOrgId: fc.constantFrom('cust', 'other', null) }),
  datapoints: fc.constant(facts().datapoints),
  ndaCoveredDatapointIds: fc.subarray(['secret']).map((x) => new Set(x)),
  legalBasisDatapointIds: fc.subarray(['person']).map((x) => new Set(x)),
  grants: fc.array(grantArb, { maxLength: 3 }), requesterIsGatekeeper: fc.boolean(), dataUseAgreement: fc.boolean(),
});
const reqArb = fc.record({
  principal: principalArb,
  purpose: fc.constantFrom('customer_access', 'recipient_access', 'maker_internal') as fc.Arbitrary<PolicyRequest['purpose']>,
  channel: fc.constantFrom<Channel>('rest', 'sse', 'webhook', 'mqtt'),
  requestedDatapointIds: fc.subarray(['a', 'b', 'secret', 'person', 'draft', 'zzz']), now: fc.constant(now),
});

test('property: nothing outside the request, the model, or the published catalogue is ever allowed', () => {
  fc.assert(fc.property(reqArb, factsArb, (r, f) => {
    const d = decide(r, f);
    for (const id of d.allowed) {
      assert.ok(r.requestedDatapointIds.includes(id));
      assert.ok(f.datapoints.some((x) => x.id === id && x.status === 'published'));
    }
  }), { numRuns: 5000 });
});

test('property: customers only ever read machines their organisation owns', () => {
  fc.assert(fc.property(reqArb, factsArb, (r, f) => {
    const d = decide(r, f);
    if (r.purpose === 'customer_access' && d.allowed.length > 0) assert.equal(f.machine.ownerOrgId, r.principal.orgId);
  }), { numRuns: 5000 });
});

test('property: recipients only read via an active, accepted, in-scope grant from the owner, never as a gatekeeper', () => {
  fc.assert(fc.property(reqArb, factsArb, (r, f) => {
    const d = decide(r, f);
    if (r.purpose !== 'recipient_access' || d.allowed.length === 0) return;
    assert.equal(f.requesterIsGatekeeper, false);
    const g = f.grants.find((x) => x.id === d.grantId);
    assert.ok(g);
    assert.equal(g.recipientOrgId, r.principal.orgId);
    assert.equal(g.customerOrgId, f.machine.ownerOrgId);
    assert.ok(g.revokedAt === null && g.expiresAt > now && g.termsAccepted && g.channels.includes(r.channel));
    if (r.principal.isMachineClient) assert.ok(r.principal.scopes.includes(`grant:${g.id}`));
    for (const id of d.allowed) assert.ok(g.datapointIds.includes(id));
  }), { numRuns: 5000 });
});

test('property: trade secrets and personal data are only released with an NDA or legal basis', () => {
  fc.assert(fc.property(reqArb, factsArb, (r, f) => {
    const d = decide(r, f);
    if (d.allowed.includes('person')) assert.ok(f.legalBasisDatapointIds.has('person'));
    if (d.allowed.includes('secret') && r.purpose !== 'maker_internal') assert.ok(f.ndaCoveredDatapointIds.has('secret'));
  }), { numRuns: 5000 });
});
