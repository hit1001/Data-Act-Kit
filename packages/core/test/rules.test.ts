import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applicability, type MakerProfile } from '../src/applicability.ts';
import { quoteCompensation } from '../src/compensation.ts';
import { canTransition, deadlineAlerts, validateDecision } from '../src/requests.ts';
import { exportFingerprint, localKek, newDataKey, open, seal, signWebhook } from '../src/crypto.ts';
import { parseEdgeBatch, ValidationError } from '../src/validate.ts';

const maker = (o: Partial<MakerProfile>): MakerProfile =>
  ({ size: 'large', hasNonSmallPartnerOrLinked: false, subcontracted: false, mediumSince: null, ...o });
const d = (s: string) => new Date(s);

test('Art. 7 / Art. 50 applicability', () => {
  const now = d('2026-11-18T00:00:00Z');
  assert.equal(applicability(maker({ size: 'small' }), d('2026-10-01'), now).chapterII, false);
  assert.equal(applicability(maker({ size: 'small', hasNonSmallPartnerOrLinked: true }), d('2026-10-01'), now).chapterII, true);
  assert.equal(applicability(maker({ size: 'micro', subcontracted: true }), d('2026-10-01'), now).chapterII, true);
  const large = applicability(maker({}), d('2026-10-01'), now);
  assert.deepEqual([large.chapterII, large.art3_1ByDesign], [true, true]);
  assert.equal(applicability(maker({}), d('2026-09-12T00:00:00Z'), now).art3_1ByDesign, false);
  const newMedium = applicability(maker({ size: 'medium', mediumSince: d('2026-03-01') }), d('2020-01-01'), now);
  assert.equal(newMedium.chapterII, false);
  assert.deepEqual(newMedium.changesAt, d('2027-03-01'));
  const newProduct = applicability(maker({ size: 'medium', mediumSince: d('2015-01-01') }), d('2026-06-01'), now);
  assert.deepEqual([newProduct.chapterII, newProduct.changesAt?.toISOString()], [false, '2027-06-01T00:00:00.000Z']);
  assert.equal(applicability(maker({ size: 'medium', mediumSince: d('2015-01-01') }), d('2024-01-01'), now).chapterII, true);
  assert.throws(() => applicability(maker({ size: 'medium' }), d('2024-01-01'), now));
  assert.equal(applicability(maker({}), d('2024-01-01'), d('2025-01-01')).chapterII, false);
});

test('Art. 9 compensation: cost cap for SMEs, itemised basis otherwise', () => {
  const base = { formattingCents: 1000, disseminationCents: 500, storageCents: 250, investmentShareCents: 2000, marginRate: 0.1 };
  const sme = quoteCompensation({ ...base, recipientCostCapped: true });
  assert.deepEqual([sme.totalCents, sme.capped, sme.lines.length], [1750, true, 3]);
  const big = quoteCompensation({ ...base, recipientCostCapped: false });
  assert.deepEqual([big.totalCents, big.lines.length], [4125, 5]);
  assert.throws(() => quoteCompensation({ ...base, storageCents: -1, recipientCostCapped: false }), RangeError);
  assert.throws(() => quoteCompensation({ ...base, formattingCents: 1.5, recipientCostCapped: false }), RangeError);
});

test('request state machine and decision validation', () => {
  assert.ok(canTransition('received', 'evaluated'));
  assert.ok(!canTransition('received', 'granted'));
  assert.ok(!canTransition('refused', 'granted'));
  assert.deepEqual(validateDecision({ outcome: 'granted', ground: null, justification: '', datapointIds: ['a'] }), []);
  assert.equal(validateDecision({ outcome: 'withheld', ground: null, justification: 'x', datapointIds: ['a'] }).length, 1);
  assert.equal(validateDecision({ outcome: 'refused', ground: 'trade_secret_measures_missing', justification: 'x', datapointIds: ['a'] }).length, 1);
  assert.deepEqual(validateDecision({ outcome: 'withheld', ground: 'trade_secret_measures_missing', justification: 'NDA not signed', datapointIds: ['a'] }), []);
  assert.equal(validateDecision({ outcome: 'refused', ground: 'security_risk', justification: ' ', datapointIds: [] }).length, 2);
  const [a50, a90] = deadlineAlerts(d('2026-01-01T00:00:00Z'), d('2026-01-01T10:00:00Z'));
  assert.deepEqual([a50?.at.toISOString(), a90?.at.toISOString()], ['2026-01-01T05:00:00.000Z', '2026-01-01T09:00:00.000Z']);
});

test('envelope encryption, webhook signatures, fingerprints', async () => {
  const kek = localKek('k1', newDataKey());
  const dek = newDataKey();
  const wrapped = await kek.wrap(dek, 'dp:1');
  assert.deepEqual(await kek.unwrap(wrapped, 'dp:1'), dek);
  await assert.rejects(kek.unwrap(wrapped, 'dp:2'));
  const sealed = seal(dek, Buffer.from('42.5'), 'r:1');
  assert.equal(open(dek, sealed, 'r:1').toString(), '42.5');
  assert.throws(() => open(dek, sealed, 'r:2'));
  assert.match(signWebhook('s', '{}', 1), /^t=1,v1=[0-9a-f]{64}$/);
  assert.notEqual(exportFingerprint('s', 'r1', 'g', 'e'), exportFingerprint('s', 'r2', 'g', 'e'));
});

test('edge batch validation rejects malformed input', () => {
  const ok = parseEdgeBatch({ deviceId: 'dev-1', seq: 3, readings: [{ datapointId: 'temp', ts: '2026-11-18T00:00:00Z', value: 1.5 }] });
  assert.equal(ok.readings.length, 1);
  for (const bad of [null, {}, { deviceId: 'a b', seq: 1, readings: [] }, { deviceId: 'd', seq: -1, readings: [{}] },
    { deviceId: 'd', seq: 1, readings: [{ datapointId: 't', ts: 'nope', value: 1 }] },
    { deviceId: 'd', seq: 1, readings: [{ datapointId: 't', ts: '2026-01-01T00:00:00Z', value: Infinity }] }]) {
    assert.throws(() => parseEdgeBatch(bad), ValidationError);
  }
});
