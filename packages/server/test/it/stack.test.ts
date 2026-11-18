// End-to-end against real TimescaleDB and Mosquitto (scripts/it.sh). Each step names the requirement
// it proves (design §3, §11); test/traceability.json maps requirements to these names.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttps } from 'node:https';
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import mqtt, { type MqttClient } from 'mqtt';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from 'jose';
import { hmacHex, localKek } from '@dak/core';
import { createAuthenticator, discoverJwksUri } from '../../src/auth.ts';
import { bootstrap, pruneAccessLog } from '../../src/bootstrap.ts';
import { parseGatekeepers, readKey, type Config } from '../../src/config.ts';
import { createPool, migrate, withScope } from '../../src/db.ts';
import { TemplateStore } from '../../src/documents.ts';
import { buildApp } from '../../src/http.ts';
import { DynSec } from '../../src/integrations.ts';
import { SseHub, TOPIC_READINGS, TOPIC_REVOKED, type LiveMessage } from '../../src/live.ts';
import { Keyring } from '../../src/readings.ts';
import { checkDeadlines, connectMqtt, runIngest, runWorker, type Runtime } from '../../src/runtime.ts';

const IT = process.env['DAK_IT'] === '1';
const S = process.env['IT_SECRETS'] ?? '';
const FONT = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf';

let issuer: Server, key: CryptoKey, issuerUrl = '';
let api: ReturnType<typeof buildApp>, apiUrl = '';
let rt: Runtime, ingest: MqttClient, worker: { stop: () => void }, apiMqtt: MqttClient;
let hook: Server, hookUrl = '';
const hookBodies: { body: string; sig: string }[] = [];

async function token(sub: string, scope = ''): Promise<string> {
  return new SignJWT({ scope }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(issuerUrl).setAudience('dataact-api')
    .setSubject(sub).setIssuedAt().setExpirationTime('10m').sign(key);
}
async function call(sub: string, method: string, path: string, body?: unknown, contentType = 'application/json') {
  const headers: Record<string, string> = { Authorization: `Bearer ${await token(sub)}` };
  if (body !== undefined) headers['Content-Type'] = contentType;
  const res = await fetch(`${apiUrl}${path}`, { method, headers, body: body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body) });
  const ct = res.headers.get('content-type') ?? '';
  return { status: res.status, headers: res.headers, json: ct.includes('json') ? await res.json() as any : null, buf: ct.includes('json') ? null : Buffer.from(await res.arrayBuffer()) };
}
const ok = async (p: Promise<{ status: number; json: any }>, expect = 200) => { const r = await p; assert.equal(r.status, expect, JSON.stringify(r.json)); return r.json; };
const until = async (fn: () => Promise<boolean>, ms = 15_000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await new Promise((r) => setTimeout(r, 200)); } assert.fail('condition not met in time'); };

function device(id: string): Promise<MqttClient> {
  return mqtt.connectAsync('mqtts://localhost:58883', { clientId: id, protocolVersion: 5,
    ca: readFileSync(join(S, 'certs/ca.crt')), cert: readFileSync(join(S, `certs/device-${id}.crt`)), key: readFileSync(join(S, `certs/device-${id}.key`)) });
}

before(async () => {
  if (!IT) return;
  const pair = await generateKeyPair('RS256');
  key = pair.privateKey;
  const jwk = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  issuer = createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(req.url?.endsWith('/jwks') ? { keys: [jwk] } : { issuer: issuerUrl, jwks_uri: `${issuerUrl}/jwks` }));
  }).listen(0);
  issuerUrl = `http://127.0.0.1:${(issuer.address() as AddressInfo).port}/realms/it`;

  hook = createHttps({ cert: readFileSync(join(S, 'certs/broker.crt')), key: readFileSync(join(S, 'certs/broker.key')) }, (req, res) => {
    let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => { hookBodies.push({ body, sig: String(req.headers['x-signature']) }); res.end('ok'); });
  }).listen(0);
  hookUrl = `https://localhost:${(hook.address() as AddressInfo).port}/hook`;

  const config: Config = {
    databaseUrl: 'postgres://dak:it-only@127.0.0.1:55432/dak',
    oidc: { issuer: issuerUrl, discoveryUrl: issuerUrl, audience: 'dataact-api', portalClientId: 'portal' },
    mqtt: { url: 'mqtts://localhost:58884', username: 'dak-service', password: readFileSync(join(S, 'mqtt_service_password'), 'utf8').trim(), caFile: join(S, 'certs/ca.crt') },
    kek: { id: 'it', file: join(S, 'kek.hex') }, fingerprintSecretFile: join(S, 'fingerprint.hex'),
    accessLogRetentionDays: 30, requestDeadlineHours: 72,
    gatekeepers: parseGatekeepers({ source: 'integration test list', reviewedAt: '2026-11-01', entries: [{ name: 'Gatekeeper Platform', identifiers: ['GK-LEI'] }] }),
    templatesDir: join(import.meta.dirname, '..', 'fixtures'), documentFont: { regular: FONT, bold: FONT.replace('.ttf', '-Bold.ttf') },
    rateLimitPerMinute: 10_000, httpPort: 0, publicBaseUrl: 'https://kit.example', alertWebhookUrl: null, llm: null, mavt: null, keycloakAdmin: null,
    allowFixtureTemplates: true,
  };
  const kek = localKek('it', readKey(config.kek.file));
  rt = { config, pool: createPool(config.databaseUrl), kek, keyring: new Keyring(kek) };
  await migrate(rt.pool);
  ingest = await runIngest(rt);
  worker = await runWorker(rt);
  const hub = new SseHub();
  apiMqtt = await connectMqtt(config, 'dak-api-it', { clean: true });
  await apiMqtt.subscribeAsync([`${TOPIC_READINGS}+`, TOPIC_REVOKED], { qos: 1 });
  apiMqtt.on('message', (t, b) => t === TOPIC_REVOKED ? hub.revoke(b.toString()) : t.startsWith(TOPIC_READINGS) && hub.deliver(JSON.parse(b.toString()) as LiveMessage));
  api = buildApp({ config, pool: rt.pool, keyring: rt.keyring, kek, hub, mqtt: apiMqtt, dynsec: new DynSec(apiMqtt), keycloak: null,
    auth: createAuthenticator(rt.pool, issuerUrl, 'dataact-api', await discoverJwksUri(issuerUrl)),
    templates: new TemplateStore(config.templatesDir, true), fingerprintSecret: readKey(config.fingerprintSecretFile).toString('hex') });
  await api.listen({ host: '127.0.0.1', port: 0 });
  apiUrl = `http://127.0.0.1:${(api.server.address() as AddressInfo).port}`;
});

after(async () => {
  if (!IT) return;
  worker.stop(); ingest.end(); apiMqtt.end();
  await api.close(); issuer.close(); hook.close(); await rt.pool.end();
});

test('Data Act kit end to end', { skip: !IT && 'set DAK_IT=1 (scripts/it.sh)' }, async (t) => {
  const ids: Record<string, string> = {};
  const { makerOrgId } = await bootstrap(rt.pool, { makerName: 'Maker GmbH', size: 'large', mediumSince: null, adminOidcSub: 'maker-admin' });
  ids['maker'] = makerOrgId;

  await t.test('setup: organisations, people, recipient category', async () => {
    for (const [k, body] of [['customer', { name: 'Customer AG', kind: 'customer', verified: true }], ['other', { name: 'Other Customer', kind: 'customer', verified: true }]] as const) {
      ids[k] = (await ok(call('maker-admin', 'POST', '/api/organisations', body))).id;
    }
    for (const [sub, org, roles] of [['legal', ids['maker'], ['legal_officer']], ['reviewer', ids['maker'], ['catalogue_reviewer']],
      ['cust-admin', ids['customer'], ['customer_admin']], ['other-admin', ids['other'], ['customer_admin']]] as const) {
      await ok(call('maker-admin', 'POST', '/api/principals', { orgId: org, oidcSub: sub, roles }));
    }
    ids['category'] = (await ok(call('legal', 'POST', '/api/recipient-categories', { name: 'Service partners', termsTemplateId: 'recipient_terms-fixture',
      termsTemplateVersion: '0', formattingCents: 1000, disseminationCents: 500, storageCents: 250, investmentShareCents: 2000, marginRate: 0.1 }))).id;
    for (const [k, body] of [['recipient', { name: 'Service Partner GmbH', kind: 'recipient', smeFlag: true, verified: true, recipientCategoryId: ids['category'] }],
      ['gatekeeper', { name: 'Gatekeeper Platform', kind: 'recipient', verified: true, groupIdentifier: 'GK-LEI', recipientCategoryId: ids['category'] }]] as const) {
      ids[k] = (await ok(call('maker-admin', 'POST', '/api/organisations', body))).id;
    }
    await ok(call('maker-admin', 'POST', '/api/principals', { orgId: ids['recipient'], oidcSub: 'recipient', roles: ['recipient'] }));
    await ok(call('maker-admin', 'POST', '/api/principals', { orgId: ids['gatekeeper'], oidcSub: 'gatekeeper', roles: ['recipient'] }));
    assert.equal((await call('cust-admin', 'POST', '/api/principals', { orgId: ids['customer'], oidcSub: 'x', roles: ['customer_user'] })).status, 403);
    assert.equal((await call('nobody', 'GET', '/api/me')).status, 403);
  });

  await t.test('R1 R2 R7 R9: catalogue import, review with flags, publish, pre-sale documents', async () => {
    ids['model'] = (await ok(call('maker-admin', 'POST', '/api/models', { name: 'Mill X', placedOnMarketAt: '2026-10-01', makerSizeAtPlacement: 'large' }))).id;
    const imp = await ok(call('reviewer', 'POST', `/api/models/${ids['model']}/import`,
      'name,source_address,dtype,unit_ucum,rate_hz\nTemperature,DB1.T,number,Cel,1\nSpindle speed,DB1.S,number,/min,1\nOperator,DB1.O,string,,\nBad,DB1.B,float,,', 'text/csv'));
    assert.deepEqual([imp.added, imp.skipped.length], [3, 1]);
    const pts: any[] = await ok(call('reviewer', 'GET', `/api/models/${ids['model']}/datapoints`));
    const by = (n: string) => pts.find((p) => p.name === n).id as string;
    ids['temp'] = by('Temperature'); ids['secret'] = by('Spindle speed'); ids['person'] = by('Operator');
    const review = (o: object) => ({ description: 'Measured value of the machine', unitUcum: null, rateHz: 1, estBytesPerDay: 100_000, tradeSecret: false,
      tsHolder: null, personalData: false, personalCategory: null, retentionDays: 365, ...o });
    await ok(call('reviewer', 'PUT', `/api/datapoints/${ids['temp']}/review`, review({ unitUcum: 'Cel' })));
    await ok(call('reviewer', 'PUT', `/api/datapoints/${ids['secret']}/review`, review({ tradeSecret: true, tsHolder: 'Maker GmbH' })));
    assert.equal((await call('reviewer', 'PUT', `/api/datapoints/${ids['person']}/review`, review({ personalData: true }))).status, 400, 'category required');
    await ok(call('reviewer', 'PUT', `/api/datapoints/${ids['person']}/review`, review({ personalData: true, personalCategory: 'operator id' })));
    const pub = await ok(call('reviewer', 'POST', `/api/models/${ids['model']}/publish`));
    assert.equal(pub.version, 1);
    const sheet = pub.documents.find((d: any) => d.kind === 'presale_datasheet');
    assert.ok(sheet.documentId, JSON.stringify(pub.documents));
    assert.match(pub.documents.find((d: any) => d.kind === 'related_service_notice').problem, /Art\. 3\(3\)/);
    const pdf = await call('legal', 'GET', `/api/documents/${sheet.documentId}.pdf`);
    assert.match(pdf.buf!.toString('latin1'), /pdfuaid:part>1</);
    assert.equal((await call('reviewer', 'PUT', `/api/datapoints/${ids['secret']}/review`, review({ tradeSecret: false }))).status, 400, 'flags fixed after publication');
    const cat = await ok(call('cust-admin', 'GET', `/api/models/${ids['model']}/catalogue.json`));
    assert.equal(cat.datapoints.find((d: any) => d.id === ids['secret']).trade_secret, true, 'R7: trade secrets identified in metadata');
    const app = await ok(call('maker-admin', 'GET', `/api/models/${ids['model']}/applicability`));
    assert.deepEqual([app.chapterII, app.art3_1ByDesign], [true, true]);
  });

  await t.test('R3: related-service notice once the legal officer records the Art. 3(3) facts', async () => {
    const facts = { relatedServiceData: 'Remote monitoring events', holderUses: 'Maintenance', thirdPartyUse: 'None', holderIdentity: 'Maker GmbH, Hamburg',
      contact: 'data@maker.example', competentAuthority: 'To be named by counsel', contractDuration: 'With the service contract' };
    await ok(call('legal', 'PUT', `/api/models/${ids['model']}/related-service`, facts));
    await ok(call('reviewer', 'PUT', `/api/datapoints/${ids['temp']}/review`, { description: 'Spindle bearing temperature', unitUcum: 'Cel', rateHz: 1,
      estBytesPerDay: 100_000, tradeSecret: false, tsHolder: null, personalData: false, personalCategory: null, retentionDays: 365 }));
    const pub = await ok(call('reviewer', 'POST', `/api/models/${ids['model']}/publish`));
    assert.ok(pub.documents.find((d: any) => d.kind === 'related_service_notice').documentId);
  });

  await t.test('R6: machine linking with minimal evidence; devices; ingest with dedupe and quarantine', async () => {
    ids['machine'] = (await ok(call('maker-admin', 'POST', '/api/machines', { modelId: ids['model'], serial: 'SN-1' }))).id;
    await ok(call('maker-admin', 'POST', '/api/devices', { id: 'dev-1', machineId: ids['machine'] }));
    const lr = await ok(call('cust-admin', 'POST', '/api/link-requests', { modelId: ids['model'], serial: 'SN-1', evidenceRef: 'INV-2026-001' }));
    assert.equal((await call('cust-admin', 'POST', '/api/link-requests', { modelId: ids['model'], serial: 'SN-1', evidenceRef: 'x', email: 'a@b' })).status, 400, 'no extra data accepted');
    await ok(call('maker-admin', 'POST', `/api/link-requests/${lr.id}/approve`));
    const dev = await device('dev-1');
    const ts = new Date(Date.now() - 60_000).toISOString();
    const batch = { deviceId: 'dev-1', seq: 0, readings: [
      { datapointId: ids['temp'], ts, value: 41.5 }, { datapointId: ids['secret'], ts, value: 12000 },
      { datapointId: ids['person'], ts, value: 'op-7' }, { datapointId: '00000000-0000-0000-0000-000000000000', ts, value: 1 }] };
    await dev.publishAsync('devices/dev-1/readings', JSON.stringify(batch), { qos: 1 });
    await dev.publishAsync('devices/dev-1/readings', JSON.stringify(batch), { qos: 1 });
    await dev.publishAsync('devices/dev-2/readings', JSON.stringify({ ...batch, deviceId: 'dev-2' }), { qos: 1 }).catch(() => undefined);
    await until(async () => (await withScope(rt.pool, 'system', null, (tx) => tx.query('SELECT 1 FROM quarantine'))).rowCount === 1);
    const counts = await withScope(rt.pool, 'system', null, async (tx) => [(await tx.query('SELECT 1 FROM reading')).rowCount, (await tx.query('SELECT 1 FROM reading_secret')).rowCount]);
    assert.deepEqual(counts, [2, 1], 'duplicate batch ignored, unknown point quarantined, device ACL blocks other topics');
    ids['ts'] = ts;
    await dev.endAsync();
  });

  const read = (sub: string, dps: string[], format = 'json') => call(sub, 'GET',
    `/api/machines/${ids['machine']}/readings?datapoints=${dps.join(',')}&from=${new Date(Date.now() - 3_600_000).toISOString()}&to=${new Date(Date.now() + 60_000).toISOString()}&format=${format}`);

  await t.test('R1 R4 R7 R9: owner reads raw data with metadata; secrets and personal data withheld by default', async () => {
    const r = await ok(read('cust-admin', [ids['temp']!, ids['secret']!, ids['person']!]));
    assert.deepEqual(r.data.map((x: any) => x.value), [41.5]);
    assert.deepEqual(r.denials.map((x: any) => x.reason).sort(), ['personal_data_without_legal_basis', 'trade_secret_without_nda']);
    assert.equal(r.metadata.catalogue.datapoints[0].unit_ucum, 'Cel');
    const csv = await read('cust-admin', [ids['temp']!], 'csv');
    assert.match(csv.buf!.toString(), /^datapoint_id,ts,value\n.+,41\.5\n$/);
    assert.match(String(csv.headers.get('link')), /rel="describedby"/);
    const pq = await read('cust-admin', [ids['temp']!], 'parquet');
    assert.equal(pq.buf!.subarray(0, 4).toString(), 'PAR1');
    assert.equal((await read('other-admin', [ids['temp']!])).status, 403, 'other customers get nothing');
  });

  await t.test('design §5.3: trade-secret values are encrypted at rest; RLS isolates organisations', async () => {
    const raw = await withScope(rt.pool, 'system', null, (tx) => tx.query<{ sealed: Buffer }>('SELECT sealed FROM reading_secret'));
    assert.ok(!raw.rows[0]!.sealed.toString('latin1').includes('12000'));
    const seen = await withScope(rt.pool, 'customer', ids['other']!, (tx) => tx.query('SELECT 1 FROM reading'));
    assert.equal(seen.rowCount, 0);
    const none = await withScope(rt.pool, 'customer', null, (tx) => tx.query('SELECT 1 FROM machine'));
    assert.equal(none.rowCount, 0);
  });

  await t.test('R7 R9 R10: NDA and legal basis release data; maker use needs a data-use agreement', async () => {
    const offer = await ok(call('cust-admin', 'POST', '/api/contract-offers', { kind: 'nda', counterpartyOrgId: ids['maker'], datapointIds: [ids['secret']], language: 'en-GB' }));
    assert.equal((await call('cust-admin', 'POST', '/api/contracts', { documentId: offer.documentId })).status, 409, 'not before approval');
    await ok(call('legal', 'POST', `/api/documents/${offer.documentId}/approve`));
    await ok(call('cust-admin', 'POST', '/api/contracts', { documentId: offer.documentId }));
    await ok(call('legal', 'POST', '/api/legal-bases', { customerOrgId: ids['customer'], datapointId: ids['person'], basis: 'GDPR Art. 6(1)(b) — customer is the data subject’s employer under contract' }));
    const r = await ok(read('cust-admin', [ids['temp']!, ids['secret']!, ids['person']!]));
    assert.deepEqual(r.data.map((x: any) => x.value).sort(), [12000, 41.5, 'op-7'].sort());
    assert.equal((await read('maker-admin', [ids['temp']!])).status, 403);
    const du = await ok(call('cust-admin', 'POST', '/api/contract-offers', { kind: 'data_use', counterpartyOrgId: ids['maker'], language: 'en-GB' }));
    await ok(call('legal', 'POST', `/api/documents/${du.documentId}/approve`));
    await ok(call('cust-admin', 'POST', '/api/contracts', { documentId: du.documentId }));
    assert.deepEqual((await ok(read('maker-admin', [ids['temp']!]))).data.length, 1);
  });

  await t.test('R12 R13 R14 R15: grants with Art. 9 quote, gatekeeper refused, terms required', async () => {
    const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
    assert.equal((await call('cust-admin', 'POST', '/api/grants', { recipientOrgId: ids['gatekeeper'], datapointIds: [ids['temp']], channels: ['rest'], purpose: 'x', expiresAt })).status, 403);
    const g = await ok(call('cust-admin', 'POST', '/api/grants', { recipientOrgId: ids['recipient'], datapointIds: [ids['temp'], ids['secret']],
      channels: ['rest', 'sse', 'webhook', 'mqtt'], purpose: 'Predictive maintenance', expiresAt }));
    ids['grant'] = g.id;
    assert.deepEqual([g.compensation.totalCents, g.compensation.capped], [1750, true], 'SME recipient pays costs only');
    assert.deepEqual((await read('recipient', [ids['temp']!])).json.denials, [{ datapointId: null, reason: 'grant_terms_not_accepted' }]);
    const terms = await ok(call('recipient', 'POST', '/api/contract-offers', { kind: 'recipient_terms', counterpartyOrgId: ids['maker'], language: 'en-GB' }));
    await ok(call('legal', 'POST', `/api/documents/${terms.documentId}/approve`));
    await ok(call('recipient', 'POST', '/api/contracts', { documentId: terms.documentId }));
    const r = await read('recipient', [ids['temp']!, ids['secret']!]);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.data.map((x: any) => x.datapointId), [ids['temp']], 'secret needs the recipient’s own NDA');
    assert.match(String(r.headers.get('x-export-fingerprint')), /^[0-9a-f]{32}$/);
    const report = await ok(call('legal', 'GET', `/api/reports/non-discrimination/${ids['category']}`));
    assert.equal(report.length, 2);
  });

  await t.test('R12 R16: webhook and MQTT bridge deliver only granted data; signatures verify', async () => {
    const w = await ok(call('recipient', 'POST', `/api/grants/${ids['grant']}/webhooks`, { url: hookUrl }));
    const creds = await ok(call('recipient', 'POST', `/api/grants/${ids['grant']}/mqtt-credentials`));
    const sub = await mqtt.connectAsync('mqtts://localhost:58884', { username: creds.username, password: creds.password, ca: readFileSync(join(S, 'certs/ca.crt')), protocolVersion: 5 });
    const got: any[] = [];
    sub.on('message', (_t, b) => got.push(JSON.parse(b.toString())));
    await sub.subscribeAsync(`grants/${ids['grant']}/readings/#`, { qos: 1 });
    const denied = await sub.subscribeAsync('internal/#', { qos: 1 });
    assert.ok(denied.every((g) => g.qos >= 128), 'recipients cannot read internal topics');
    const dev = await device('dev-1');
    await dev.publishAsync('devices/dev-1/readings', JSON.stringify({ deviceId: 'dev-1', seq: 1, readings: [
      { datapointId: ids['temp'], ts: new Date().toISOString(), value: 42 }, { datapointId: ids['secret'], ts: new Date().toISOString(), value: 13000 }] }), { qos: 1 });
    await until(async () => hookBodies.length > 0 && got.length > 0, 20_000);
    const { body, sig } = hookBodies[0]!;
    const [tPart, vPart] = sig.split(',');
    assert.equal(vPart!.slice(3), hmacHex(w.secret, `${tPart!.slice(2)}.${body}`));
    for (const payload of [JSON.parse(body), got[0]]) assert.deepEqual(payload.readings.map((x: any) => x.value), [42], 'no trade secret without the recipient NDA');
    await sub.endAsync(); await dev.endAsync();
  });

  await t.test('revoking a grant ends live streams and access at once', async () => {
    const res = await fetch(`${apiUrl}/api/machines/${ids['machine']}/stream?datapoints=${ids['temp']}`, { headers: { Authorization: `Bearer ${await token('recipient')}` } });
    assert.equal(res.status, 200);
    const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
    assert.match((await reader.read()).value ?? '', /event: metadata/);
    await ok(call('cust-admin', 'DELETE', `/api/grants/${ids['grant']}`));
    let text = '';
    for (;;) { const { value, done } = await reader.read(); if (done) break; text += value; }
    assert.match(text, /event: revoked/);
    assert.equal((await read('recipient', [ids['temp']!])).status, 403);
  });

  await t.test('R8: withholding produces a decision letter and an authority notice for approval', async () => {
    const req = await ok(call('cust-admin', 'POST', '/api/requests', { kind: 'share', machineId: ids['machine'], datapointIds: [ids['secret']], recipientOrgId: ids['recipient'] }));
    assert.equal(req.state, 'evaluated');
    assert.equal((await call('legal', 'POST', `/api/requests/${req.id}/decision`, { outcome: 'refused', ground: 'trade_secret_measures_missing',
      justification: 'x', datapointIds: [ids['secret']], language: 'en-GB' })).status, 400, 'refusal needs an Art. 4(2) or 4(8) ground');
    const d = await ok(call('legal', 'POST', `/api/requests/${req.id}/decision`, { outcome: 'withheld', ground: 'trade_secret_measures_missing',
      justification: 'The recipient has not agreed the confidentiality measures for spindle speed.', datapointIds: [ids['secret']], language: 'en-GB' }));
    const docs = await withScope(rt.pool, 'system', null, (tx) => tx.query<{ kind: string; status: string }>(
      'SELECT d.kind, d.status::text FROM decision x JOIN document d ON d.id IN (x.letter_document_id, x.authority_document_id) WHERE x.id=$1', [d.decisionId]));
    assert.deepEqual(docs.rows.map((r) => `${r.kind}:${r.status}`).sort(), ['authority_notice:draft', 'decision_letter:draft']);
    const auto = await ok(call('cust-admin', 'POST', '/api/requests', { kind: 'access', machineId: ids['machine'], datapointIds: [ids['temp']] }));
    assert.equal(auto.state, 'granted');
  });

  await t.test('R6: access log is minimal and pruned; deadline alerts fire at 50% and 90%', async () => {
    const cols = await withScope(rt.pool, 'system', null, (tx) => tx.query<{ column_name: string }>(
      "SELECT column_name FROM information_schema.columns WHERE table_name='access_log' ORDER BY column_name"));
    assert.deepEqual(cols.rows.map((r) => r.column_name), ['id', 'principal_id', 'request_id', 'ts']);
    await withScope(rt.pool, 'system', null, (tx) => tx.query("UPDATE access_log SET ts = now() - interval '31 days' WHERE id = (SELECT min(id) FROM access_log)"));
    assert.equal(await pruneAccessLog(rt.pool, 30), 1);
    await withScope(rt.pool, 'system', null, (tx) => tx.query(
      "UPDATE request SET received_at = now() - interval '10 hours', due_at = now() - interval '1 hour' WHERE state = 'evaluated'"));
    assert.ok((await checkDeadlines(rt)) >= 2);
    const n = await ok(call('legal', 'GET', '/api/notifications'));
    assert.ok(n.some((x: any) => /90%/.test(x.message)));
  });
});
