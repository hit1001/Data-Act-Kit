import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { parseNodeSet2, parseTagCsv } from '../src/catalogue.ts';
import { fill, render, TemplateError, TemplateStore } from '../src/documents.ts';
import { ConfigError, parseGatekeepers } from '../src/config.ts';
import { isGatekeeper } from '../src/access.ts';

test('NodeSet2 import maps known types and reports the rest', () => {
  const r = parseNodeSet2(`<?xml version="1.0"?><UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
    <UAVariable NodeId="ns=1;s=Temp" BrowseName="1:Temp" DataType="Double"><DisplayName>Spindle temperature</DisplayName><Description>Bearing temperature</Description></UAVariable>
    <UAVariable NodeId="ns=1;s=On" BrowseName="1:On" DataType="i=1"><DisplayName>Running</DisplayName></UAVariable>
    <UAVariable NodeId="ns=1;s=Img" BrowseName="1:Img" DataType="ByteString"/></UANodeSet>`);
  assert.deepEqual(r.points.map((p) => [p.name, p.dtype, p.description]), [['Spindle temperature', 'number', 'Bearing temperature'], ['Running', 'boolean', null]]);
  assert.deepEqual(r.skipped, [{ address: 'ns=1;s=Img', reason: 'unsupported DataType ByteString' }]);
  assert.throws(() => parseNodeSet2('<x/>'));
});

test('tag-list CSV import validates every row', () => {
  const r = parseTagCsv('name,source_address,dtype,unit_ucum,rate_hz\n"Temp, spindle",DB1.DBD0,number,Cel,1\nBad,DB1.X,float,,\nNo rate,DB1.Y,boolean,,0');
  assert.deepEqual(r.points.map((p) => [p.name, p.unitUcum, p.rateHz]), [['Temp, spindle', 'Cel', 1]]);
  assert.equal(r.skipped.length, 2);
  assert.throws(() => parseTagCsv('name,b\n1,2'), /source_address/);
});

test('templates: unfilled placeholders fail; fixtures load only when allowed; PDF is tagged PDF/UA', async () => {
  assert.throws(() => fill('Hi {{x}}', {}), TemplateError);
  const dir = join(import.meta.dirname, 'fixtures');
  assert.equal(new TemplateStore(dir, false).list().length, 0);
  const t = new TemplateStore(dir, true).current('presale_datasheet', 'en-GB');
  const out = await render(t, { 'model.name': 'M1', 'data.list': 'Temp', 'data.estimated_volume_per_day': '1 MB', 'data.realtime': 'yes',
    'access.portal_url': 'https://x/', 'access.api_url': 'https://x/api' },
    { regular: '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', bold: '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf' });
  const pdf = out.pdf.toString('latin1');
  assert.match(pdf, /pdfuaid:part>1</);
  assert.match(pdf, /\/StructTreeRoot/);
  assert.match(pdf, /\/Lang \(en-GB\)/);
  assert.match(pdf, /\/FontFile2/, 'fonts must be embedded');
  assert.equal(out.content.title, 'TEST FIXTURE — not legal text: M1');
  assert.match(out.sha256, /^[0-9a-f]{64}$/);
});

test('gatekeeper list must be sourced and dated; matching by name or group identifier', () => {
  assert.throws(() => parseGatekeepers({ entries: [] }), ConfigError);
  const list = parseGatekeepers({ source: 'Commission decision list', reviewedAt: '2026-11-01', entries: [{ name: 'Big Platform Inc', identifiers: ['LEI-1'] }] });
  assert.ok(isGatekeeper(list, { name: ' big platform inc ', group_identifier: null }));
  assert.ok(isGatekeeper(list, { name: 'Subsidiary GmbH', group_identifier: 'LEI-1' }));
  assert.ok(!isGatekeeper(list, { name: 'Service Partner GmbH', group_identifier: 'LEI-9' }));
});
