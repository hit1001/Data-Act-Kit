// Catalogue service (design §5.4): imports, human review, versioned publishing and export.
import { XMLParser } from 'fast-xml-parser';
import { newDataKey, type DataType, type KeyEncryptionKey } from '@dak/core';
import type { Tx } from './db.ts';

export interface ImportedPoint { readonly name: string; readonly sourceAddress: string; readonly dtype: DataType; readonly unitUcum: string | null; readonly rateHz: number | null; readonly description: string | null }
export interface ImportResult { readonly points: readonly ImportedPoint[]; readonly skipped: readonly { readonly address: string; readonly reason: string }[] }

const NUMERIC = new Set(['Double', 'Float', 'Int16', 'Int32', 'Int64', 'UInt16', 'UInt32', 'UInt64', 'Byte', 'SByte',
  'i=2', 'i=3', 'i=4', 'i=5', 'i=6', 'i=7', 'i=8', 'i=9', 'i=10', 'i=11']);
const BOOLEAN = new Set(['Boolean', 'i=1']);
const STRING = new Set(['String', 'LocalizedText', 'DateTime', 'i=12', 'i=21', 'i=13']);

function mapOpcType(t: string): DataType | null {
  if (NUMERIC.has(t)) return 'number';
  if (BOOLEAN.has(t)) return 'boolean';
  if (STRING.has(t)) return 'string';
  return null;
}

const text = (v: unknown): string | null => {
  if (typeof v === 'string') return v.trim() || null;
  if (v && typeof v === 'object' && '#text' in v) return String((v as { '#text': unknown })['#text']).trim() || null;
  return null;
};

/** OPC UA NodeSet2 XML: every UAVariable becomes a data point. Types it cannot map are reported, not guessed. */
export function parseNodeSet2(xml: string): ImportResult {
  const doc = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '', isArray: (n) => n === 'UAVariable' }).parse(xml) as
    { UANodeSet?: { UAVariable?: Record<string, unknown>[] } };
  if (!doc.UANodeSet) throw new Error('Not an OPC UA NodeSet2 document');
  const points: ImportedPoint[] = [];
  const skipped: { address: string; reason: string }[] = [];
  for (const v of doc.UANodeSet.UAVariable ?? []) {
    const address = String(v['NodeId'] ?? '');
    const dtype = mapOpcType(String(v['DataType'] ?? ''));
    if (!address) { skipped.push({ address: '(no NodeId)', reason: 'missing NodeId' }); continue; }
    if (!dtype) { skipped.push({ address, reason: `unsupported DataType ${String(v['DataType'] ?? '(none)')}` }); continue; }
    points.push({
      name: text(v['DisplayName']) ?? String(v['BrowseName'] ?? address), sourceAddress: address, dtype,
      unitUcum: null, rateHz: null, description: text(v['Description']),
    });
  }
  return { points, skipped };
}

/** Tag list CSV with header `name,source_address,dtype[,unit_ucum][,rate_hz][,description]` (README). */
export function parseTagCsv(csv: string): ImportResult {
  const rows = csv.split(/\r?\n/).filter((l) => l.trim() !== '').map(splitCsvLine);
  const header = rows.shift()?.map((h) => h.trim().toLowerCase()) ?? [];
  for (const col of ['name', 'source_address', 'dtype']) if (!header.includes(col)) throw new Error(`CSV header must include ${col}`);
  const col = (r: string[], name: string): string | null => {
    const i = header.indexOf(name);
    return i < 0 ? null : (r[i]?.trim() || null);
  };
  const points: ImportedPoint[] = [];
  const skipped: { address: string; reason: string }[] = [];
  for (const r of rows) {
    const address = col(r, 'source_address') ?? '';
    const dtype = col(r, 'dtype');
    const rate = col(r, 'rate_hz');
    if (!address || !col(r, 'name')) { skipped.push({ address: address || '(empty)', reason: 'name and source_address are required' }); continue; }
    if (dtype !== 'number' && dtype !== 'boolean' && dtype !== 'string') { skipped.push({ address, reason: `dtype must be number, boolean or string` }); continue; }
    if (rate !== null && !(Number(rate) > 0)) { skipped.push({ address, reason: 'rate_hz must be a positive number' }); continue; }
    points.push({ name: col(r, 'name') as string, sourceAddress: address, dtype, unitUcum: col(r, 'unit_ucum'),
      rateHz: rate === null ? null : Number(rate), description: col(r, 'description') });
  }
  return { points, skipped };
}

function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '', quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') quoted = false; else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { out.push(cur); cur = ''; } else cur += ch;
  }
  out.push(cur);
  return out;
}

/** Inserts new points as drafts; existing addresses are left untouched so reviews are never overwritten. */
export async function importPoints(tx: Tx, modelId: string, points: readonly ImportedPoint[]): Promise<{ added: number; existing: number }> {
  let added = 0;
  for (const p of points) {
    const r = await tx.query(`INSERT INTO datapoint (model_id, name, source_address, dtype, unit_ucum, rate_hz, draft_description)
      VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (model_id, source_address) DO NOTHING`,
      [modelId, p.name, p.sourceAddress, p.dtype, p.unitUcum, p.rateHz, p.description]);
    added += r.rowCount ?? 0;
  }
  return { added, existing: points.length - added };
}

export interface Review {
  readonly description: string; readonly unitUcum: string | null; readonly rateHz: number | null; readonly estBytesPerDay: number | null;
  readonly tradeSecret: boolean; readonly tsHolder: string | null; readonly personalData: boolean; readonly personalCategory: string | null;
  readonly retentionDays: number | null;
}

export class CatalogueError extends Error { override readonly name = 'CatalogueError'; }

/**
 * Records a reviewer's approval of one data point. The trade-secret and personal-data flags decide where
 * readings are stored (design §5.3), so they are fixed once the point has been published.
 */
export async function reviewPoint(tx: Tx, kek: KeyEncryptionKey, datapointId: string, reviewerId: string, r: Review): Promise<void> {
  const cur = (await tx.query<{ version: number; trade_secret: boolean; personal_data: boolean }>(
    'SELECT version, trade_secret, personal_data FROM datapoint WHERE id = $1 FOR UPDATE', [datapointId])).rows[0];
  if (!cur) throw new CatalogueError('Data point not found');
  if (cur.version > 0 && (cur.trade_secret !== r.tradeSecret || cur.personal_data !== r.personalData)) {
    throw new CatalogueError('Trade-secret and personal-data flags cannot change after publication');
  }
  if (r.description.trim() === '') throw new CatalogueError('A description is required');
  if (r.tradeSecret && !r.tsHolder) throw new CatalogueError('Name the trade secret holder (Art. 3(3)(h))');
  if (r.personalData && !r.personalCategory) throw new CatalogueError('Name the category of personal data');
  await tx.query(`UPDATE datapoint SET description=$2, unit_ucum=$3, rate_hz=$4, est_bytes_per_day=$5, trade_secret=$6, ts_holder=$7,
      personal_data=$8, personal_category=$9, retention_days=$10, reviewed_by=$11, reviewed_at=now() WHERE id=$1`,
    [datapointId, r.description.trim(), r.unitUcum, r.rateHz, r.estBytesPerDay, r.tradeSecret, r.tsHolder, r.personalData,
      r.personalCategory, r.retentionDays, reviewerId]);
  if (r.tradeSecret) {
    const exists = (await tx.query('SELECT 1 FROM data_key WHERE datapoint_id = $1', [datapointId])).rowCount;
    if (!exists) await tx.query('INSERT INTO data_key (datapoint_id, kek_id, wrapped) VALUES ($1,$2,$3)',
      [datapointId, kek.id, await kek.wrap(newDataKey(), `dp:${datapointId}`)]);
  }
}

/** Publishes all reviewed points of a model as a new catalogue version and stores an immutable snapshot. */
export async function publish(tx: Tx, modelId: string, publisherId: string): Promise<number> {
  const model = (await tx.query<{ catalogue_version: number }>('SELECT catalogue_version FROM product_model WHERE id=$1 FOR UPDATE', [modelId])).rows[0];
  if (!model) throw new CatalogueError('Model not found');
  const version = model.catalogue_version + 1;
  const changed = await tx.query(`UPDATE datapoint SET status='published', version=$2 WHERE model_id=$1 AND reviewed_by IS NOT NULL
      AND (status='draft' OR reviewed_at > (SELECT coalesce(max(published_at), '-infinity') FROM catalogue_version WHERE model_id=$1))`,
    [modelId, version]);
  if (!changed.rowCount) throw new CatalogueError('Nothing reviewed since the last publication');
  await tx.query('UPDATE product_model SET catalogue_version=$2 WHERE id=$1', [modelId, version]);
  await tx.query('INSERT INTO catalogue_version (model_id, version, snapshot, published_by) VALUES ($1,$2,$3,$4)',
    [modelId, version, JSON.stringify(await exportCatalogue(tx, modelId)), publisherId]);
  return version;
}

export interface CatalogueEntry {
  readonly id: string; readonly name: string; readonly description: string; readonly unit_ucum: string | null; readonly dtype: DataType;
  readonly rate_hz: number | null; readonly est_bytes_per_day: number | null; readonly trade_secret: boolean;
  readonly trade_secret_holder: string | null; readonly personal_data: boolean; readonly retention_days: number | null; readonly version: number;
}

/** The published catalogue: the metadata delivered with every export (R1, R4). */
export async function exportCatalogue(tx: Tx, modelId: string): Promise<{ modelId: string; datapoints: CatalogueEntry[] }> {
  const rows = (await tx.query<CatalogueEntry>(`SELECT id, name, description, unit_ucum, dtype, rate_hz, est_bytes_per_day::float8 AS est_bytes_per_day,
      trade_secret, ts_holder AS trade_secret_holder, personal_data, retention_days, version
      FROM datapoint WHERE model_id=$1 AND status='published' ORDER BY name`, [modelId])).rows;
  return { modelId, datapoints: rows };
}

export const CATALOGUE_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'Data Act kit catalogue',
  type: 'object',
  required: ['modelId', 'datapoints'],
  properties: {
    modelId: { type: 'string', format: 'uuid' },
    datapoints: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'name', 'description', 'dtype', 'trade_secret', 'personal_data', 'version'],
        properties: {
          id: { type: 'string', format: 'uuid' }, name: { type: 'string' }, description: { type: 'string' },
          unit_ucum: { type: ['string', 'null'], description: 'UCUM unit code' },
          dtype: { enum: ['number', 'boolean', 'string'] }, rate_hz: { type: ['number', 'null'] },
          est_bytes_per_day: { type: ['number', 'null'] }, trade_secret: { type: 'boolean' },
          trade_secret_holder: { type: ['string', 'null'] }, personal_data: { type: 'boolean' },
          retention_days: { type: ['integer', 'null'] }, version: { type: 'integer' },
        },
      },
    },
  },
} as const;
