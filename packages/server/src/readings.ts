// Reading storage and retrieval (design §5.2, §5.3). Trade-secret values are sealed with a per-datapoint
// data key; all other values are stored raw at full resolution ("same quality", R4).
import { open, seal, type EdgeBatch, type KeyEncryptionKey, type ReadingInput } from '@dak/core';
import type { Tx } from './db.ts';

export class Keyring {
  private readonly cache = new Map<string, Buffer>();
  private readonly kek: KeyEncryptionKey;
  constructor(kek: KeyEncryptionKey) { this.kek = kek; }

  async dataKey(tx: Tx, datapointId: string): Promise<Buffer> {
    const hit = this.cache.get(datapointId);
    if (hit) return hit;
    const row = (await tx.query<{ kek_id: string; wrapped: Buffer }>('SELECT kek_id, wrapped FROM data_key WHERE datapoint_id=$1', [datapointId])).rows[0];
    if (!row) throw new Error(`No data key for trade-secret data point ${datapointId}`);
    if (row.kek_id !== this.kek.id) throw new Error(`Data key ${datapointId} is wrapped by KEK ${row.kek_id}, not the configured ${this.kek.id}`);
    const key = await this.kek.unwrap(row.wrapped, `dp:${datapointId}`);
    this.cache.set(datapointId, key);
    return key;
  }
}

interface CataloguePoint { id: string; dtype: string; status: string; trade_secret: boolean; model_id: string }

export type IngestOutcome =
  | { readonly kind: 'stored'; readonly machineId: string; readonly accepted: readonly ReadingInput[]; readonly quarantined: number }
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'quarantined'; readonly reason: string };

const aad = (machineId: string, datapointId: string, ts: string) => `r:${machineId}:${datapointId}:${new Date(ts).toISOString()}`;

/**
 * Stores one edge batch atomically. `deviceId` is the identity proven by the broker (certificate CN),
 * never the one claimed in the payload. Duplicates are recognised by sequence number.
 */
export async function ingestBatch(tx: Tx, keyring: Keyring, deviceId: string, batch: EdgeBatch): Promise<IngestOutcome> {
  const quarantine = async (reason: string, payload: unknown) => {
    await tx.query('INSERT INTO quarantine (device_id, reason, payload) VALUES ($1,$2,$3)', [deviceId, reason, JSON.stringify(payload)]);
  };
  if (batch.deviceId !== deviceId) {
    await quarantine('device_id_mismatch', batch);
    return { kind: 'quarantined', reason: 'device_id_mismatch' };
  }
  const dev = (await tx.query<{ machine_id: string; model_id: string; last_seq: string }>(
    `SELECT d.machine_id, m.model_id, d.last_seq FROM device d JOIN machine m ON m.id = d.machine_id WHERE d.id=$1 FOR UPDATE OF d`, [deviceId])).rows[0];
  if (!dev) {
    await quarantine('unknown_device', batch);
    return { kind: 'quarantined', reason: 'unknown_device' };
  }
  if (batch.seq <= Number(dev.last_seq)) return { kind: 'duplicate' };

  const ids = [...new Set(batch.readings.map((r) => r.datapointId))];
  const points = new Map((await tx.query<CataloguePoint>(
    'SELECT id::text, dtype::text, status::text, trade_secret, model_id::text FROM datapoint WHERE id::text = ANY($1)', [ids])).rows.map((p) => [p.id, p]));

  const accepted: ReadingInput[] = [];
  const rejected: { reading: ReadingInput; reason: string }[] = [];
  for (const r of batch.readings) {
    const p = points.get(r.datapointId);
    const reason = !p ? 'unknown_datapoint' : p.model_id !== dev.model_id ? 'datapoint_not_in_machine_model'
      : p.status !== 'published' ? 'datapoint_not_published' : typeof r.value !== p.dtype ? 'value_type_mismatch' : null;
    if (reason || !p) { rejected.push({ reading: r, reason: reason ?? 'unknown_datapoint' }); continue; }
    if (p.trade_secret) {
      const key = await keyring.dataKey(tx, p.id);
      await tx.query(`INSERT INTO reading_secret (machine_id, datapoint_id, ts, sealed) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
        [dev.machine_id, p.id, r.ts, seal(key, Buffer.from(JSON.stringify(r.value)), aad(dev.machine_id, p.id, r.ts))]);
    } else {
      await tx.query(`INSERT INTO reading (machine_id, datapoint_id, ts, num, bool, txt) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
        [dev.machine_id, p.id, r.ts, typeof r.value === 'number' ? r.value : null, typeof r.value === 'boolean' ? r.value : null,
          typeof r.value === 'string' ? r.value : null]);
    }
    accepted.push(r);
  }
  for (const { reading, reason } of rejected) await quarantine(reason, reading);
  await tx.query('UPDATE device SET last_seq=$2 WHERE id=$1', [deviceId, batch.seq]);
  return { kind: 'stored', machineId: dev.machine_id, accepted, quarantined: rejected.length };
}

export interface ReadingRow { readonly datapointId: string; readonly ts: string; readonly value: number | boolean | string }
export interface Page { readonly rows: readonly ReadingRow[]; readonly next: string | null }

/** Cursor = last (ts, datapointId) of the previous page, base64url-encoded. */
const encodeCursor = (r: ReadingRow) => Buffer.from(JSON.stringify([r.ts, r.datapointId])).toString('base64url');
function decodeCursor(c: string): [string, string] {
  const v = JSON.parse(Buffer.from(c, 'base64url').toString('utf8')) as unknown;
  if (!Array.isArray(v) || typeof v[0] !== 'string' || typeof v[1] !== 'string') throw new Error('Invalid cursor');
  return [v[0], v[1]];
}

/**
 * Reads already-authorised data points. Callers must pass only ids allowed by the policy decision point;
 * row-level security enforces the same rule underneath.
 */
export async function readPage(tx: Tx, keyring: Keyring, machineId: string, datapointIds: readonly string[],
  from: Date, to: Date, limit: number, cursor: string | null): Promise<Page> {
  if (datapointIds.length === 0) return { rows: [], next: null };
  const [afterTs, afterDp] = cursor ? decodeCursor(cursor) : [from.toISOString(), ''];
  const rows = (await tx.query<{ datapoint_id: string; ts: Date; num: number | null; bool: boolean | null; txt: string | null; sealed: Buffer | null }>(
    `SELECT datapoint_id::text, ts, num, bool, txt, NULL::bytea AS sealed FROM reading
       WHERE machine_id=$1 AND datapoint_id::text = ANY($2) AND ts < $4 AND (ts, datapoint_id::text) > ($3::timestamptz, $5)
     UNION ALL
     SELECT datapoint_id::text, ts, NULL, NULL, NULL, sealed FROM reading_secret
       WHERE machine_id=$1 AND datapoint_id::text = ANY($2) AND ts < $4 AND (ts, datapoint_id::text) > ($3::timestamptz, $5)
     ORDER BY ts, datapoint_id LIMIT $6`,
    [machineId, datapointIds, afterTs, to.toISOString(), afterDp, limit + 1])).rows;
  const out: ReadingRow[] = [];
  for (const r of rows.slice(0, limit)) {
    const ts = r.ts.toISOString();
    let value: number | boolean | string;
    if (r.sealed) value = JSON.parse(open(await keyring.dataKey(tx, r.datapoint_id), r.sealed, aad(machineId, r.datapoint_id, ts)).toString('utf8')) as number | boolean | string;
    else value = (r.num ?? r.bool ?? r.txt) as number | boolean | string;
    out.push({ datapointId: r.datapoint_id, ts, value });
  }
  const last = out.at(-1);
  return { rows: out, next: rows.length > limit && last ? encodeCursor(last) : null };
}
