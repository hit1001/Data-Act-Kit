// Validation of untrusted input crossing a trust boundary (edge MQTT payloads, catalogue imports).
import type { DataType, EdgeBatch, ReadingInput } from './types.ts';

export class ValidationError extends Error {
  override readonly name = 'ValidationError';
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

export function isId(v: unknown): v is string { return typeof v === 'string' && ID_RE.test(v); }

export function parseEdgeBatch(raw: unknown, maxReadings = 10_000): EdgeBatch {
  if (!isObj(raw)) throw new ValidationError('Batch must be an object');
  const { deviceId, seq, readings } = raw;
  if (!isId(deviceId)) throw new ValidationError('deviceId invalid');
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) throw new ValidationError('seq must be a non-negative integer');
  if (!Array.isArray(readings) || readings.length === 0 || readings.length > maxReadings) {
    throw new ValidationError(`readings must be a non-empty array of at most ${maxReadings}`);
  }
  return { deviceId, seq, readings: readings.map(parseReading) };
}

function parseReading(r: unknown, i: number): ReadingInput {
  if (!isObj(r)) throw new ValidationError(`readings[${i}] must be an object`);
  const { datapointId, ts, value } = r;
  if (!isId(datapointId)) throw new ValidationError(`readings[${i}].datapointId invalid`);
  if (typeof ts !== 'string' || Number.isNaN(Date.parse(ts))) throw new ValidationError(`readings[${i}].ts must be ISO 8601`);
  const ok = (typeof value === 'number' && Number.isFinite(value)) || typeof value === 'boolean' ||
    (typeof value === 'string' && value.length <= 4096);
  if (!ok) throw new ValidationError(`readings[${i}].value must be a finite number, boolean or string`);
  return { datapointId, ts, value: value as number | boolean | string };
}

export function valueMatchesType(value: ReadingInput['value'], dtype: DataType): boolean {
  return typeof value === dtype;
}
