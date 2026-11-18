// Envelope encryption for trade-secret data points (design §5.3) and HMAC helpers (§5.6, §8).
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALG = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;

function assertKey(key: Buffer): void {
  if (key.length !== 32) throw new RangeError('AES-256 keys must be 32 bytes');
}

/** Ciphertext layout: iv(12) | tag(16) | data. `aad` binds the ciphertext to its context. */
export function seal(key: Buffer, plaintext: Buffer, aad: string): Buffer {
  assertKey(key);
  const iv = randomBytes(IV_BYTES);
  const c = createCipheriv(ALG, key, iv);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]);
}

export function open(key: Buffer, sealed: Buffer, aad: string): Buffer {
  assertKey(key);
  if (sealed.length < IV_BYTES + TAG_BYTES) throw new Error('Ciphertext too short');
  const d = createDecipheriv(ALG, key, sealed.subarray(0, IV_BYTES));
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(sealed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
  return Buffer.concat([d.update(sealed.subarray(IV_BYTES + TAG_BYTES)), d.final()]);
}

/** Wraps a data key with the key-encryption key held outside the database. */
export interface KeyEncryptionKey {
  readonly id: string;
  wrap(dataKey: Buffer, context: string): Promise<Buffer>;
  unwrap(wrapped: Buffer, context: string): Promise<Buffer>;
}

/** KEK read from a secret file (Docker/Kubernetes secret, design §8). Vault/KMS implement the same interface. */
export function localKek(id: string, key: Buffer): KeyEncryptionKey {
  assertKey(key);
  return {
    id,
    wrap: async (dataKey, context) => seal(key, dataKey, `kek:${id}:${context}`),
    unwrap: async (wrapped, context) => open(key, wrapped, `kek:${id}:${context}`),
  };
}

export const newDataKey = (): Buffer => randomBytes(32);

export function hmacHex(secret: string | Buffer, message: string): string {
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}

export function hmacEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex');
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}

/** Webhook signature header value: `t=<unix>,v1=<hmac(t.body)>` (design §5.6). */
export function signWebhook(secret: string, body: string, unixSeconds: number): string {
  return `t=${unixSeconds},v1=${hmacHex(secret, `${unixSeconds}.${body}`)}`;
}

/** Per-recipient fingerprint included in export metadata, to trace misuse (Art. 11, design §8). */
export function exportFingerprint(secret: string, recipientOrgId: string, grantId: string, exportId: string): string {
  return hmacHex(secret, `${recipientOrgId}|${grantId}|${exportId}`).slice(0, 32);
}
