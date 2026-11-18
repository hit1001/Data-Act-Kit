// Process wiring shared by the api, ingest and worker entry points.
import { readFileSync } from 'node:fs';
import mqtt, { type MqttClient } from 'mqtt';
import type pg from 'pg';
import { deadlineAlerts, localKek, parseEdgeBatch, ValidationError, type KeyEncryptionKey } from '@dak/core';
import { pruneAccessLog } from './bootstrap.ts';
import { loadConfig, readKey, type Config } from './config.ts';
import { createPool, withScope } from './db.ts';
import { deliverWebhooks, pushFanout, TOPIC_READINGS, type LiveMessage } from './live.ts';
import { ingestBatch, Keyring } from './readings.ts';

export interface Runtime { readonly config: Config; readonly pool: pg.Pool; readonly kek: KeyEncryptionKey; readonly keyring: Keyring }

export function boot(): Runtime {
  const config = loadConfig();
  const kek = localKek(config.kek.id, readKey(config.kek.file));
  return { config, pool: createPool(config.databaseUrl), kek, keyring: new Keyring(kek) };
}

export function connectMqtt(config: Config, clientId: string, opts: Partial<mqtt.IClientOptions> = {}): Promise<MqttClient> {
  const client = mqtt.connect(config.mqtt.url, {
    clientId, username: config.mqtt.username, password: config.mqtt.password, ca: readFileSync(config.mqtt.caFile),
    protocolVersion: 5, clean: false, properties: { sessionExpiryInterval: 7 * 24 * 3600 }, reconnectPeriod: 2000, ...opts,
  });
  return new Promise((resolve, reject) => {
    client.once('connect', () => resolve(client));
    client.once('error', reject);
  });
}

/**
 * Ingest (design §5.2). The device id comes from the topic, which the broker's ACL ties to the device
 * certificate. Messages are acknowledged only after the transaction commits; on a database failure the
 * process exits so the broker redelivers the unacknowledged message (at-least-once, deduplicated by seq).
 */
export async function runIngest(rt: Runtime): Promise<MqttClient> {
  const client = await connectMqtt(rt.config, 'dak-ingest', {
    customHandleAcks: (topic, message, _packet, done) => {
      handle(topic, message).then(() => done(0), (err: Error) => {
        console.error('[ingest] fatal, exiting for redelivery:', err.message);
        process.exit(1);
      });
    },
  });
  await client.subscribeAsync('$share/ingest/devices/+/readings', { qos: 1 });

  async function handle(topic: string, message: Buffer): Promise<void> {
    const deviceId = topic.split('/')[1] ?? '';
    let raw: unknown;
    try { raw = JSON.parse(message.toString('utf8')); } catch { raw = null; }
    let batch;
    try { batch = parseEdgeBatch(raw); } catch (err) {
      if (!(err instanceof ValidationError)) throw err;
      await withScope(rt.pool, 'system', null, (tx) => tx.query('INSERT INTO quarantine (device_id, reason, payload) VALUES ($1,$2,$3)',
        [deviceId, `invalid_payload: ${err.message}`, JSON.stringify(raw ?? message.toString('utf8').slice(0, 10_000))]));
      return;
    }
    const outcome = await withScope(rt.pool, 'system', null, (tx) => ingestBatch(tx, rt.keyring, deviceId, batch));
    if (outcome.kind === 'stored' && outcome.accepted.length > 0) {
      const live: LiveMessage = { machineId: outcome.machineId, readings: outcome.accepted };
      await client.publishAsync(`${TOPIC_READINGS}${outcome.machineId}`, JSON.stringify(live), { qos: 1 });
    }
  }
  return client;
}

/** Background work: push fan-out, webhook delivery, deadline alerts (§5.8) and access-log retention (R6). */
export async function runWorker(rt: Runtime): Promise<{ stop: () => void }> {
  const client = await connectMqtt(rt.config, 'dak-worker');
  await client.subscribeAsync(`$share/worker/${TOPIC_READINGS}+`, { qos: 1 });
  client.on('message', (_topic, buf) => {
    pushFanout(rt.pool, rt.config.gatekeepers, client, JSON.parse(buf.toString('utf8')) as LiveMessage)
      .catch((err: Error) => console.error('[worker] fan-out failed:', err.message));
  });
  const openSecret = async (sealed: Buffer, endpointId: string) => (await rt.kek.unwrap(sealed, `webhook:${endpointId}`)).toString('utf8');
  const timers = [
    every(5_000, () => deliverWebhooks({ pool: rt.pool, openSecret })),
    every(60_000, () => checkDeadlines(rt)),
    every(3_600_000, () => pruneAccessLog(rt.pool, rt.config.accessLogRetentionDays)),
  ];
  return { stop: () => { timers.forEach(clearInterval); client.end(); } };
}

function every(ms: number, fn: () => Promise<unknown>): NodeJS.Timeout {
  let running = false;
  return setInterval(() => {
    if (running) return;
    running = true;
    fn().catch((err: Error) => console.error('[worker]', err.message)).finally(() => { running = false; });
  }, ms);
}

export async function checkDeadlines(rt: Runtime): Promise<number> {
  const fired = await withScope(rt.pool, 'system', null, async (tx) => {
    const open = (await tx.query<{ id: string; received_at: Date; due_at: Date; alerted_50: boolean; alerted_90: boolean }>(
      `SELECT id::text, received_at, due_at, alerted_50, alerted_90 FROM request WHERE state IN ('received','evaluated') AND NOT (alerted_50 AND alerted_90) FOR UPDATE SKIP LOCKED`)).rows;
    const out: string[] = [];
    for (const r of open) {
      for (const a of deadlineAlerts(r.received_at, r.due_at)) {
        const flag = a.threshold === 50 ? 'alerted_50' : 'alerted_90';
        if (r[flag] || a.at > new Date()) continue;
        const message = `Request ${r.id} has used ${a.threshold}% of its response time (due ${r.due_at.toISOString()})`;
        await tx.query(`UPDATE request SET ${flag}=true WHERE id=$1`, [r.id]);
        await tx.query(`INSERT INTO notification (kind, ref_id, message) VALUES ('request_deadline', $1, $2)`, [r.id, message]);
        out.push(message);
      }
    }
    return out;
  });
  if (rt.config.alertWebhookUrl) {
    for (const message of fired) {
      await fetch(rt.config.alertWebhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: message }) })
        .catch((err: Error) => console.error('[worker] alert webhook failed:', err.message));
    }
  }
  return fired.length;
}
