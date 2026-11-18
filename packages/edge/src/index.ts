// Edge connector (design §5.1): reads machine tags (OPC UA, or MQTT from an existing gateway), buffers
// on disk and publishes outbound over mutual TLS. It has no write or method-call code paths.
import { readFileSync } from 'node:fs';
import mqtt, { type MqttClient } from 'mqtt';
import { AttributeIds, ClientSubscription, DataType, MessageSecurityMode, OPCUAClient, SecurityPolicy, TimestampsToReturn, UserTokenType, type ClientSession, type DataValue } from 'node-opcua';
import { isId, type ReadingInput } from '@dak/core';
import { DurableQueue } from './queue.ts';

export interface PointMap { readonly datapointId: string; readonly source: string; readonly samplingMs: number }
export interface EdgeConfig {
  readonly deviceId: string;
  readonly broker: { readonly url: string; readonly caFile: string; readonly certFile: string; readonly keyFile: string };
  readonly source:
    | { readonly kind: 'opcua'; readonly endpoint: string; readonly securityMode: 'None' | 'Sign' | 'SignAndEncrypt'; readonly securityPolicy: string;
        readonly user: { readonly name: string; readonly passwordFile: string } | null }
    | { readonly kind: 'mqtt'; readonly url: string; readonly username: string | null; readonly passwordFile: string | null };
  readonly points: readonly PointMap[];
  readonly queue: { readonly dir: string; readonly maxAgeDays: number };
  readonly flushMs: number;
  readonly maxBatch: number;
}

export function parseEdgeConfig(raw: unknown): EdgeConfig {
  const c = raw as EdgeConfig;
  const fail = (m: string): never => { throw new Error(`Edge config: ${m}`); };
  if (!c || !isId(c.deviceId)) fail('deviceId must match [A-Za-z0-9._:-]{1,128}');
  if (!c.broker?.url?.startsWith('mqtts://')) fail('broker.url must be mqtts:// (mutual TLS only)');
  if (!c.broker.caFile || !c.broker.certFile || !c.broker.keyFile) fail('broker caFile, certFile and keyFile are required');
  if (c.source?.kind !== 'opcua' && c.source?.kind !== 'mqtt') fail('source.kind must be opcua or mqtt');
  if (!Array.isArray(c.points) || c.points.length === 0) fail('points must be a non-empty array');
  for (const p of c.points) if (!isId(p.datapointId) || !p.source || !(p.samplingMs > 0)) fail(`invalid point ${JSON.stringify(p)}`);
  if (!c.queue?.dir || !(c.queue.maxAgeDays > 0)) fail('queue.dir and queue.maxAgeDays are required');
  if (!(c.flushMs > 0) || !(c.maxBatch > 0)) fail('flushMs and maxBatch must be positive');
  return c;
}

function toValue(dv: DataValue): number | boolean | string | null {
  const v = dv.value?.value as unknown;
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'boolean' || typeof v === 'string') return v;
  if (dv.value?.dataType === DataType.DateTime && v instanceof Date) return v.toISOString();
  return null;
}

/** Read-only OPC UA subscription: monitored items on Value only. */
async function startOpcua(cfg: Extract<EdgeConfig['source'], { kind: 'opcua' }>, points: readonly PointMap[], push: (r: ReadingInput) => void): Promise<() => Promise<void>> {
  const client = OPCUAClient.create({
    applicationName: 'dataact-kit-edge', endpointMustExist: false,
    securityMode: MessageSecurityMode[cfg.securityMode], securityPolicy: cfg.securityPolicy as SecurityPolicy,
    connectionStrategy: { initialDelay: 1000, maxDelay: 30_000, maxRetry: Number.MAX_SAFE_INTEGER },
  });
  await client.connect(cfg.endpoint);
  const session: ClientSession = cfg.user
    ? await client.createSession({ type: UserTokenType.UserName, userName: cfg.user.name, password: readFileSync(cfg.user.passwordFile, 'utf8').trim() })
    : await client.createSession();
  const sub = ClientSubscription.create(session, { requestedPublishingInterval: Math.min(...points.map((p) => p.samplingMs)), publishingEnabled: true,
    requestedLifetimeCount: 600, requestedMaxKeepAliveCount: 20, maxNotificationsPerPublish: 10_000, priority: 1 });
  for (const p of points) {
    const item = await sub.monitor({ nodeId: p.source, attributeId: AttributeIds.Value },
      { samplingInterval: p.samplingMs, discardOldest: true, queueSize: 100 }, TimestampsToReturn.Source);
    item.on('changed', (dv: DataValue) => {
      const value = toValue(dv);
      if (value === null || !dv.statusCode.isGood()) return;
      push({ datapointId: p.datapointId, ts: (dv.sourceTimestamp ?? new Date()).toISOString(), value });
    });
  }
  return async () => { await sub.terminate(); await session.close(); await client.disconnect(); };
}

/** Existing gateway publishing JSON or plain values on MQTT; each point's `source` is a topic. */
async function startMqttSource(cfg: Extract<EdgeConfig['source'], { kind: 'mqtt' }>, points: readonly PointMap[], push: (r: ReadingInput) => void): Promise<() => Promise<void>> {
  const opts: mqtt.IClientOptions = {};
  if (cfg.username) opts.username = cfg.username;
  if (cfg.passwordFile) opts.password = readFileSync(cfg.passwordFile, 'utf8').trim();
  const client = await mqtt.connectAsync(cfg.url, opts);
  const byTopic = new Map(points.map((p) => [p.source, p]));
  await client.subscribeAsync([...byTopic.keys()], { qos: 1 });
  client.on('message', (topic, buf) => {
    const p = byTopic.get(topic);
    if (!p) return;
    const text = buf.toString('utf8').trim();
    let value: unknown = text;
    try { value = JSON.parse(text); } catch { /* plain string value */ }
    if (value && typeof value === 'object' && 'value' in value) value = (value as { value: unknown }).value;
    if ((typeof value === 'number' && Number.isFinite(value)) || typeof value === 'boolean' || typeof value === 'string') {
      push({ datapointId: p.datapointId, ts: new Date().toISOString(), value });
    }
  });
  return async () => { await client.endAsync(); };
}

/** Publishes the queue in order, one batch at a time, acknowledging only after the broker's PUBACK. */
export function startPublisher(queue: DurableQueue, broker: MqttClient, deviceId: string, intervalMs: number): () => void {
  let busy = false;
  const tick = async () => {
    if (busy || !broker.connected) return;
    busy = true;
    try {
      for (let b = queue.peek(); b && broker.connected; b = queue.peek()) {
        await broker.publishAsync(`devices/${deviceId}/readings`, JSON.stringify(b), { qos: 1 });
        queue.ack(b.seq);
      }
    } catch (err) { console.warn('[edge] publish failed, will retry:', (err as Error).message); } finally { busy = false; }
  };
  const t = setInterval(() => void tick(), intervalMs);
  return () => clearInterval(t);
}

export async function runEdge(cfg: EdgeConfig): Promise<() => Promise<void>> {
  const queue = new DurableQueue(cfg.queue.dir, cfg.deviceId, cfg.queue.maxAgeDays);
  let buffer: ReadingInput[] = [];
  const flush = () => { if (buffer.length) { queue.append(buffer); buffer = []; } };
  const push = (r: ReadingInput) => { buffer.push(r); if (buffer.length >= cfg.maxBatch) flush(); };
  const flushTimer = setInterval(flush, cfg.flushMs);
  const broker = mqtt.connect(cfg.broker.url, {
    clientId: cfg.deviceId, protocolVersion: 5, clean: true, reconnectPeriod: 5000,
    ca: readFileSync(cfg.broker.caFile), cert: readFileSync(cfg.broker.certFile), key: readFileSync(cfg.broker.keyFile),
  });
  broker.on('error', (err) => console.warn('[edge] broker:', err.message));
  const stopPublisher = startPublisher(queue, broker, cfg.deviceId, cfg.flushMs);
  const stopSource = cfg.source.kind === 'opcua' ? await startOpcua(cfg.source, cfg.points, push) : await startMqttSource(cfg.source, cfg.points, push);
  return async () => { clearInterval(flushTimer); flush(); stopPublisher(); await stopSource(); await broker.endAsync(); };
}
