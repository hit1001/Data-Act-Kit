// Live delivery (design §5.6): ingest publishes accepted readings on `internal/readings/<machineId>`;
// SSE streams, webhooks and the MQTT bridge fan them out after the policy decision point.
import type { ServerResponse } from 'node:http';
import { decide, signWebhook, type Principal, type ReadingInput } from '@dak/core';
import type { MqttClient } from 'mqtt';
import type pg from 'pg';
import { loadFacts } from './access.ts';
import type { GatekeeperList } from './config.ts';
import { withScope } from './db.ts';

export const TOPIC_READINGS = 'internal/readings/';
export const TOPIC_REVOKED = 'internal/grants/revoked';

export interface LiveMessage { readonly machineId: string; readonly readings: readonly ReadingInput[] }

interface Stream { readonly res: ServerResponse; readonly machineId: string; readonly allowed: ReadonlySet<string>; readonly grantId: string | null }

export class SseHub {
  private readonly streams = new Set<Stream>();

  open(res: ServerResponse, machineId: string, allowed: readonly string[], grantId: string | null, metadata: unknown): void {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write(`event: metadata\ndata: ${JSON.stringify(metadata)}\n\n`);
    const s: Stream = { res, machineId, allowed: new Set(allowed), grantId };
    this.streams.add(s);
    res.on('close', () => this.streams.delete(s));
  }

  deliver(m: LiveMessage): void {
    for (const s of this.streams) {
      if (s.machineId !== m.machineId) continue;
      const rows = m.readings.filter((r) => s.allowed.has(r.datapointId));
      if (rows.length) s.res.write(`event: readings\ndata: ${JSON.stringify(rows)}\n\n`);
    }
  }

  /** Revoking a grant ends its streams at once (design §7: revoke stops delivery). */
  revoke(grantId: string): void {
    for (const s of this.streams) {
      if (s.grantId !== grantId) continue;
      s.res.write('event: revoked\ndata: {}\n\n');
      s.res.end();
      this.streams.delete(s);
    }
  }

  get size(): number { return this.streams.size; }
}

interface PushGrant { id: string; recipient_org_id: string; channels: string[] }

/** Worker-side fan-out to webhooks (queued, signed, retried) and the MQTT bridge. */
export async function pushFanout(pool: pg.Pool, gatekeepers: GatekeeperList, mqtt: MqttClient, m: LiveMessage): Promise<void> {
  await withScope(pool, 'system', null, async (tx) => {
    const grants = (await tx.query<PushGrant>(`SELECT g.id::text, g.recipient_org_id::text, g.channels FROM "grant" g JOIN machine mc ON mc.owner_org_id = g.customer_org_id
        WHERE mc.id::text=$1 AND g.revoked_at IS NULL AND g.expires_at > now() AND g.channels && ARRAY['webhook','mqtt']`, [m.machineId])).rows;
    for (const g of grants) {
      // Push channels act for the recipient organisation as a whole; decide per channel.
      const principal: Principal = { id: 'push', orgId: g.recipient_org_id, orgKind: 'recipient', roles: ['recipient'], isMachineClient: false, scopes: [] };
      const facts = await loadFacts(tx, gatekeepers, principal, m.machineId);
      if (!facts) continue;
      const ids = [...new Set(m.readings.map((r) => r.datapointId))];
      for (const channel of ['webhook', 'mqtt'] as const) {
        if (!g.channels.includes(channel)) continue;
        const d = decide({ principal, purpose: 'recipient_access', channel, requestedDatapointIds: ids, now: new Date() }, facts);
        if (d.grantId !== g.id || d.allowed.length === 0) continue;
        const rows = m.readings.filter((r) => d.allowed.includes(r.datapointId));
        const payload = { grantId: g.id, machineId: m.machineId, readings: rows };
        if (channel === 'mqtt') {
          mqtt.publish(`grants/${g.id}/readings/${m.machineId}`, JSON.stringify(payload), { qos: 1 });
        } else {
          await tx.query(`INSERT INTO webhook_delivery (endpoint_id, payload) SELECT id, $2 FROM webhook_endpoint WHERE grant_id::text=$1 AND disabled_at IS NULL`,
            [g.id, JSON.stringify(payload)]);
        }
      }
    }
  });
}

export interface WebhookDeps { readonly pool: pg.Pool; readonly openSecret: (sealed: Buffer, endpointId: string) => Promise<string> }

/** Delivers due webhooks with exponential backoff (1 min doubling, capped at 6 h). Grants are re-checked before sending. */
export async function deliverWebhooks(deps: WebhookDeps, batch = 50): Promise<number> {
  return withScope(deps.pool, 'system', null, async (tx) => {
    const due = (await tx.query<{ id: string; endpoint_id: string; url: string; secret_sealed: Buffer; payload: unknown; attempts: number; active: boolean }>(
      `SELECT d.id::text, e.id::text AS endpoint_id, e.url, e.secret_sealed, d.payload, d.attempts,
         (g.revoked_at IS NULL AND g.expires_at > now() AND e.disabled_at IS NULL) AS active
       FROM webhook_delivery d JOIN webhook_endpoint e ON e.id = d.endpoint_id JOIN "grant" g ON g.id = e.grant_id
       WHERE d.delivered_at IS NULL AND d.next_attempt_at <= now() ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED`, [batch])).rows;
    for (const d of due) {
      if (!d.active) { await tx.query('DELETE FROM webhook_delivery WHERE id=$1', [d.id]); continue; }
      const body = JSON.stringify(d.payload);
      let error: string | null = null;
      try {
        const res = await fetch(d.url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000),
          headers: { 'Content-Type': 'application/json', 'X-Signature': signWebhook(await deps.openSecret(d.secret_sealed, d.endpoint_id), body, Math.floor(Date.now() / 1000)) }, body });
        if (!res.ok) error = `HTTP ${res.status}`;
      } catch (err) { error = (err as Error).message; }
      if (error === null) await tx.query('UPDATE webhook_delivery SET delivered_at=now(), attempts=attempts+1 WHERE id=$1', [d.id]);
      else await tx.query(`UPDATE webhook_delivery SET attempts=attempts+1, last_error=$2,
          next_attempt_at = now() + least(interval '6 hours', interval '1 minute' * power(2, attempts)) WHERE id=$1`, [d.id, error.slice(0, 500)]);
    }
    return due.length;
  });
}
