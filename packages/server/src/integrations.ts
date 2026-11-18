// External integrations: local LLM drafting traced to MAVT (§5.10), Keycloak grant scopes (§5.7),
// Mosquitto dynamic-security ACLs for the MQTT bridge (§5.6).
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { MqttClient } from 'mqtt';
import type { Config } from './config.ts';
import type { Tx } from './db.ts';

// ── MAVT tracing ────────────────────────────────────────────────────────────────────────────────
interface MavtVisibility {
  setGoal(goal: string, opts?: { runId?: string }): Promise<unknown>;
  registerAgent(a: { id: string; label?: string; role?: string; model?: string }): Promise<unknown>;
  logLlmTurn(t: { agent: string; model?: string; promptTokens?: number; completionTokens?: number; latencyMs?: number; messages?: unknown[]; response?: string }): Promise<unknown>;
  logEvent(e: { agent: string; type?: string; message?: string }): Promise<unknown>;
  finishRun(status?: string): Promise<unknown>;
  flush(): Promise<void>;
}
const { Visibility } = createRequire(import.meta.url)('../vendor/mavt-sdk.cjs') as { Visibility: new (o: { url: string; apiKey: string }) => MavtVisibility };

// ── Catalogue drafting with the local LLM ─────────────────────────────────────────────────────────
const DRAFT_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['description', 'unit_ucum'],
  properties: {
    description: { type: 'string', minLength: 10, maxLength: 400 },
    unit_ucum: { type: ['string', 'null'], maxLength: 32 },
  },
};

interface Draft { description: string; unit_ucum: string | null }
function isDraft(v: unknown): v is Draft {
  const o = v as Draft;
  return !!o && typeof o.description === 'string' && o.description.length >= 10 && o.description.length <= 400 &&
    (o.unit_ucum === null || (typeof o.unit_ucum === 'string' && o.unit_ucum.length <= 32));
}

/**
 * Drafts descriptions and units for unreviewed data points. Output is schema-constrained and validated;
 * invalid output is discarded. Drafts are suggestions only: a reviewer publishes (design §5.4).
 */
export async function draftCatalogue(tx: Tx, config: Config, modelId: string): Promise<{ drafted: number; rejected: number }> {
  if (!config.llm) throw new Error('LLM_URL is not configured');
  const llm = config.llm;
  const points = (await tx.query<{ id: string; name: string; source_address: string; dtype: string; draft_description: string | null }>(
    `SELECT id::text, name, source_address, dtype::text, draft_description FROM datapoint WHERE model_id=$1 AND reviewed_by IS NULL ORDER BY name`, [modelId])).rows;
  const vis = config.mavt ? new Visibility({ url: config.mavt.url, apiKey: config.mavt.apiKey }) : null;
  const agent = 'catalogue-drafter';
  void vis?.setGoal(`Draft catalogue for model ${modelId}`, { runId: `catalogue-${modelId}-${Date.now()}` });
  void vis?.registerAgent({ id: agent, role: 'worker', model: llm.model });
  let drafted = 0, rejected = 0;
  for (const p of points) {
    const messages = [
      { role: 'system', content: 'You describe industrial machine data points for the machine owner. Be factual and brief. Use UCUM unit codes (e.g. Cel, bar, rpm → /min, kW.h). Use null for unit when there is none or you are unsure.' },
      { role: 'user', content: `Name: ${p.name}\nAddress: ${p.source_address}\nType: ${p.dtype}\nExisting text: ${p.draft_description ?? 'none'}` },
    ];
    const t0 = Date.now();
    const res = await fetch(`${llm.url}/v1/chat/completions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: llm.model, messages, temperature: 0, response_format: { type: 'json_schema', json_schema: { name: 'draft', schema: DRAFT_SCHEMA } } }),
    });
    if (!res.ok) throw new Error(`LLM request failed: HTTP ${res.status}`);
    const body = (await res.json()) as { choices?: { message?: { content?: string } }[]; usage?: { prompt_tokens?: number; completion_tokens?: number } };
    const content = body.choices?.[0]?.message?.content ?? '';
    void vis?.logLlmTurn({ agent, model: llm.model, promptTokens: body.usage?.prompt_tokens ?? 0, completionTokens: body.usage?.completion_tokens ?? 0,
      latencyMs: Date.now() - t0, messages, response: content });
    let parsed: unknown = null;
    try { parsed = JSON.parse(content); } catch { parsed = null; }
    if (!isDraft(parsed)) { rejected++; void vis?.logEvent({ agent, type: 'fail', message: `Invalid draft for ${p.name}` }); continue; }
    await tx.query('UPDATE datapoint SET draft_description=$2, draft_unit_ucum=$3 WHERE id=$1 AND reviewed_by IS NULL', [p.id, parsed.description, parsed.unit_ucum]);
    drafted++;
  }
  if (vis) { void vis.finishRun(rejected ? 'error' : 'done'); await vis.flush(); }
  return { drafted, rejected };
}

// ── Keycloak: a client scope per grant for machine clients (design §5.7) ──────────────────────────
export class KeycloakAdmin {
  private token: { value: string; exp: number } | null = null;
  private readonly cfg: NonNullable<Config['keycloakAdmin']>;
  private readonly secret: string;
  constructor(cfg: NonNullable<Config['keycloakAdmin']>) { this.cfg = cfg; this.secret = readFileSync(cfg.clientSecretFile, 'utf8').trim(); }

  private async call(method: string, path: string, body?: unknown): Promise<Response> {
    if (!this.token || this.token.exp < Date.now() + 10_000) {
      const r = await fetch(`${this.cfg.url}/realms/${this.cfg.realm}/protocol/openid-connect/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: this.cfg.clientId, client_secret: this.secret }),
      });
      if (!r.ok) throw new Error(`Keycloak token request failed: HTTP ${r.status}`);
      const j = (await r.json()) as { access_token: string; expires_in: number };
      this.token = { value: j.access_token, exp: Date.now() + j.expires_in * 1000 };
    }
    const init: RequestInit = { method, headers: { Authorization: `Bearer ${this.token.value}`, 'Content-Type': 'application/json' } };
    if (body !== undefined) init.body = JSON.stringify(body);
    return fetch(`${this.cfg.url}/admin/realms/${this.cfg.realm}${path}`, init);
  }

  /** Creates scope `grant:<id>` and offers it to every machine client of the recipient (by service-account user id). */
  async addGrantScope(grantId: string, serviceAccountUserIds: readonly string[]): Promise<void> {
    const name = `grant:${grantId}`;
    let r = await this.call('POST', '/client-scopes', { name, protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' } });
    if (!r.ok && r.status !== 409) throw new Error(`Keycloak: creating ${name} failed: HTTP ${r.status}`);
    r = await this.call('GET', `/client-scopes`);
    const scope = ((await r.json()) as { id: string; name: string }[]).find((s) => s.name === name);
    if (!scope) throw new Error(`Keycloak: ${name} not found after creation`);
    for (const userId of serviceAccountUserIds) {
      const u = (await (await this.call('GET', `/users/${userId}`)).json()) as { serviceAccountClientLink?: string };
      if (!u.serviceAccountClientLink) throw new Error(`Keycloak user ${userId} is not a service account`);
      const client = ((await (await this.call('GET', `/clients?clientId=${encodeURIComponent(u.serviceAccountClientLink)}`)).json()) as { id: string }[])[0];
      if (!client) throw new Error(`Keycloak client ${u.serviceAccountClientLink} not found`);
      r = await this.call('PUT', `/clients/${client.id}/optional-client-scopes/${scope.id}`);
      if (!r.ok) throw new Error(`Keycloak: assigning ${name} failed: HTTP ${r.status}`);
    }
  }

  async removeGrantScope(grantId: string): Promise<void> {
    const scope = ((await (await this.call('GET', '/client-scopes')).json()) as { id: string; name: string }[]).find((s) => s.name === `grant:${grantId}`);
    if (scope) {
      const r = await this.call('DELETE', `/client-scopes/${scope.id}`);
      if (!r.ok && r.status !== 404) throw new Error(`Keycloak: deleting grant:${grantId} failed: HTTP ${r.status}`);
    }
  }
}

// ── Mosquitto dynamic security: MQTT bridge access per grant (design §5.6) ─────────────────────────
const DYNSEC_TOPIC = '$CONTROL/dynamic-security/v1';

export class DynSec {
  private readonly client: MqttClient;
  private readonly pending = new Map<string, (r: { error?: string }) => void>();
  constructor(client: MqttClient) {
    this.client = client;
    client.subscribe(`${DYNSEC_TOPIC}/response`);
    client.on('message', (topic, buf) => {
      if (topic !== `${DYNSEC_TOPIC}/response`) return;
      const { responses } = JSON.parse(buf.toString()) as { responses: { command: string; error?: string; correlationData?: string }[] };
      for (const r of responses) { const cb = r.correlationData ? this.pending.get(r.correlationData) : undefined; cb?.(r); }
    });
  }

  private send(command: Record<string, unknown>, tolerate: readonly string[] = []): Promise<void> {
    const correlationData = randomBytes(8).toString('hex');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(correlationData); reject(new Error(`dynsec ${String(command['command'])} timed out`)); }, 10_000);
      this.pending.set(correlationData, (r) => {
        clearTimeout(timer); this.pending.delete(correlationData);
        if (r.error && !tolerate.some((t) => r.error?.includes(t))) reject(new Error(`dynsec ${String(command['command'])}: ${r.error}`)); else resolve();
      });
      this.client.publish(DYNSEC_TOPIC, JSON.stringify({ commands: [{ ...command, correlationData }] }));
    });
  }

  /** Grants a recipient's MQTT client read access to `grants/<grantId>/#` and nothing else. */
  async allowGrant(recipientOrgId: string, grantId: string): Promise<void> {
    const role = `grant-${grantId}`;
    await this.send({ command: 'createRole', rolename: role }, ['already exists']);
    await this.send({ command: 'addRoleACL', rolename: role, acltype: 'subscribePattern', topic: `grants/${grantId}/#`, allow: true }, ['already exists']);
    await this.send({ command: 'addClientRole', username: `recipient-${recipientOrgId}`, rolename: role }, ['already']);
  }

  async revokeGrant(grantId: string): Promise<void> {
    await this.send({ command: 'deleteRole', rolename: `grant-${grantId}` }, ['not found']);
  }

  /** Creates or rotates the recipient's MQTT credentials; the password is returned once and not stored. */
  async rotateRecipientPassword(recipientOrgId: string): Promise<{ username: string; password: string }> {
    const username = `recipient-${recipientOrgId}`;
    const password = randomBytes(24).toString('base64url');
    await this.send({ command: 'createClient', username, password }, ['already exists']);
    await this.send({ command: 'setClientPassword', username, password });
    return { username, password };
  }
}
