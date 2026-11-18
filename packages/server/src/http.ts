// HTTP API and portal (design §5.6–§5.9). Every route authenticates, checks roles, and reaches machine
// data only through `authorise` (the policy decision point).
import { randomUUID, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import parquet from '@dsnp/parquetjs';
import type pg from 'pg';
import type { MqttClient } from 'mqtt';
import {
  applicability, decide as policyDecide, exportFingerprint, ValidationError, type Channel, type EnterpriseSize, type Principal, type Role, type KeyEncryptionKey,
} from '@dak/core';
import { authorise, loadFacts } from './access.ts';
import { AuthError, requireRole, type Authenticator } from './auth.ts';
import { CATALOGUE_JSON_SCHEMA, CatalogueError, exportCatalogue, importPoints, parseNodeSet2, parseTagCsv, publish, reviewPoint, type Review } from './catalogue.ts';
import type { Config } from './config.ts';
import { withScope, type Tx } from './db.ts';
import { presaleContext, render, storeDocument, TemplateError, type Context, type TemplateStore } from './documents.ts';
import { draftCatalogue, type DynSec, type KeycloakAdmin } from './integrations.ts';
import { TOPIC_REVOKED, type SseHub } from './live.ts';
import { readPage, type Keyring } from './readings.ts';
import * as rec from './records.ts';

export interface AppDeps {
  readonly config: Config; readonly pool: pg.Pool; readonly auth: Authenticator; readonly templates: TemplateStore;
  readonly keyring: Keyring; readonly kek: KeyEncryptionKey; readonly fingerprintSecret: string; readonly hub: SseHub;
  readonly mqtt: MqttClient; readonly dynsec: DynSec; readonly keycloak: KeycloakAdmin | null;
}

declare module 'fastify' { interface FastifyRequest { principal: Principal } }

const MAKER_STAFF: Role[] = ['maker_admin', 'catalogue_reviewer', 'legal_officer'];
const PAGE_MAX = 50_000;
const PUBLIC_DIR = join(import.meta.dirname, '..', 'public');
const STATIC: Record<string, string> = {
  '/': 'index.html', '/app.js': 'app.js', '/theme.css': 'theme.css', '/icons.svg': 'icons.svg', '/callback': 'index.html',
};
const MIME: Record<string, string> = { html: 'text/html; charset=utf-8', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' };

const uuid = { type: 'string', format: 'uuid' } as const;
const uuids = { type: 'array', items: uuid, maxItems: 5000 } as const;
const str = (max = 500) => ({ type: 'string', minLength: 1, maxLength: max }) as const;

export function buildApp(d: AppDeps): FastifyInstance {
  const app = Fastify({ logger: { level: 'info', redact: ['req.headers.authorization'] }, bodyLimit: 20 * 1024 * 1024, trustProxy: true });
  app.addContentTypeParser(['text/csv', 'application/xml', 'text/xml'], { parseAs: 'string' }, (_r, body, done) => done(null, body));
  const buckets = new Map<string, { n: number; reset: number }>();

  app.setErrorHandler((err: Error & { status?: number; statusCode?: number; validation?: unknown }, _req, reply) => {
    if (err instanceof AuthError || err instanceof rec.RecordError) return reply.code(err.status).send({ error: err.message });
    if (err instanceof CatalogueError || err instanceof TemplateError || err instanceof ValidationError) return reply.code(400).send({ error: err.message });
    if (err.validation) return reply.code(400).send({ error: err.message });
    if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: err.message });
    app.log.error(err);
    return reply.code(500).send({ error: 'Internal error' });
  });

  app.get('/healthz', async () => {
    await d.pool.query('SELECT 1');
    return { ok: true, mqtt: d.mqtt.connected };
  });

  for (const [path, file] of Object.entries(STATIC)) {
    app.get(path, async (_req, reply) => reply.type(MIME[file.split('.').pop() ?? 'html'] ?? 'text/plain')
      .header('Content-Security-Policy', "default-src 'self'; connect-src 'self' " + new URL(d.config.oidc.issuer).origin + "; img-src 'self' data:; frame-ancestors 'none'")
      .header('X-Content-Type-Options', 'nosniff').send(readFileSync(join(PUBLIC_DIR, file))));
  }
  app.get('/portal-config.json', async () => ({ issuer: d.config.oidc.issuer, clientId: d.config.oidc.portalClientId }));

  // ── Authentication and protective rate limits for everything under /api (design §5.6, §8) ──
  app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.url.startsWith('/api/')) return;
    req.principal = await d.auth.authenticate(req.headers.authorization);
    const now = Date.now();
    const b = buckets.get(req.principal.id);
    if (!b || b.reset <= now) buckets.set(req.principal.id, { n: 1, reset: now + 60_000 });
    else if (++b.n > d.config.rateLimitPerMinute) return reply.code(429).header('Retry-After', String(Math.ceil((b.reset - now) / 1000))).send({ error: 'Rate limit exceeded' });
  });

  const sys = <T>(fn: (tx: Tx) => Promise<T>) => withScope(d.pool, 'system', null, fn);
  const access = { pool: d.pool, gatekeepers: d.config.gatekeepers };
  const recDeps: rec.Deps = { config: d.config, templates: d.templates };

  app.get('/api/me', async (req) => req.principal);

  // ── Organisations and principals (maker administration) ──
  app.post<{ Body: { name: string; kind: 'maker' | 'customer' | 'recipient'; smeFlag?: boolean; nonProfitResearch?: boolean; hasNonSmePartnerOrLinked?: boolean;
    groupIdentifier?: string; recipientCategoryId?: string; size?: EnterpriseSize; subcontracted?: boolean; mediumSince?: string; verified?: boolean } }>('/api/organisations', {
    schema: { body: { type: 'object', required: ['name', 'kind'], additionalProperties: false, properties: {
      name: str(200), kind: { enum: ['maker', 'customer', 'recipient'] }, smeFlag: { type: 'boolean' }, nonProfitResearch: { type: 'boolean' },
      hasNonSmePartnerOrLinked: { type: 'boolean' }, groupIdentifier: str(100), recipientCategoryId: uuid, size: { enum: ['micro', 'small', 'medium', 'large'] },
      subcontracted: { type: 'boolean' }, mediumSince: { type: 'string', format: 'date' }, verified: { type: 'boolean' } } } },
  }, async (req) => {
    requireRole(req.principal, 'maker_admin');
    const b = req.body;
    return sys(async (tx) => (await tx.query(`INSERT INTO organisation (name, kind, sme_flag, non_profit_research, has_non_sme_partner_or_linked, group_identifier,
        recipient_category_id, size, subcontracted, medium_since, verified_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, CASE WHEN $11 THEN now() END) RETURNING id`,
      [b.name, b.kind, b.smeFlag ?? false, b.nonProfitResearch ?? false, b.hasNonSmePartnerOrLinked ?? false, b.groupIdentifier ?? null,
        b.recipientCategoryId ?? null, b.size ?? null, b.subcontracted ?? false, b.mediumSince ?? null, b.verified ?? false])).rows[0]);
  });

  app.post<{ Body: { orgId: string; oidcSub: string; roles: Role[]; machineClient?: boolean } }>('/api/principals', {
    schema: { body: { type: 'object', required: ['orgId', 'oidcSub', 'roles'], additionalProperties: false, properties: {
      orgId: uuid, oidcSub: str(200), roles: { type: 'array', minItems: 1, items: { enum: ['maker_admin', 'catalogue_reviewer', 'legal_officer', 'customer_admin', 'customer_user', 'recipient'] } },
      machineClient: { type: 'boolean' } } } },
  }, async (req) => {
    requireRole(req.principal, 'maker_admin');
    const b = req.body;
    return sys(async (tx) => {
      const kind = (await tx.query<{ kind: string }>('SELECT kind::text FROM organisation WHERE id=$1', [b.orgId])).rows[0]?.kind;
      if (!kind) throw new rec.RecordError('Organisation not found', 404);
      const allowed: Record<string, Role[]> = { maker: MAKER_STAFF, customer: ['customer_admin', 'customer_user'], recipient: ['recipient'] };
      if (!b.roles.every((r) => allowed[kind]?.includes(r))) throw new rec.RecordError(`Roles not valid for a ${kind} organisation`);
      return (await tx.query('INSERT INTO principal (org_id, oidc_sub, roles, machine_client) VALUES ($1,$2,$3,$4) RETURNING id',
        [b.orgId, b.oidcSub, b.roles, b.machineClient ?? false])).rows[0];
    });
  });

  app.post<{ Body: { name: string; termsTemplateId: string; termsTemplateVersion: string; formattingCents: number; disseminationCents: number;
    storageCents: number; investmentShareCents: number; marginRate: number } }>('/api/recipient-categories', {
    schema: { body: { type: 'object', additionalProperties: false, required: ['name', 'termsTemplateId', 'termsTemplateVersion', 'formattingCents', 'disseminationCents', 'storageCents', 'investmentShareCents', 'marginRate'],
      properties: { name: str(100), termsTemplateId: str(100), termsTemplateVersion: str(50), formattingCents: { type: 'integer', minimum: 0 },
        disseminationCents: { type: 'integer', minimum: 0 }, storageCents: { type: 'integer', minimum: 0 }, investmentShareCents: { type: 'integer', minimum: 0 },
        marginRate: { type: 'number', minimum: 0, maximum: 10 } } } },
  }, async (req) => {
    requireRole(req.principal, 'legal_officer');
    const b = req.body;
    if (d.templates.get(b.termsTemplateId, b.termsTemplateVersion).kind !== 'recipient_terms') throw new rec.RecordError('That template is not recipient terms');
    return sys(async (tx) => (await tx.query(`INSERT INTO recipient_category (name, terms_template_id, terms_template_version, formatting_cents, dissemination_cents,
        storage_cents, investment_share_cents, margin_rate) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [b.name, b.termsTemplateId, b.termsTemplateVersion, b.formattingCents, b.disseminationCents, b.storageCents, b.investmentShareCents, b.marginRate])).rows[0]);
  });

  // ── Product models and catalogue (§5.4) ──
  app.post<{ Body: { name: string; placedOnMarketAt?: string; makerSizeAtPlacement?: EnterpriseSize } }>('/api/models', {
    schema: { body: { type: 'object', required: ['name'], additionalProperties: false, properties: {
      name: str(200), placedOnMarketAt: { type: 'string', format: 'date' }, makerSizeAtPlacement: { enum: ['micro', 'small', 'medium', 'large'] } } } },
  }, async (req) => {
    requireRole(req.principal, 'maker_admin');
    const b = req.body;
    return sys(async (tx) => (await tx.query('INSERT INTO product_model (maker_org_id, name, placed_on_market_at, maker_size_at_placement) VALUES ($1,$2,$3,$4) RETURNING id',
      [req.principal.orgId, b.name, b.placedOnMarketAt ?? null, b.makerSizeAtPlacement ?? null])).rows[0]);
  });

  app.get('/api/models', async (req) => {
    requireRole(req.principal, ...MAKER_STAFF);
    return sys(async (tx) => (await tx.query('SELECT id, name, placed_on_market_at, maker_size_at_placement, catalogue_version, related_service IS NOT NULL AS has_related_service FROM product_model WHERE maker_org_id=$1 ORDER BY name', [req.principal.orgId])).rows);
  });

  app.get<{ Params: { id: string } }>('/api/models/:id/applicability', async (req) => {
    requireRole(req.principal, ...MAKER_STAFF);
    return sys(async (tx) => {
      const m = (await tx.query<{ placed_on_market_at: Date | null; size: EnterpriseSize | null; has_non_sme_partner_or_linked: boolean; subcontracted: boolean; medium_since: Date | null }>(
        `SELECT pm.placed_on_market_at, coalesce(pm.maker_size_at_placement, o.size) AS size, o.has_non_sme_partner_or_linked, o.subcontracted, o.medium_since
         FROM product_model pm JOIN organisation o ON o.id = pm.maker_org_id WHERE pm.id::text=$1 AND pm.maker_org_id=$2`, [req.params.id, req.principal.orgId])).rows[0];
      if (!m) throw new rec.RecordError('Model not found', 404);
      if (!m.placed_on_market_at || !m.size) throw new rec.RecordError('Set the placing-on-market date and the maker size first', 409);
      return applicability({ size: m.size, hasNonSmallPartnerOrLinked: m.has_non_sme_partner_or_linked, subcontracted: m.subcontracted, mediumSince: m.medium_since },
        m.placed_on_market_at, new Date());
    });
  });

  app.post<{ Params: { id: string }; Body: string }>('/api/models/:id/import', async (req) => {
    requireRole(req.principal, 'maker_admin', 'catalogue_reviewer');
    const ct = String(req.headers['content-type'] ?? '');
    if (typeof req.body !== 'string') throw new rec.RecordError('Send a NodeSet2 XML or tag-list CSV body');
    const parsed = ct.startsWith('text/csv') ? parseTagCsv(req.body) : parseNodeSet2(req.body);
    return sys(async (tx) => {
      await ownModel(tx, req.principal, req.params.id);
      return { ...(await importPoints(tx, req.params.id, parsed.points)), skipped: parsed.skipped };
    });
  });

  app.post<{ Params: { id: string } }>('/api/models/:id/draft', async (req) => {
    requireRole(req.principal, 'catalogue_reviewer');
    return sys(async (tx) => { await ownModel(tx, req.principal, req.params.id); return draftCatalogue(tx, d.config, req.params.id); });
  });

  app.get<{ Params: { id: string } }>('/api/models/:id/datapoints', async (req) => {
    requireRole(req.principal, ...MAKER_STAFF);
    return sys(async (tx) => {
      await ownModel(tx, req.principal, req.params.id);
      return (await tx.query('SELECT * FROM datapoint WHERE model_id=$1 ORDER BY name', [req.params.id])).rows;
    });
  });

  app.put<{ Params: { id: string }; Body: Review }>('/api/datapoints/:id/review', {
    schema: { body: { type: 'object', additionalProperties: false,
      required: ['description', 'unitUcum', 'rateHz', 'estBytesPerDay', 'tradeSecret', 'tsHolder', 'personalData', 'personalCategory', 'retentionDays'],
      properties: { description: str(2000), unitUcum: { type: ['string', 'null'], maxLength: 32 }, rateHz: { type: ['number', 'null'], exclusiveMinimum: 0 },
        estBytesPerDay: { type: ['integer', 'null'], minimum: 0 }, tradeSecret: { type: 'boolean' }, tsHolder: { type: ['string', 'null'], maxLength: 200 },
        personalData: { type: 'boolean' }, personalCategory: { type: ['string', 'null'], maxLength: 200 }, retentionDays: { type: ['integer', 'null'], minimum: 1 } } } },
  }, async (req) => {
    requireRole(req.principal, 'catalogue_reviewer');
    return sys(async (tx) => {
      const owner = (await tx.query('SELECT 1 FROM datapoint dp JOIN product_model pm ON pm.id = dp.model_id WHERE dp.id::text=$1 AND pm.maker_org_id=$2', [req.params.id, req.principal.orgId])).rowCount;
      if (!owner) throw new rec.RecordError('Data point not found', 404);
      await reviewPoint(tx, d.kek, req.params.id, req.principal.id, req.body);
      return { ok: true };
    });
  });

  app.put<{ Params: { id: string }; Body: Record<string, string> }>('/api/models/:id/related-service', {
    schema: { body: { type: 'object', additionalProperties: false,
      required: ['relatedServiceData', 'holderUses', 'thirdPartyUse', 'holderIdentity', 'contact', 'competentAuthority', 'contractDuration'],
      properties: Object.fromEntries(['relatedServiceData', 'holderUses', 'thirdPartyUse', 'holderIdentity', 'contact', 'competentAuthority', 'contractDuration'].map((k) => [k, str(4000)])) } },
  }, async (req) => {
    requireRole(req.principal, 'legal_officer');
    return sys(async (tx) => {
      await ownModel(tx, req.principal, req.params.id);
      await tx.query('UPDATE product_model SET related_service=$2 WHERE id=$1', [req.params.id, JSON.stringify(req.body)]);
      return { ok: true };
    });
  });

  app.post<{ Params: { id: string } }>('/api/models/:id/publish', async (req) => {
    requireRole(req.principal, 'catalogue_reviewer');
    return sys(async (tx) => {
      await ownModel(tx, req.principal, req.params.id);
      const version = await publish(tx, req.params.id, req.principal.id);
      return { version, documents: await generateModelDocuments(tx, req.params.id) };
    });
  });

  /** After publication the model's documents are regenerated and queued for approval (design §7). */
  async function generateModelDocuments(tx: Tx, modelId: string) {
    const out: { kind: string; language: string; documentId?: string; problem?: string }[] = [];
    const languages = [...new Set(d.templates.list().filter((t) => t.kind === 'presale_datasheet' || t.kind === 'related_service_notice').map((t) => t.language))];
    if (languages.length === 0) return [{ kind: 'presale_datasheet', language: '-', problem: 'No approved templates installed' }];
    const base = await presaleContext(tx, modelId, d.config.publicBaseUrl).catch((e: Error) => e);
    const rs = (await tx.query<{ related_service: Record<string, string> | null }>('SELECT related_service FROM product_model WHERE id=$1', [modelId])).rows[0]?.related_service ?? null;
    for (const language of languages) {
      for (const kind of ['presale_datasheet', 'related_service_notice'] as const) {
        try {
          if (base instanceof Error) throw base;
          if (kind === 'related_service_notice' && !rs) throw new TemplateError('Related-service facts not recorded (Art. 3(3))');
          const ctx: Context = kind === 'related_service_notice'
            ? { ...base, ...Object.fromEntries(Object.entries(rs ?? {}).map(([k, v]) => [`service.${k}`, v])) } : base;
          const t = d.templates.current(kind, language);
          out.push({ kind, language, documentId: await storeDocument(tx, t, { model: modelId, kind }, await render(t, ctx, d.config.documentFont)) });
        } catch (err) { out.push({ kind, language, problem: (err as Error).message }); }
      }
    }
    return out;
  }

  app.get<{ Params: { id: string } }>('/api/models/:id/catalogue.json', async (req) =>
    sys(async (tx) => exportCatalogue(tx, req.params.id)));
  app.get('/api/catalogue-schema.json', async () => CATALOGUE_JSON_SCHEMA);

  // ── Machines, devices and customer linking (§5.7) ──
  app.post<{ Body: { modelId: string; serial: string } }>('/api/machines', {
    schema: { body: { type: 'object', required: ['modelId', 'serial'], additionalProperties: false, properties: { modelId: uuid, serial: str(100) } } },
  }, async (req) => {
    requireRole(req.principal, 'maker_admin');
    return sys(async (tx) => { await ownModel(tx, req.principal, req.body.modelId);
      return (await tx.query('INSERT INTO machine (model_id, serial) VALUES ($1,$2) RETURNING id', [req.body.modelId, req.body.serial])).rows[0]; });
  });

  app.post<{ Body: { id: string; machineId: string } }>('/api/devices', {
    schema: { body: { type: 'object', required: ['id', 'machineId'], additionalProperties: false, properties: { id: { type: 'string', pattern: '^[A-Za-z0-9._:-]{1,128}$' }, machineId: uuid } } },
  }, async (req) => {
    requireRole(req.principal, 'maker_admin');
    return sys(async (tx) => { await tx.query('INSERT INTO device (id, machine_id) VALUES ($1,$2)', [req.body.id, req.body.machineId]); return { ok: true }; });
  });

  app.get('/api/machines', async (req) => {
    const p = req.principal;
    return withScope(d.pool, p.orgKind, p.orgId, async (tx) => (await tx.query(
      `SELECT m.id, m.serial, m.model_id, pm.name AS model, m.owner_org_id, m.linked_at FROM machine m JOIN product_model pm ON pm.id = m.model_id ORDER BY pm.name, m.serial`)).rows);
  });

  app.post<{ Body: { modelId: string; serial: string; evidenceRef: string } }>('/api/link-requests', {
    schema: { body: { type: 'object', required: ['modelId', 'serial', 'evidenceRef'], additionalProperties: false, properties: { modelId: uuid, serial: str(100), evidenceRef: str(200) } } },
  }, async (req) => {
    requireRole(req.principal, 'customer_admin');
    return sys(async (tx) => (await tx.query('INSERT INTO link_request (customer_org_id, model_id, serial, evidence_ref) VALUES ($1,$2,$3,$4) RETURNING id',
      [req.principal.orgId, req.body.modelId, req.body.serial, req.body.evidenceRef])).rows[0]);
  });

  app.get('/api/link-requests', async (req) => {
    const p = req.principal;
    return sys(async (tx) => (await tx.query(`SELECT lr.*, o.name AS customer, pm.name AS model FROM link_request lr JOIN organisation o ON o.id = lr.customer_org_id
        JOIN product_model pm ON pm.id = lr.model_id WHERE ($1 OR lr.customer_org_id=$2) ORDER BY lr.created_at DESC`,
      [p.orgKind === 'maker' && p.roles.includes('maker_admin'), p.orgId])).rows);
  });

  app.post<{ Params: { id: string; action: 'approve' | 'reject' } }>('/api/link-requests/:id/:action', async (req) => {
    requireRole(req.principal, 'maker_admin');
    if (req.params.action !== 'approve' && req.params.action !== 'reject') throw new rec.RecordError('Unknown action', 404);
    return sys(async (tx) => {
      const lr = (await tx.query<{ customer_org_id: string; model_id: string; serial: string; evidence_ref: string }>(
        `UPDATE link_request SET status=$2, reviewed_by=$3, reviewed_at=now() WHERE id::text=$1 AND status='pending' RETURNING customer_org_id, model_id, serial, evidence_ref`,
        [req.params.id, req.params.action === 'approve' ? 'approved' : 'rejected', req.principal.id])).rows[0];
      if (!lr) throw new rec.RecordError('Pending link request not found', 404);
      if (req.params.action === 'approve') {
        const r = await tx.query(`UPDATE machine SET owner_org_id=$3, linked_at=now(), link_evidence_ref=$4 WHERE model_id=$1 AND serial=$2`,
          [lr.model_id, lr.serial, lr.customer_org_id, lr.evidence_ref]);
        if (!r.rowCount) throw new rec.RecordError('No machine with that model and serial', 409);
      }
      return { ok: true };
    });
  });

  // ── Data access: export and live stream (R1, R4, R12) ──
  const readingsQuery = { type: 'object', required: ['datapoints', 'from', 'to'], additionalProperties: false, properties: {
    datapoints: str(20_000), from: { type: 'string', format: 'date-time' }, to: { type: 'string', format: 'date-time' },
    format: { enum: ['json', 'csv', 'parquet'] }, limit: { type: 'integer', minimum: 1, maximum: PAGE_MAX }, cursor: str(500) } } as const;

  app.get<{ Params: { id: string }; Querystring: { datapoints: string; from: string; to: string; format?: 'json' | 'csv' | 'parquet'; limit?: number; cursor?: string } }>(
    '/api/machines/:id/readings', { schema: { querystring: readingsQuery } }, async (req, reply) => {
      const p = req.principal, q = req.query;
      const from = new Date(q.from), to = new Date(q.to);
      if (!(from < to)) throw new rec.RecordError('from must be before to');
      const { decision, machineFound } = await authorise(access, p, req.params.id, 'rest', q.datapoints.split(','));
      if (!machineFound) throw new rec.RecordError('Machine not found', 404);
      if (decision.allowed.length === 0) return reply.code(403).send({ error: 'No requested data point may be released', denials: decision.denials });
      const exportId = randomUUID();
      const fingerprint = decision.grantId ? exportFingerprint(d.fingerprintSecret, p.orgId, decision.grantId, exportId) : null;
      const page = await withScope(d.pool, p.orgKind, p.orgId, (tx) =>
        readPage(tx, d.keyring, req.params.id, decision.allowed, from, to, q.limit ?? PAGE_MAX, q.cursor ?? null));
      const metadata = await sys(async (tx) => {
        const modelId = (await tx.query<{ model_id: string }>('SELECT model_id::text FROM machine WHERE id::text=$1', [req.params.id])).rows[0]!.model_id;
        const cat = await exportCatalogue(tx, modelId);
        return { exportId, fingerprint, catalogue: { ...cat, datapoints: cat.datapoints.filter((x) => decision.allowed.includes(x.id)) }, denials: decision.denials };
      });
      reply.header('Link', `<${d.config.publicBaseUrl}/api/models/${metadata.catalogue.modelId}/catalogue.json>; rel="describedby"`);
      if (fingerprint) reply.header('X-Export-Fingerprint', fingerprint);
      if (page.next) reply.header('X-Next-Cursor', page.next);
      if (q.format === 'csv') {
        const esc = (v: unknown) => { const s = String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
        return reply.type('text/csv; charset=utf-8').send(['datapoint_id,ts,value', ...page.rows.map((r) => `${r.datapointId},${r.ts},${esc(r.value)}`)].join('\n') + '\n');
      }
      if (q.format === 'parquet') {
        const out = new PassThrough();
        const schema = new parquet.ParquetSchema({ datapoint_id: { type: 'UTF8' }, ts: { type: 'TIMESTAMP_MILLIS' },
          num: { type: 'DOUBLE', optional: true }, bool: { type: 'BOOLEAN', optional: true }, txt: { type: 'UTF8', optional: true } });
        // The library's type demands an fs.WriteStream but it only calls write/end, which PassThrough provides.
        const w = await parquet.ParquetWriter.openStream(schema, out as unknown as Parameters<typeof parquet.ParquetWriter.openStream>[1]);
        w.setMetadata('dataact-kit.metadata', JSON.stringify(metadata));
        void (async () => {
          for (const r of page.rows) await w.appendRow({ datapoint_id: r.datapointId, ts: new Date(r.ts),
            ...(typeof r.value === 'number' ? { num: r.value } : typeof r.value === 'boolean' ? { bool: r.value } : { txt: r.value }) });
          await w.close();
        })().catch((e: Error) => out.destroy(e));
        return reply.type('application/vnd.apache.parquet').send(out);
      }
      return { metadata, data: page.rows, next: page.next };
    });

  app.get<{ Params: { id: string }; Querystring: { datapoints: string } }>('/api/machines/:id/stream', {
    schema: { querystring: { type: 'object', required: ['datapoints'], properties: { datapoints: str(20_000) } } },
  }, async (req, reply) => {
    const { decision, machineFound } = await authorise(access, req.principal, req.params.id, 'sse', req.query.datapoints.split(','));
    if (!machineFound) throw new rec.RecordError('Machine not found', 404);
    if (decision.allowed.length === 0) return reply.code(403).send({ error: 'No requested data point may be released', denials: decision.denials });
    reply.hijack();
    d.hub.open(reply.raw, req.params.id, decision.allowed, decision.grantId, { allowed: decision.allowed, denials: decision.denials });
  });

  // ── Contracts and documents (§5.8, §5.9) ──
  app.get('/api/templates', async () => d.templates.list().map(({ id, kind, version, language, title, approvedAt }) => ({ id, kind, version, language, title, approvedAt })));

  app.post<{ Body: { kind: 'data_use' | 'nda' | 'recipient_terms'; counterpartyOrgId: string; datapointIds?: string[]; language: string } }>('/api/contract-offers', {
    schema: { body: { type: 'object', required: ['kind', 'counterpartyOrgId', 'language'], additionalProperties: false, properties: {
      kind: { enum: ['data_use', 'nda', 'recipient_terms'] }, counterpartyOrgId: uuid, datapointIds: uuids, language: str(10) } } },
  }, async (req) => sys(async (tx) => ({ documentId: await rec.offerContract(tx, recDeps, req.principal, req.body.kind, req.body.counterpartyOrgId, req.body.datapointIds ?? [], req.body.language) })));

  app.post<{ Params: { id: string } }>('/api/documents/:id/approve', async (req) => {
    requireRole(req.principal, 'legal_officer');
    return sys(async (tx) => { await rec.approveDocument(tx, req.principal, req.params.id); return { ok: true }; });
  });

  app.post<{ Body: { documentId: string } }>('/api/contracts', {
    schema: { body: { type: 'object', required: ['documentId'], additionalProperties: false, properties: { documentId: uuid } } },
  }, async (req) => sys(async (tx) => ({ contractId: await rec.acceptContract(tx, req.principal, req.body.documentId) })));

  app.get<{ Params: { id: string; fmt: 'json' | 'pdf' } }>('/api/documents/:id.:fmt', async (req, reply) => {
    const doc = await sys(async (tx) => (await tx.query<{ kind: string; subject: Record<string, unknown>; content: unknown; pdf: Buffer; status: string; sha256: string }>(
      'SELECT kind, subject, content, pdf, status::text, sha256 FROM document WHERE id::text=$1', [req.params.id])).rows[0]);
    if (!doc) throw new rec.RecordError('Document not found', 404);
    const p = req.principal;
    const staff = p.orgKind === 'maker' && p.roles.some((r) => MAKER_STAFF.includes(r));
    const party = doc.status === 'approved' && (doc.subject['orgId'] === p.orgId || doc.kind === 'presale_datasheet' || doc.kind === 'related_service_notice' ||
      (doc.kind === 'decision_letter' && await sys(async (tx) => Boolean((await tx.query(
        'SELECT 1 FROM request WHERE id::text=$1 AND (requester_org_id=$2 OR recipient_org_id=$2)', [doc.subject['request'], p.orgId])).rowCount))));
    if (!staff && !party) throw new rec.RecordError('Document not found', 404);
    reply.header('X-Document-SHA256', doc.sha256);
    return req.params.fmt === 'pdf' ? reply.type('application/pdf').send(doc.pdf) : { kind: doc.kind, status: doc.status, content: doc.content, sha256: doc.sha256 };
  });

  app.get('/api/documents', async (req) => {
    requireRole(req.principal, ...MAKER_STAFF);
    return sys(async (tx) => (await tx.query('SELECT id, kind, template_id, template_version, subject, status, created_at, approved_at FROM document ORDER BY created_at DESC LIMIT 200')).rows);
  });

  // ── Grants and third-party delivery (R11–R15) ──
  app.get('/api/grants', async (req) => {
    const p = req.principal;
    return sys(async (tx) => (await tx.query(`SELECT g.*, c.name AS customer, r.name AS recipient FROM "grant" g JOIN organisation c ON c.id = g.customer_org_id
        JOIN organisation r ON r.id = g.recipient_org_id WHERE $1 OR g.customer_org_id=$2 OR g.recipient_org_id=$2 ORDER BY g.created_at DESC`,
      [p.orgKind === 'maker' && p.roles.includes('legal_officer'), p.orgId])).rows);
  });

  app.post<{ Body: { recipientOrgId: string; datapointIds: string[]; channels: Channel[]; purpose: string; expiresAt: string } }>('/api/grants', {
    schema: { body: { type: 'object', required: ['recipientOrgId', 'datapointIds', 'channels', 'purpose', 'expiresAt'], additionalProperties: false, properties: {
      recipientOrgId: uuid, datapointIds: { ...uuids, minItems: 1 }, channels: { type: 'array', minItems: 1, items: { enum: ['rest', 'sse', 'webhook', 'mqtt'] } },
      purpose: str(1000), expiresAt: { type: 'string', format: 'date-time' } } } },
  }, async (req) => {
    requireRole(req.principal, 'customer_admin');
    const created = await sys((tx) => rec.createGrant(tx, recDeps, req.principal, { ...req.body, expiresAt: new Date(req.body.expiresAt) }));
    if (d.keycloak) {
      const clients = await sys(async (tx) => (await tx.query<{ oidc_sub: string }>('SELECT oidc_sub FROM principal WHERE org_id=$1 AND machine_client', [req.body.recipientOrgId])).rows.map((r) => r.oidc_sub));
      if (clients.length) await d.keycloak.addGrantScope(created.id, clients);
    }
    return created;
  });

  app.delete<{ Params: { id: string } }>('/api/grants/:id', async (req) => {
    requireRole(req.principal, 'customer_admin');
    await sys((tx) => rec.revokeGrant(tx, req.principal, req.params.id));
    d.mqtt.publish(TOPIC_REVOKED, req.params.id, { qos: 1 });
    await d.dynsec.revokeGrant(req.params.id);
    await d.keycloak?.removeGrantScope(req.params.id);
    return { ok: true };
  });

  /** Recipient-owned grant that is active, on the channel, with accepted terms; otherwise 404/409. */
  async function recipientGrant(p: Principal, grantId: string, channel: Channel): Promise<void> {
    requireRole(p, 'recipient');
    const g = await sys(async (tx) => (await tx.query<{ channels: Channel[]; active: boolean }>(
      'SELECT channels, (revoked_at IS NULL AND expires_at > now()) AS active FROM "grant" WHERE id::text=$1 AND recipient_org_id=$2', [grantId, p.orgId])).rows[0]);
    if (!g?.active) throw new rec.RecordError('Active grant not found', 404);
    if (!g.channels.includes(channel)) throw new rec.RecordError(`The grant does not include ${channel}`, 409);
  }

  app.post<{ Params: { id: string }; Body: { url: string } }>('/api/grants/:id/webhooks', {
    schema: { body: { type: 'object', required: ['url'], additionalProperties: false, properties: { url: { type: 'string', pattern: '^https://', maxLength: 2000 } } } },
  }, async (req) => {
    await recipientGrant(req.principal, req.params.id, 'webhook');
    const secret = randomBytes(32).toString('base64url');
    const id = randomUUID();
    const sealed = await d.kek.wrap(Buffer.from(secret), `webhook:${id}`);
    await sys(async (tx) => tx.query('INSERT INTO webhook_endpoint (id, grant_id, url, secret_sealed) VALUES ($1,$2,$3,$4)', [id, req.params.id, req.body.url, sealed]));
    return { id, secret, note: 'Store this secret; it is shown once. Verify X-Signature: t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>.<body>")).' };
  });

  app.post<{ Params: { id: string } }>('/api/grants/:id/mqtt-credentials', async (req) => {
    await recipientGrant(req.principal, req.params.id, 'mqtt');
    const creds = await d.dynsec.rotateRecipientPassword(req.principal.orgId);
    await d.dynsec.allowGrant(req.principal.orgId, req.params.id);
    return { ...creds, topic: `grants/${req.params.id}/readings/#`, note: 'The password is shown once.' };
  });

  app.post<{ Body: { customerOrgId: string; datapointId: string; basis: string } }>('/api/legal-bases', {
    schema: { body: { type: 'object', required: ['customerOrgId', 'datapointId', 'basis'], additionalProperties: false, properties: { customerOrgId: uuid, datapointId: uuid, basis: str(1000) } } },
  }, async (req) => {
    requireRole(req.principal, 'legal_officer');
    return sys(async (tx) => { await rec.recordLegalBasis(tx, req.principal, req.body.customerOrgId, req.body.datapointId, req.body.basis); return { ok: true }; });
  });

  // ── Requests and decisions (R4, R8) ──
  app.post<{ Body: { kind: 'access' | 'share'; machineId: string; datapointIds: string[]; recipientOrgId?: string } }>('/api/requests', {
    schema: { body: { type: 'object', required: ['kind', 'machineId', 'datapointIds'], additionalProperties: false, properties: {
      kind: { enum: ['access', 'share'] }, machineId: uuid, datapointIds: { ...uuids, minItems: 1 }, recipientOrgId: uuid } } },
  }, async (req) => {
    requireRole(req.principal, 'customer_admin', 'customer_user');
    const b = req.body;
    return sys(async (tx) => {
      const id = await rec.createRequest(tx, recDeps, req.principal, b.kind, b.machineId, b.datapointIds, b.recipientOrgId ?? null);
      await rec.transition(tx, id, 'evaluated');
      // Share requests are judged with the recipient's NDAs; access requests with the customer's own.
      const subject: Principal = b.kind === 'share' ? { ...req.principal, orgId: b.recipientOrgId as string } : req.principal;
      const facts = await loadFacts(tx, d.config.gatekeepers, subject, b.machineId);
      if (!facts) throw new rec.RecordError('Machine not found', 404);
      if (b.kind === 'share' && facts.requesterIsGatekeeper) throw new rec.RecordError('Designated gatekeepers are not eligible third parties (Art. 5(3))', 403);
      const decision = policyDecide({ principal: req.principal, purpose: 'customer_access', channel: 'rest', requestedDatapointIds: b.datapointIds, now: new Date() }, facts);
      if (decision.denials.length === 0) await rec.recordAutomaticGrant(tx, id, decision.allowed);
      return { id, allowed: decision.allowed, denials: decision.denials, state: decision.denials.length === 0 ? 'granted' : 'evaluated' };
    });
  });

  app.get('/api/requests', async (req) => {
    const p = req.principal;
    return sys(async (tx) => (await tx.query(`SELECT r.*, (SELECT row_to_json(x) FROM decision x WHERE x.request_id = r.id ORDER BY x.decided_at DESC LIMIT 1) AS decision
        FROM request r WHERE $1 OR r.requester_org_id=$2 OR r.recipient_org_id=$2 ORDER BY r.received_at DESC LIMIT 500`,
      [p.orgKind === 'maker' && p.roles.includes('legal_officer'), p.orgId])).rows);
  });

  app.post<{ Params: { id: string }; Body: { outcome: 'granted' | 'withheld' | 'refused'; ground: 'security_risk' | 'trade_secret_measures_missing' | 'trade_secret_serious_damage' | null; justification: string; datapointIds: string[]; language: string } }>(
    '/api/requests/:id/decision', {
      schema: { body: { type: 'object', required: ['outcome', 'ground', 'justification', 'datapointIds', 'language'], additionalProperties: false, properties: {
        outcome: { enum: ['granted', 'withheld', 'refused'] }, ground: { enum: ['security_risk', 'trade_secret_measures_missing', 'trade_secret_serious_damage', null] },
        justification: { type: 'string', maxLength: 20_000 }, datapointIds: uuids, language: str(10) } } },
    }, async (req) => {
      requireRole(req.principal, 'legal_officer');
      const b = req.body;
      return sys(async (tx) => ({ decisionId: await rec.decide(tx, recDeps, req.principal, req.params.id,
        { outcome: b.outcome, ground: b.ground, justification: b.justification, datapointIds: b.datapointIds }, b.language) }));
    });

  app.get<{ Params: { id: string } }>('/api/reports/non-discrimination/:id', async (req) => {
    requireRole(req.principal, 'legal_officer');
    return sys((tx) => rec.nonDiscriminationReport(tx, req.params.id));
  });

  app.get('/api/notifications', async (req) => {
    requireRole(req.principal, ...MAKER_STAFF);
    return sys(async (tx) => (await tx.query('SELECT * FROM notification ORDER BY created_at DESC LIMIT 200')).rows);
  });

  return app;
}

async function ownModel(tx: Tx, p: Principal, modelId: string): Promise<void> {
  const r = await tx.query('SELECT 1 FROM product_model WHERE id::text=$1 AND maker_org_id=$2', [modelId, p.orgId]);
  if (!r.rowCount) throw new rec.RecordError('Model not found', 404);
}
