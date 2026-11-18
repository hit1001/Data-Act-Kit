// Document generator (design §5.9). Templates are lawyer-authored files; the kit ships none. A template is
// used only if it records who approved it (design §11). Rendering fails on any unfilled placeholder.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import PDFDocument from 'pdfkit';
import type { Tx } from './db.ts';

export const DOCUMENT_KINDS = [
  'presale_datasheet', 'related_service_notice', 'data_use_agreement', 'nda', 'recipient_terms', 'decision_letter', 'authority_notice',
] as const;
export type DocumentKind = (typeof DOCUMENT_KINDS)[number];

export interface Template {
  readonly id: string; readonly kind: DocumentKind; readonly version: string; readonly language: string; readonly title: string;
  readonly approvedBy: string; readonly approvedAt: string; readonly fixture: boolean;
  readonly sections: readonly { readonly heading: string; readonly body: string }[];
}

export class TemplateError extends Error { override readonly name = 'TemplateError'; }

function parseTemplate(raw: unknown, file: string): Template {
  const t = raw as Partial<Template>;
  const bad = (m: string) => new TemplateError(`${file}: ${m}`);
  if (!t || typeof t.id !== 'string' || !t.id) throw bad('id required');
  if (!DOCUMENT_KINDS.includes(t.kind as DocumentKind)) throw bad(`kind must be one of ${DOCUMENT_KINDS.join(', ')}`);
  if (typeof t.version !== 'string' || !t.version) throw bad('version required');
  if (typeof t.language !== 'string' || !/^[a-z]{2}(-[A-Z]{2})?$/.test(t.language)) throw bad('language must be a BCP 47 tag like de-DE');
  if (typeof t.title !== 'string' || !t.title) throw bad('title required');
  if (typeof t.approvedBy !== 'string' || !t.approvedBy || typeof t.approvedAt !== 'string' || Number.isNaN(Date.parse(t.approvedAt))) {
    throw bad('approvedBy and an ISO approvedAt are required: templates need recorded legal approval');
  }
  if (!Array.isArray(t.sections) || t.sections.length === 0 || !t.sections.every((s) => typeof s?.heading === 'string' && typeof s.body === 'string')) {
    throw bad('sections must be a non-empty array of { heading, body }');
  }
  return { ...(t as Template), fixture: t.fixture === true };
}

export class TemplateStore {
  private readonly templates: Template[];
  constructor(dir: string, allowFixtures: boolean) {
    this.templates = readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => parseTemplate(JSON.parse(readFileSync(join(dir, f), 'utf8')), f))
      .filter((t) => allowFixtures || !t.fixture);
    const keys = new Set<string>();
    for (const t of this.templates) {
      const k = `${t.id}@${t.version}`;
      if (keys.has(k)) throw new TemplateError(`Duplicate template ${k}`);
      keys.add(k);
    }
  }
  get(id: string, version: string): Template {
    const t = this.templates.find((x) => x.id === id && x.version === version);
    if (!t) throw new TemplateError(`Template ${id}@${version} is not installed`);
    return t;
  }
  /** The current template for a kind and language: the most recently approved version. */
  current(kind: DocumentKind, language: string): Template {
    const t = this.templates.filter((x) => x.kind === kind && x.language === language)
      .sort((a, b) => Date.parse(b.approvedAt) - Date.parse(a.approvedAt))[0];
    if (!t) throw new TemplateError(`No approved ${kind} template in ${language}`);
    return t;
  }
  list(): readonly Template[] { return this.templates; }
}

export type Context = Readonly<Record<string, string>>;

export function fill(text: string, ctx: Context): string {
  return text.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_, key: string) => {
    const v = ctx[key];
    if (v === undefined) throw new TemplateError(`No value for placeholder {{${key}}}`);
    return v;
  });
}

export interface Rendered { readonly content: { title: string; language: string; sections: { heading: string; body: string }[] }; readonly pdf: Buffer; readonly sha256: string }

export async function render(t: Template, ctx: Context, fonts: { regular: string; bold: string }): Promise<Rendered> {
  const content = { title: fill(t.title, ctx), language: t.language, sections: t.sections.map((s) => ({ heading: fill(s.heading, ctx), body: fill(s.body, ctx) })) };
  const pdf = await toPdfUa(content, fonts);
  return { content, pdf, sha256: createHash('sha256').update(pdf).digest('hex') };
}

/** Tagged PDF with PDF/UA identification, embedded fonts and a logical structure tree. */
function toPdfUa(c: Rendered['content'], fonts: { regular: string; bold: string }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // pdfkit 0.17 implements subset 'PDF/UA' at runtime; its type definitions only list PDF/A subsets.
    const options = { pdfVersion: '1.7', subset: 'PDF/UA', tagged: true, displayTitle: true, lang: c.language,
      info: { Title: c.title }, margin: 56 } as unknown as PDFKit.PDFDocumentOptions;
    const doc = new PDFDocument(options);
    const chunks: Buffer[] = [];
    doc.on('data', (b: Buffer) => chunks.push(b));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.registerFont('regular', fonts.regular);
    doc.registerFont('bold', fonts.bold);
    const root = doc.struct('Document');
    doc.addStructure(root);
    root.add(doc.struct('H1', {}, () => { doc.font('bold').fontSize(16).text(c.title); }));
    for (const s of c.sections) {
      root.add(doc.struct('H2', {}, () => { doc.moveDown(0.8).font('bold').fontSize(12).text(s.heading); }));
      for (const para of s.body.split(/\n{2,}/)) {
        root.add(doc.struct('P', {}, () => { doc.moveDown(0.3).font('regular').fontSize(10).text(para); }));
      }
    }
    root.end();
    doc.end();
  });
}

export async function storeDocument(tx: Tx, t: Template, subject: object, r: Rendered): Promise<string> {
  return (await tx.query<{ id: string }>(`INSERT INTO document (kind, template_id, template_version, subject, content, pdf, sha256)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id::text`,
    [t.kind, t.id, t.version, JSON.stringify(subject), JSON.stringify(r.content), r.pdf, r.sha256])).rows[0]!.id;
}

// ── Contexts: the facts each document states, taken from the catalogue and records ────────────────────

const fmtBytes = (n: number) => n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.round(n / 1e3)} kB`;

/** Art. 3(2) facts for a product model, from its published catalogue and the deployment's access means. */
export async function presaleContext(tx: Tx, modelId: string, publicBaseUrl: string): Promise<Context> {
  const m = (await tx.query<{ name: string; maker: string; version: number }>(
    'SELECT pm.name, o.name AS maker, pm.catalogue_version AS version FROM product_model pm JOIN organisation o ON o.id = pm.maker_org_id WHERE pm.id=$1', [modelId])).rows[0];
  if (!m) throw new TemplateError('Model not found');
  const dps = (await tx.query<{ name: string; dtype: string; unit_ucum: string | null; rate_hz: number | null; est: string | null; retention_days: number | null }>(
    `SELECT name, dtype::text, unit_ucum, rate_hz, est_bytes_per_day::text AS est, retention_days FROM datapoint
      WHERE model_id=$1 AND status='published' ORDER BY name`, [modelId])).rows;
  if (dps.length === 0) throw new TemplateError('The model has no published data points');
  const missingVolume = dps.filter((d) => d.est === null).map((d) => d.name);
  if (missingVolume.length) throw new TemplateError(`Estimated volume missing for: ${missingVolume.join(', ')} (Art. 3(2)(a))`);
  const missingRetention = dps.filter((d) => d.retention_days === null).map((d) => d.name);
  if (missingRetention.length) throw new TemplateError(`Retention missing for: ${missingRetention.join(', ')} (Art. 3(2)(c))`);
  const total = dps.reduce((s, d) => s + Number(d.est), 0);
  return {
    'model.name': m.name, 'maker.name': m.maker, 'catalogue.version': String(m.version),
    'data.list': dps.map((d) => `${d.name}: ${d.dtype}${d.unit_ucum ? ` [${d.unit_ucum}]` : ''}${d.rate_hz ? `, ${d.rate_hz} Hz` : ''}, ${fmtBytes(Number(d.est))}/day`).join('\n'),
    'data.formats': 'CSV, JSON, Parquet; metadata as JSON with JSON Schema',
    'data.estimated_volume_per_day': fmtBytes(total),
    'data.realtime': dps.some((d) => d.rate_hz !== null) ? 'yes' : 'no',
    'data.retention': [...new Set(dps.map((d) => d.retention_days))].map((x) => `${x} days`).join(', '),
    'access.portal_url': `${publicBaseUrl}/`,
    'access.api_url': `${publicBaseUrl}/api`,
    'access.catalogue_url': `${publicBaseUrl}/api/models/${modelId}/catalogue.json`,
  };
}

export async function partiesContext(tx: Tx, orgId: string, counterpartyOrgId: string, datapointIds: readonly string[]): Promise<Context> {
  const orgs = (await tx.query<{ id: string; name: string }>('SELECT id::text, name FROM organisation WHERE id::text = ANY($1)', [[orgId, counterpartyOrgId]])).rows;
  const name = (id: string) => orgs.find((o) => o.id === id)?.name ?? (() => { throw new TemplateError(`Organisation ${id} not found`); })();
  const dps = datapointIds.length ? (await tx.query<{ name: string }>('SELECT name FROM datapoint WHERE id::text = ANY($1) ORDER BY name', [datapointIds])).rows : [];
  return { 'party.name': name(orgId), 'counterparty.name': name(counterpartyOrgId), 'datapoints.list': dps.map((d) => d.name).join(', ') || '—' };
}
