// Portal (design §5.6, §5.7). OIDC authorization-code flow with PKCE; every value from the server is
// rendered as text, never as HTML. Grant, decline and revoke are equally prominent (R5).

const $ = (s) => document.querySelector(s);
const cfg = await (await fetch('/portal-config.json')).json();
let token = sessionStorage.getItem('token');
let me = null;

// ── OIDC (PKCE) ───────────────────────────────────────────────────────────────
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function login() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem('pkce', JSON.stringify({ verifier, state }));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  const disco = await (await fetch(`${cfg.issuer}/.well-known/openid-configuration`)).json();
  const u = new URL(disco.authorization_endpoint);
  Object.entries({ client_id: cfg.clientId, response_type: 'code', scope: 'openid', redirect_uri: `${location.origin}/callback`,
    code_challenge: challenge, code_challenge_method: 'S256', state }).forEach(([k, v]) => u.searchParams.set(k, v));
  location.assign(u);
}
async function finishLogin() {
  const q = new URLSearchParams(location.search);
  const saved = JSON.parse(sessionStorage.getItem('pkce') ?? 'null');
  if (!saved || q.get('state') !== saved.state) throw new Error('Login state mismatch');
  const disco = await (await fetch(`${cfg.issuer}/.well-known/openid-configuration`)).json();
  const res = await fetch(disco.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: cfg.clientId, code: q.get('code') ?? '', redirect_uri: `${location.origin}/callback`, code_verifier: saved.verifier }) });
  if (!res.ok) throw new Error('Login failed');
  token = (await res.json()).access_token;
  sessionStorage.setItem('token', token);
  sessionStorage.removeItem('pkce');
  history.replaceState(null, '', '/');
}

// ── API and DOM helpers ───────────────────────────────────────────────────────
async function api(method, path, body, raw = false) {
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined && typeof body !== 'string') headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  if (res.status === 401) { sessionStorage.removeItem('token'); return login(); }
  if (raw) { if (!res.ok) throw new Error((await res.json()).error ?? `HTTP ${res.status}`); return res; }
  const data = res.headers.get('content-type')?.includes('json') ? await res.json() : null;
  if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
  return data;
}
function h(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (v !== undefined && v !== null) e.setAttribute(k, v === true ? '' : v);
  e.append(...kids.flat().filter((x) => x !== null && x !== undefined).map((x) => (x instanceof Node ? x : String(x))));
  return e;
}
function toast(text, kind = 'ok') {
  const t = h('div', { class: `toast t-${kind}` }, h('div', { class: 'toast-body' }, h('div', { class: 'toast-text' }, text)));
  $('#toasts').append(t); setTimeout(() => t.remove(), 6000);
}
const act = (fn) => async (e) => { e?.preventDefault?.(); try { await fn(e); } catch (err) { toast(err.message, 'err'); } };
function table(cols, rows) {
  if (!rows.length) return h('p', { class: 'empty' }, 'Nothing here yet.');
  return h('div', { class: 'table-scroll' }, h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, cols.map((c) => h('th', {}, c[0])))),
    h('tbody', {}, rows.map((r) => h('tr', {}, cols.map((c) => h('td', {}, c[1](r))))))));
}
function form(fields, submitLabel, onSubmit) {
  const f = h('form', { class: 'inline' }, fields.map(([name, label, type = 'text', extra = {}]) => h('div', { class: 'field' }, h('label', { for: `f-${name}` }, label),
    type === 'select' ? h('select', { class: 'select', id: `f-${name}`, name, ...extra.attrs }, (extra.options ?? []).map(([v, t]) => h('option', { value: v }, t)))
      : type === 'textarea' ? h('textarea', { class: 'input', id: `f-${name}`, name, rows: 3, ...extra.attrs })
        : h('input', { class: 'input', id: `f-${name}`, name, type, ...extra.attrs }))), h('button', { class: 'btn btn-primary', type: 'submit' }, submitLabel));
  f.addEventListener('submit', act(async (e) => { await onSubmit(Object.fromEntries(new FormData(f)), f); }));
  return f;
}
const date = (v) => (v ? new Date(v).toLocaleString() : '–');
const download = (blob, name) => { const a = h('a', { href: URL.createObjectURL(blob), download: name }); a.click(); URL.revokeObjectURL(a.href); };

// ── Views ─────────────────────────────────────────────────────────────────────
const views = {
  async machines() {
    const rows = await api('GET', '/api/machines');
    const out = [h('h1', {}, 'Machines'), table([['Model', (r) => r.model], ['Serial', (r) => r.serial], ['Linked', (r) => date(r.linked_at)], ['Id', (r) => h('span', { class: 'mono' }, r.id)]], rows)];
    if (me.roles.includes('customer_admin')) {
      out.push(h('h2', {}, 'Link a machine you own or lease'), h('p', { class: 'note' }, 'Only the serial number and your invoice or contract reference are needed.'),
        form([['modelId', 'Model id'], ['serial', 'Serial number'], ['evidenceRef', 'Invoice or contract reference']], 'Request link',
          async (v) => { await api('POST', '/api/link-requests', v); toast('Link requested; the maker will confirm it.'); }));
    }
    if (me.roles.includes('maker_admin')) {
      const lrs = await api('GET', '/api/link-requests');
      out.push(h('h2', {}, 'Link requests'), table([['Customer', (r) => r.customer], ['Model', (r) => r.model], ['Serial', (r) => r.serial], ['Evidence', (r) => r.evidence_ref], ['Status', (r) => r.status],
        ['', (r) => r.status !== 'pending' ? '' : h('div', { class: 'row' },
          h('button', { class: 'btn btn-sm', onclick: act(async () => { await api('POST', `/api/link-requests/${r.id}/approve`); render('machines'); }) }, 'Approve'),
          h('button', { class: 'btn btn-sm', onclick: act(async () => { await api('POST', `/api/link-requests/${r.id}/reject`); render('machines'); }) }, 'Reject'))]], lrs),
      h('h2', {}, 'Register a machine'), form([['modelId', 'Model id'], ['serial', 'Serial number']], 'Register', async (v) => { await api('POST', '/api/machines', v); render('machines'); }),
      h('h2', {}, 'Register an edge device'), form([['id', 'Device id (certificate CN)'], ['machineId', 'Machine id']], 'Register', async (v) => { await api('POST', '/api/devices', v); toast('Device registered'); }));
    }
    return out;
  },

  async data() {
    const machines = await api('GET', '/api/machines');
    const result = h('div');
    let live = null;
    const now = new Date(), dayAgo = new Date(now.getTime() - 86_400_000);
    const f = form([['machine', 'Machine', 'select', { options: machines.map((m) => [m.id, `${m.model} · ${m.serial}`]) }],
      ['datapoints', 'Data point ids (comma-separated)'], ['from', 'From', 'datetime-local', { attrs: { value: dayAgo.toISOString().slice(0, 16) } }],
      ['to', 'To', 'datetime-local', { attrs: { value: now.toISOString().slice(0, 16) } }],
      ['format', 'Format', 'select', { options: [['json', 'JSON'], ['csv', 'CSV'], ['parquet', 'Parquet']] }]], 'Get data', async (v) => {
      const q = new URLSearchParams({ datapoints: v.datapoints, from: new Date(v.from).toISOString(), to: new Date(v.to).toISOString(), format: v.format });
      const res = await api('GET', `/api/machines/${v.machine}/readings?${q}`, undefined, true);
      if (v.format === 'json') { const j = await res.json(); result.replaceChildren(h('h2', {}, `${j.data.length} readings`), h('pre', {}, JSON.stringify(j, null, 2).slice(0, 20_000))); }
      else download(await res.blob(), `machine-${v.machine}.${v.format}`);
    });
    const liveBtn = h('button', { class: 'btn', onclick: act(async () => {
      if (live) { live.abort(); live = null; liveBtn.textContent = 'Start live view'; return; }
      const v = Object.fromEntries(new FormData(f));
      live = new AbortController(); liveBtn.textContent = 'Stop live view';
      const res = await fetch(`/api/machines/${v.machine}/stream?datapoints=${encodeURIComponent(v.datapoints)}`, { headers: { Authorization: `Bearer ${token}` }, signal: live.signal });
      if (!res.ok) throw new Error((await res.json()).error);
      const pre = h('pre'); result.replaceChildren(h('h2', {}, 'Live'), pre);
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      for (;;) { const { value, done } = await reader.read(); if (done) break; pre.textContent = (value + pre.textContent).slice(0, 20_000); }
    }) }, 'Start live view');
    return [h('h1', {}, 'Machine data'), h('p', { class: 'note' }, 'Data comes with its metadata. Data points you may not receive are listed with the reason.'), f, liveBtn, result];
  },

  async grants() {
    const rows = await api('GET', '/api/grants');
    const out = [h('h1', {}, 'Data sharing'), table([['Customer', (r) => r.customer], ['Recipient', (r) => r.recipient], ['Channels', (r) => r.channels.join(', ')], ['Purpose', (r) => r.purpose],
      ['Expires', (r) => date(r.expires_at)], ['Fee', (r) => `${(r.compensation.totalCents / 100).toFixed(2)} €${r.compensation.capped ? ' (cost only)' : ''}`],
      ['Status', (r) => (r.revoked_at ? `Revoked ${date(r.revoked_at)}` : 'Active')],
      ['', (r) => {
        if (r.revoked_at) return '';
        const btns = [];
        if (me.roles.includes('customer_admin')) btns.push(h('button', { class: 'btn btn-sm', onclick: act(async () => { await api('DELETE', `/api/grants/${r.id}`); render('grants'); }) }, 'Revoke'));
        if (me.roles.includes('recipient') && r.channels.includes('mqtt')) btns.push(h('button', { class: 'btn btn-sm', onclick: act(async () => { const c = await api('POST', `/api/grants/${r.id}/mqtt-credentials`); alert(`MQTT username: ${c.username}\npassword (shown once): ${c.password}\ntopic: ${c.topic}`); }) }, 'MQTT credentials'));
        return h('div', { class: 'row' }, btns);
      }]], rows)];
    if (me.roles.includes('customer_admin')) {
      out.push(h('h2', {}, 'Share data with a third party'), h('p', { class: 'note' }, 'You choose who receives which data, how, and until when. You can revoke at any time; you pay nothing.'),
        form([['recipientOrgId', 'Recipient organisation id'], ['datapointIds', 'Data point ids (comma-separated)'], ['channels', 'Channels (rest, sse, webhook, mqtt)'],
          ['purpose', 'Purpose agreed with the recipient'], ['expiresAt', 'Expires', 'datetime-local']], 'Share', async (v) => {
          const g = await api('POST', '/api/grants', { recipientOrgId: v.recipientOrgId, datapointIds: v.datapointIds.split(',').map((s) => s.trim()).filter(Boolean),
            channels: v.channels.split(',').map((s) => s.trim()).filter(Boolean), purpose: v.purpose, expiresAt: new Date(v.expiresAt).toISOString() });
          toast(`Shared. The recipient's fee: ${(g.compensation.totalCents / 100).toFixed(2)} €`); render('grants');
        }));
    }
    if (me.roles.includes('recipient')) {
      out.push(h('h2', {}, 'Receive pushes by webhook'), form([['grantId', 'Grant id'], ['url', 'HTTPS URL']], 'Register webhook', async (v) => {
        const w = await api('POST', `/api/grants/${v.grantId}/webhooks`, { url: v.url }); alert(`Webhook secret (shown once): ${w.secret}\n${w.note}`);
      }));
    }
    return out;
  },

  async contracts() {
    const templates = await api('GET', '/api/templates');
    const out = [h('h1', {}, 'Agreements'), h('p', { class: 'note' }, 'Request an agreement; the maker approves the document, then you can read and accept it.')];
    const kinds = me.orgKind === 'customer' ? [['data_use', 'Data-use agreement (maker uses your data)'], ['nda', 'Confidentiality agreement for trade secrets']]
      : me.orgKind === 'recipient' ? [['recipient_terms', 'Recipient terms'], ['nda', 'Confidentiality agreement for trade secrets']] : [];
    if (kinds.length) {
      out.push(form([['kind', 'Agreement', 'select', { options: kinds }], ['counterpartyOrgId', 'Maker organisation id'], ['datapointIds', 'Trade-secret data point ids (NDA only)'],
        ['language', 'Language', 'select', { options: [...new Set(templates.map((t) => t.language))].map((l) => [l, l]) }]], 'Request agreement', async (v) => {
        const r = await api('POST', '/api/contract-offers', { kind: v.kind, counterpartyOrgId: v.counterpartyOrgId, language: v.language,
          ...(v.datapointIds ? { datapointIds: v.datapointIds.split(',').map((s) => s.trim()).filter(Boolean) } : {}) });
        toast(`Requested. Document ${r.documentId} awaits approval.`);
      }), h('h2', {}, 'Accept an approved agreement'), form([['documentId', 'Document id']], 'Read', async (v) => {
        const doc = await api('GET', `/api/documents/${v.documentId}.json`);
        const box = h('div', {}, h('h2', {}, doc.content.title), doc.content.sections.map((s) => [h('h3', {}, s.heading), h('p', {}, s.body)]),
          h('div', { class: 'row' }, h('button', { class: 'btn btn-primary', onclick: act(async () => { await api('POST', '/api/contracts', { documentId: v.documentId }); toast('Accepted'); box.remove(); }) }, 'Accept'),
            h('button', { class: 'btn', onclick: () => box.remove() }, 'Decline')));
        out.at(-1).after(box);
      }));
    }
    return out;
  },

  async requests() {
    const rows = await api('GET', '/api/requests');
    const out = [h('h1', {}, 'Requests'), table([['Kind', (r) => r.kind], ['Machine', (r) => r.machine_id], ['State', (r) => r.state], ['Received', (r) => date(r.received_at)],
      ['Due', (r) => date(r.due_at)], ['Decision', (r) => r.decision ? `${r.decision.outcome}${r.decision.ground ? ` · ${r.decision.ground}` : ''}` : '–'], ['Id', (r) => h('span', { class: 'mono' }, r.id)]], rows)];
    if (me.roles.some((r) => r === 'customer_admin' || r === 'customer_user')) {
      out.push(h('h2', {}, 'New request'), form([['kind', 'Kind', 'select', { options: [['access', 'Access my data'], ['share', 'Share with a third party']] }], ['machineId', 'Machine id'],
        ['datapointIds', 'Data point ids (comma-separated)'], ['recipientOrgId', 'Recipient organisation id (share only)']], 'Send request', async (v) => {
        const r = await api('POST', '/api/requests', { kind: v.kind, machineId: v.machineId, datapointIds: v.datapointIds.split(',').map((s) => s.trim()).filter(Boolean),
          ...(v.kind === 'share' ? { recipientOrgId: v.recipientOrgId } : {}) });
        toast(r.state === 'granted' ? 'Granted' : 'Received; some data points need a decision'); render('requests');
      }));
    }
    if (me.roles.includes('legal_officer')) {
      out.push(h('h2', {}, 'Decide a request'), h('p', { class: 'note' }, 'Withholding or refusing creates a decision letter and the notice to the competent authority, both for your approval.'),
        form([['requestId', 'Request id'], ['outcome', 'Outcome', 'select', { options: [['withheld', 'Withhold'], ['refused', 'Refuse'], ['granted', 'Grant']] }],
          ['ground', 'Legal ground', 'select', { options: [['', '— none (grant)'], ['trade_secret_measures_missing', 'Art. 4(7)/5(10) confidentiality measures missing'],
            ['trade_secret_serious_damage', 'Art. 4(8)/5(11) serious economic damage'], ['security_risk', 'Art. 4(2) security risk']] }],
          ['datapointIds', 'Affected data point ids'], ['justification', 'Written justification', 'textarea'], ['language', 'Language']], 'Record decision', async (v) => {
          await api('POST', `/api/requests/${v.requestId}/decision`, { outcome: v.outcome, ground: v.ground || null, justification: v.justification, language: v.language,
            datapointIds: v.datapointIds.split(',').map((s) => s.trim()).filter(Boolean) });
          toast('Decision recorded; approve the documents under Documents.'); render('requests');
        }));
    }
    return out;
  },

  async catalogue() {
    const models = await api('GET', '/api/models');
    const out = [h('h1', {}, 'Product models and catalogue'), table([['Model', (m) => m.name], ['Catalogue version', (m) => m.catalogue_version], ['On market', (m) => m.placed_on_market_at ?? '–'],
      ['', (m) => h('div', { class: 'row' }, h('button', { class: 'btn btn-sm', onclick: act(() => render('review', m)) }, 'Review'),
        h('button', { class: 'btn btn-sm', onclick: act(async () => { const a = await api('GET', `/api/models/${m.id}/applicability`); toast(`${a.reason}${a.changesAt ? ` · changes ${date(a.changesAt)}` : ''}`); }) }, 'Obligations'))]], models)];
    if (me.roles.includes('maker_admin')) out.push(h('h2', {}, 'New model'), form([['name', 'Name'], ['placedOnMarketAt', 'Placed on market', 'date'],
      ['makerSizeAtPlacement', 'Your size when placed', 'select', { options: [['', '—'], ['micro', 'Micro'], ['small', 'Small'], ['medium', 'Medium'], ['large', 'Large']] }]], 'Create', async (v) => {
      await api('POST', '/api/models', { name: v.name, ...(v.placedOnMarketAt ? { placedOnMarketAt: v.placedOnMarketAt } : {}), ...(v.makerSizeAtPlacement ? { makerSizeAtPlacement: v.makerSizeAtPlacement } : {}) });
      render('catalogue');
    }));
    return out;
  },

  async review(model) {
    const pts = await api('GET', `/api/models/${model.id}/datapoints`);
    const file = h('input', { type: 'file', accept: '.xml,.csv' });
    const out = [h('h1', {}, `Catalogue · ${model.name}`),
      h('div', { class: 'row' }, file, h('button', { class: 'btn', onclick: act(async () => {
        const f = file.files[0]; if (!f) throw new Error('Choose a NodeSet2 XML or tag-list CSV file');
        const res = await fetch(`/api/models/${model.id}/import`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': f.name.endsWith('.csv') ? 'text/csv' : 'application/xml' }, body: await f.text() });
        const j = await res.json(); if (!res.ok) throw new Error(j.error);
        toast(`Added ${j.added}, existing ${j.existing}, skipped ${j.skipped.length}`); render('review', model);
      }) }, 'Import'),
        h('button', { class: 'btn', onclick: act(async () => { const r = await api('POST', `/api/models/${model.id}/draft`); toast(`Drafted ${r.drafted}, rejected ${r.rejected}`); render('review', model); }) }, 'Draft descriptions with AI'),
        h('button', { class: 'btn btn-primary', onclick: act(async () => { const r = await api('POST', `/api/models/${model.id}/publish`); toast(`Published version ${r.version}; ${r.documents.filter((x) => x.documentId).length} documents queued for approval`); render('review', model); }) }, 'Publish reviewed')),
      h('p', { class: 'note' }, 'AI drafts are suggestions. Nothing is published until a reviewer saves it.'),
      table([['Name', (p) => p.name], ['Address', (p) => h('span', { class: 'mono' }, p.source_address)], ['Type', (p) => p.dtype], ['Status', (p) => `${p.status}${p.reviewed_at ? ' · reviewed' : ''}`],
        ['Review', (p) => form([['description', 'Description', 'text', { attrs: { value: p.description ?? p.draft_description ?? '' } }], ['unitUcum', 'Unit (UCUM)', 'text', { attrs: { value: p.unit_ucum ?? p.draft_unit_ucum ?? '' } }],
          ['rateHz', 'Rate Hz', 'number', { attrs: { value: p.rate_hz ?? '', step: 'any' } }], ['estBytesPerDay', 'Bytes/day', 'number', { attrs: { value: p.est_bytes_per_day ?? '' } }],
          ['retentionDays', 'Retention days', 'number', { attrs: { value: p.retention_days ?? '' } }],
          ['tradeSecret', 'Trade secret', 'select', { options: [['false', 'No'], ['true', 'Yes']] }], ['tsHolder', 'Secret holder', 'text', { attrs: { value: p.ts_holder ?? '' } }],
          ['personalData', 'Personal data', 'select', { options: [['false', 'No'], ['true', 'Yes']] }], ['personalCategory', 'Category', 'text', { attrs: { value: p.personal_category ?? '' } }]],
          'Save review', async (v) => {
            const num = (x) => (x === '' ? null : Number(x));
            await api('PUT', `/api/datapoints/${p.id}/review`, { description: v.description, unitUcum: v.unitUcum || null, rateHz: num(v.rateHz), estBytesPerDay: num(v.estBytesPerDay),
              tradeSecret: v.tradeSecret === 'true', tsHolder: v.tsHolder || null, personalData: v.personalData === 'true', personalCategory: v.personalCategory || null, retentionDays: num(v.retentionDays) });
            toast('Saved');
          })]], pts)];
    if (me.roles.includes('legal_officer')) {
      const keys = [['relatedServiceData', 'Related-service data and how users access it (3(3)(b))'], ['holderUses', 'Your own uses and purposes (3(3)(c))'], ['thirdPartyUse', 'Third-party use agreed with users (3(3)(c))'],
        ['holderIdentity', 'Your trading name and address (3(3)(d))'], ['contact', 'How to contact you (3(3)(e))'], ['competentAuthority', 'Competent authority for complaints (3(3)(g))'], ['contractDuration', 'Contract duration and termination (3(3)(i))']];
      out.push(h('h2', {}, 'Related-service information (Art. 3(3))'), form(keys.map(([k, l]) => [k, l, 'textarea']), 'Save', async (v) => { await api('PUT', `/api/models/${model.id}/related-service`, v); toast('Saved'); }));
    }
    return out;
  },

  async documents() {
    const rows = await api('GET', '/api/documents');
    return [h('h1', {}, 'Documents'), h('p', { class: 'note' }, 'Nothing reaches a customer, recipient or authority until it is approved here.'),
      table([['Kind', (d) => d.kind], ['Template', (d) => `${d.template_id}@${d.template_version}`], ['Created', (d) => date(d.created_at)], ['Status', (d) => d.status],
        ['', (d) => h('div', { class: 'row' }, h('button', { class: 'btn btn-sm', onclick: act(async () => download(await (await api('GET', `/api/documents/${d.id}.pdf`, undefined, true)).blob(), `${d.kind}.pdf`)) }, 'PDF'),
          d.status === 'draft' && me.roles.includes('legal_officer') ? h('button', { class: 'btn btn-sm', onclick: act(async () => { await api('POST', `/api/documents/${d.id}/approve`); render('documents'); }) }, 'Approve') : null)]], rows)];
  },

  async admin() {
    const out = [h('h1', {}, 'Organisations and access')];
    if (me.roles.includes('maker_admin')) {
      out.push(h('h2', {}, 'Add an organisation'), form([['name', 'Name'], ['kind', 'Kind', 'select', { options: [['customer', 'Customer'], ['recipient', 'Recipient']] }],
        ['groupIdentifier', 'Group identifier (e.g. LEI of the ultimate parent)'], ['recipientCategoryId', 'Recipient category id'],
        ['smeFlag', 'SME', 'select', { options: [['false', 'No'], ['true', 'Yes']] }], ['verified', 'Verified', 'select', { options: [['false', 'No'], ['true', 'Yes']] }]], 'Add', async (v) => {
        const r = await api('POST', '/api/organisations', { name: v.name, kind: v.kind, smeFlag: v.smeFlag === 'true', verified: v.verified === 'true',
          ...(v.groupIdentifier ? { groupIdentifier: v.groupIdentifier } : {}), ...(v.recipientCategoryId ? { recipientCategoryId: v.recipientCategoryId } : {}) });
        toast(`Organisation ${r.id}`);
      }), h('h2', {}, 'Register a person or machine client'), form([['orgId', 'Organisation id'], ['oidcSub', 'Identity-provider subject (sub)'], ['roles', 'Roles (comma-separated)'],
        ['machineClient', 'Machine client', 'select', { options: [['false', 'No'], ['true', 'Yes']] }]], 'Register', async (v) => {
        await api('POST', '/api/principals', { orgId: v.orgId, oidcSub: v.oidcSub, roles: v.roles.split(',').map((s) => s.trim()), machineClient: v.machineClient === 'true' }); toast('Registered');
      }));
    }
    if (me.roles.includes('legal_officer')) {
      out.push(h('h2', {}, 'Recipient category (terms and fees, identical for every member)'), form([['name', 'Name'], ['termsTemplateId', 'Terms template id'], ['termsTemplateVersion', 'Terms template version'],
        ['formattingCents', 'Formatting (cents)', 'number'], ['disseminationCents', 'Dissemination (cents)', 'number'], ['storageCents', 'Storage (cents)', 'number'],
        ['investmentShareCents', 'Investment share (cents)', 'number'], ['marginRate', 'Margin (e.g. 0.1)', 'number', { attrs: { step: 'any' } }]], 'Create', async (v) => {
        const r = await api('POST', '/api/recipient-categories', { ...v, formattingCents: +v.formattingCents, disseminationCents: +v.disseminationCents, storageCents: +v.storageCents,
          investmentShareCents: +v.investmentShareCents, marginRate: +v.marginRate });
        toast(`Category ${r.id}`);
      }), h('h2', {}, 'Personal-data legal basis'), form([['customerOrgId', 'Customer organisation id'], ['datapointId', 'Data point id'], ['basis', 'GDPR legal basis']], 'Record',
        async (v) => { await api('POST', '/api/legal-bases', v); toast('Recorded'); }),
      h('h2', {}, 'Non-discrimination report'), form([['categoryId', 'Recipient category id']], 'Show', async (v, f) => { f.after(h('pre', {}, JSON.stringify(await api('GET', `/api/reports/non-discrimination/${v.categoryId}`), null, 2))); }));
    }
    const notes = me.orgKind === 'maker' ? await api('GET', '/api/notifications') : [];
    if (notes.length) out.push(h('h2', {}, 'Deadline alerts'), table([['When', (n) => date(n.created_at)], ['Message', (n) => n.message]], notes));
    return out;
  },
};

const NAV = [
  ['machines', 'Machines', () => true], ['data', 'Machine data', () => me.orgKind !== 'maker'], ['grants', 'Data sharing', () => true],
  ['contracts', 'Agreements', () => me.orgKind !== 'maker'], ['requests', 'Requests', () => me.orgKind !== 'recipient'],
  ['catalogue', 'Catalogue', () => me.orgKind === 'maker'], ['documents', 'Documents', () => me.orgKind === 'maker'], ['admin', 'Administration', () => me.orgKind === 'maker'],
];

async function render(view, arg) {
  for (const b of document.querySelectorAll('nav button')) b.setAttribute('aria-current', b.dataset.view === view ? 'page' : 'false');
  const main = $('#main');
  try { main.replaceChildren(...[await views[view](arg)].flat()); } catch (err) { main.replaceChildren(h('p', { class: 'err' }, err.message)); }
}

try {
  if (location.pathname === '/callback') await finishLogin();
  if (!token) await login();
  else {
    me = await api('GET', '/api/me');
    $('#who').textContent = `${me.orgKind} · ${me.roles.join(', ')}`;
    $('#logout').hidden = false;
    $('#logout').addEventListener('click', () => { sessionStorage.clear(); location.assign('/'); });
    $('#nav').replaceChildren(...NAV.filter(([, , show]) => show()).map(([v, label]) => h('button', { 'data-view': v, onclick: () => render(v) }, label)));
    await render(NAV.find(([, , show]) => show())[0]);
  }
} catch (err) {
  $('#main').replaceChildren(h('p', { class: 'err' }, err.message));
}
