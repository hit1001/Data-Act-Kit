// Configuration from the environment. Values the design leaves to counsel or the operator have no
// defaults: the process refuses to start without them rather than assume.
import { readFileSync } from 'node:fs';

export interface GatekeeperEntry { readonly name: string; readonly identifiers: readonly string[] }
export interface GatekeeperList { readonly source: string; readonly reviewedAt: string; readonly entries: readonly GatekeeperEntry[] }

export interface Config {
  readonly databaseUrl: string;
  readonly oidc: { readonly issuer: string; readonly discoveryUrl: string; readonly audience: string; readonly portalClientId: string };
  readonly mqtt: { readonly url: string; readonly username: string; readonly password: string; readonly caFile: string };
  readonly kek: { readonly id: string; readonly file: string };
  readonly fingerprintSecretFile: string;
  readonly accessLogRetentionDays: number;
  readonly requestDeadlineHours: number;
  readonly gatekeepers: GatekeeperList;
  readonly templatesDir: string;
  readonly documentFont: { readonly regular: string; readonly bold: string };
  readonly rateLimitPerMinute: number;
  readonly httpPort: number;
  readonly publicBaseUrl: string;
  readonly alertWebhookUrl: string | null;
  readonly llm: { readonly url: string; readonly model: string } | null;
  readonly mavt: { readonly url: string; readonly apiKey: string } | null;
  readonly keycloakAdmin: { readonly url: string; readonly realm: string; readonly clientId: string; readonly clientSecretFile: string } | null;
  readonly allowFixtureTemplates: boolean;
}

export class ConfigError extends Error { override readonly name = 'ConfigError'; }

type Env = Readonly<Record<string, string | undefined>>;

function req(env: Env, key: string): string {
  const v = env[key]?.trim();
  if (!v) throw new ConfigError(`${key} is required`);
  return v;
}
function opt(env: Env, key: string): string | null { return env[key]?.trim() || null; }
function posInt(env: Env, key: string): number {
  const n = Number(req(env, key));
  if (!Number.isInteger(n) || n <= 0) throw new ConfigError(`${key} must be a positive integer`);
  return n;
}

export function parseGatekeepers(raw: unknown): GatekeeperList {
  const o = raw as Partial<GatekeeperList> | null;
  if (!o || typeof o.source !== 'string' || !o.source || typeof o.reviewedAt !== 'string' || Number.isNaN(Date.parse(o.reviewedAt))) {
    throw new ConfigError('Gatekeeper list needs "source" and an ISO "reviewedAt" (open question 7 in the design)');
  }
  if (!Array.isArray(o.entries) || !o.entries.every((e) => typeof e?.name === 'string' && Array.isArray(e.identifiers))) {
    throw new ConfigError('Gatekeeper list "entries" must be [{ name, identifiers[] }]');
  }
  return { source: o.source, reviewedAt: o.reviewedAt, entries: o.entries };
}

export function loadConfig(env: Env = process.env): Config {
  const llmUrl = opt(env, 'LLM_URL');
  const kcUrl = opt(env, 'KEYCLOAK_ADMIN_URL');
  return {
    databaseUrl: req(env, 'DATABASE_URL'),
    oidc: { issuer: req(env, 'OIDC_ISSUER'), discoveryUrl: opt(env, 'OIDC_DISCOVERY_URL') ?? req(env, 'OIDC_ISSUER'), audience: req(env, 'OIDC_AUDIENCE'), portalClientId: req(env, 'OIDC_PORTAL_CLIENT_ID') },
    mqtt: { url: req(env, 'MQTT_URL'), username: req(env, 'MQTT_USERNAME'), password: readFileSync(req(env, 'MQTT_PASSWORD_FILE'), 'utf8').trim(), caFile: req(env, 'MQTT_CA_FILE') },
    kek: { id: req(env, 'KEK_ID'), file: req(env, 'KEK_FILE') },
    fingerprintSecretFile: req(env, 'FINGERPRINT_SECRET_FILE'),
    accessLogRetentionDays: posInt(env, 'ACCESS_LOG_RETENTION_DAYS'),
    requestDeadlineHours: posInt(env, 'REQUEST_DEADLINE_HOURS'),
    gatekeepers: parseGatekeepers(JSON.parse(readFileSync(req(env, 'GATEKEEPERS_FILE'), 'utf8'))),
    templatesDir: req(env, 'TEMPLATES_DIR'),
    documentFont: { regular: req(env, 'DOCUMENT_FONT_FILE'), bold: req(env, 'DOCUMENT_FONT_BOLD_FILE') },
    rateLimitPerMinute: posInt(env, 'RATE_LIMIT_PER_MINUTE'),
    httpPort: posInt(env, 'HTTP_PORT'),
    publicBaseUrl: req(env, 'PUBLIC_BASE_URL').replace(/\/+$/, ''),
    alertWebhookUrl: opt(env, 'ALERT_WEBHOOK_URL'),
    llm: llmUrl ? { url: llmUrl.replace(/\/+$/, ''), model: req(env, 'LLM_MODEL') } : null,
    mavt: opt(env, 'MAVT_URL') ? { url: req(env, 'MAVT_URL'), apiKey: readFileSync(req(env, 'MAVT_API_KEY_FILE'), 'utf8').trim() } : null,
    keycloakAdmin: kcUrl ? {
      url: kcUrl.replace(/\/+$/, ''), realm: req(env, 'KEYCLOAK_REALM'),
      clientId: req(env, 'KEYCLOAK_ADMIN_CLIENT_ID'), clientSecretFile: req(env, 'KEYCLOAK_ADMIN_CLIENT_SECRET_FILE'),
    } : null,
    allowFixtureTemplates: env['ALLOW_FIXTURE_TEMPLATES'] === '1',
  };
}

export function readKey(file: string): Buffer {
  const hex = readFileSync(file, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new ConfigError(`${file} must contain 64 hex characters (32 bytes)`);
  return Buffer.from(hex, 'hex');
}
