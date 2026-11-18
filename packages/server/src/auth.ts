// OIDC bearer-token validation (design §5.7). The identity provider proves who the caller is; the
// database decides which organisation and roles they have.
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type pg from 'pg';
import type { OrgKind, Principal, Role } from '@dak/core';
import { withScope } from './db.ts';

export class AuthError extends Error {
  override readonly name = 'AuthError';
  readonly status: 401 | 403;
  constructor(message: string, status: 401 | 403) { super(message); this.status = status; }
}

export interface Authenticator { authenticate(authorization: string | undefined): Promise<Principal> }

/** `discoveryUrl` may differ from the issuer when the API reaches the provider on an internal address. */
export async function discoverJwksUri(issuer: string, discoveryUrl: string = issuer): Promise<URL> {
  const res = await fetch(`${discoveryUrl.replace(/\/+$/, '')}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed for ${issuer}: HTTP ${res.status}`);
  const doc = (await res.json()) as { jwks_uri?: string; issuer?: string };
  if (!doc.jwks_uri || doc.issuer !== issuer) throw new Error('OIDC discovery document does not match the configured issuer');
  return new URL(doc.jwks_uri);
}

export function createAuthenticator(pool: pg.Pool, issuer: string, audience: string, jwksUri: URL): Authenticator {
  const jwks = createRemoteJWKSet(jwksUri);
  return {
    async authenticate(authorization) {
      const token = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(authorization ?? '')?.[1];
      if (!token) throw new AuthError('Bearer token required', 401);
      let claims: JWTPayload;
      try {
        ({ payload: claims } = await jwtVerify(token, jwks, { issuer, audience }));
      } catch {
        throw new AuthError('Invalid or expired token', 401);
      }
      if (!claims.sub) throw new AuthError('Token has no subject', 401);
      return loadPrincipal(pool, claims.sub, typeof claims['scope'] === 'string' ? claims['scope'].split(' ') : []);
    },
  };
}

export async function loadPrincipal(pool: pg.Pool, sub: string, scopes: readonly string[]): Promise<Principal> {
  const row = await withScope(pool, 'system', null, async (tx) => (await tx.query<{
    id: string; org_id: string; kind: OrgKind; roles: Role[]; machine_client: boolean;
  }>(`SELECT p.id, p.org_id, o.kind, p.roles, p.machine_client FROM principal p JOIN organisation o ON o.id = p.org_id
      WHERE p.oidc_sub = $1`, [sub])).rows[0]);
  if (!row) throw new AuthError('Not registered with this deployment', 403);
  return { id: row.id, orgId: row.org_id, orgKind: row.kind, roles: row.roles, isMachineClient: row.machine_client, scopes };
}

export function requireRole(p: Principal, ...roles: Role[]): void {
  if (!roles.some((r) => p.roles.includes(r))) throw new AuthError(`Requires role: ${roles.join(' or ')}`, 403);
}
