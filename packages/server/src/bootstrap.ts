// First-run setup: the maker organisation and its first administrator. Everything after that is done
// through the API by that administrator.
import type pg from 'pg';
import type { EnterpriseSize } from '@dak/core';
import { withScope } from './db.ts';

export interface BootstrapInput {
  readonly makerName: string;
  readonly size: EnterpriseSize;
  readonly mediumSince: string | null;
  readonly adminOidcSub: string;
}

export async function bootstrap(pool: pg.Pool, b: BootstrapInput): Promise<{ makerOrgId: string; adminPrincipalId: string }> {
  if (b.size === 'medium' && !b.mediumSince) throw new Error('mediumSince is required for a medium-sized maker (Art. 7(1))');
  return withScope(pool, 'system', null, async (tx) => {
    const existing = await tx.query("SELECT 1 FROM organisation WHERE kind='maker'");
    if (existing.rowCount) throw new Error('Already bootstrapped: a maker organisation exists');
    const makerOrgId = (await tx.query<{ id: string }>(
      "INSERT INTO organisation (name, kind, size, medium_since, verified_at) VALUES ($1,'maker',$2,$3,now()) RETURNING id::text",
      [b.makerName, b.size, b.mediumSince])).rows[0]!.id;
    const adminPrincipalId = (await tx.query<{ id: string }>(
      "INSERT INTO principal (org_id, oidc_sub, roles) VALUES ($1,$2,ARRAY['maker_admin']) RETURNING id::text",
      [makerOrgId, b.adminOidcSub])).rows[0]!.id;
    return { makerOrgId, adminPrincipalId };
  });
}

export async function pruneAccessLog(pool: pg.Pool, retentionDays: number): Promise<number> {
  return withScope(pool, 'system', null, async (tx) =>
    (await tx.query('DELETE FROM access_log WHERE ts < now() - make_interval(days => $1)', [retentionDays])).rowCount ?? 0);
}
