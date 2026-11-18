import { bootstrap } from '../bootstrap.ts';
import { loadConfig } from '../config.ts';
import { createPool } from '../db.ts';
import type { EnterpriseSize } from '@dak/core';

const need = (k: string): string => { const v = process.env[k]?.trim(); if (!v) throw new Error(`${k} is required`); return v; };
const size = need('MAKER_SIZE') as EnterpriseSize;
if (!['micro', 'small', 'medium', 'large'].includes(size)) throw new Error('MAKER_SIZE must be micro, small, medium or large');
const pool = createPool(loadConfig().databaseUrl);
const r = await bootstrap(pool, { makerName: need('MAKER_NAME'), size, mediumSince: process.env['MAKER_MEDIUM_SINCE'] ?? null, adminOidcSub: need('ADMIN_OIDC_SUB') });
console.log(`Maker organisation ${r.makerOrgId}; administrator principal ${r.adminPrincipalId}`);
await pool.end();
