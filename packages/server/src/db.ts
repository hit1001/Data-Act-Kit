// Postgres access. Every query runs inside `withScope`, which sets the row-level-security context
// (design §5.3) for that transaction only.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';

export type Scope = 'system' | 'maker' | 'customer' | 'recipient';
export type Tx = pg.PoolClient;

export function createPool(databaseUrl: string): pg.Pool {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 20 });
  pool.on('error', (err) => console.error('[db] idle client error', err.message));
  return pool;
}

export async function withScope<T>(pool: pg.Pool, scope: Scope, orgId: string | null, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const tx = await pool.connect();
  try {
    await tx.query('BEGIN');
    await tx.query("SELECT set_config('app.scope', $1, true), set_config('app.org_id', $2, true)", [scope, orgId ?? '']);
    const result = await fn(tx);
    await tx.query('COMMIT');
    return result;
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    tx.release();
  }
}

const MIGRATIONS_DIR = join(import.meta.dirname, '..', 'migrations');

/** Applies pending migrations in file-name order, each in its own transaction, under an advisory lock. */
export async function migrate(pool: pg.Pool): Promise<string[]> {
  const c = await pool.connect();
  try {
    await c.query('SELECT pg_advisory_lock(727272)');
    await c.query('CREATE TABLE IF NOT EXISTS schema_migration (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
    const done = new Set((await c.query<{ name: string }>('SELECT name FROM schema_migration')).rows.map((r) => r.name));
    const applied: string[] = [];
    for (const name of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort()) {
      if (done.has(name)) continue;
      await c.query('BEGIN');
      try {
        await c.query(readFileSync(join(MIGRATIONS_DIR, name), 'utf8'));
        await c.query('INSERT INTO schema_migration (name) VALUES ($1)', [name]);
        await c.query('COMMIT');
        applied.push(name);
      } catch (err) {
        await c.query('ROLLBACK');
        throw new Error(`Migration ${name} failed: ${(err as Error).message}`);
      }
    }
    return applied;
  } finally {
    await c.query('SELECT pg_advisory_unlock(727272)').catch(() => undefined);
    c.release();
  }
}
