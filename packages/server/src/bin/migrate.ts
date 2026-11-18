import { loadConfig } from '../config.ts';
import { createPool, migrate } from '../db.ts';

const pool = createPool(loadConfig().databaseUrl);
const applied = await migrate(pool);
console.log(applied.length ? `Applied: ${applied.join(', ')}` : 'Database is up to date');
await pool.end();
