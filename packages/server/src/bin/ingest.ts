import { boot, runIngest } from '../runtime.ts';

const rt = boot();
const client = await runIngest(rt);
console.log('[ingest] running');
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => { client.end(); void rt.pool.end(); });
