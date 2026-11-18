import { boot, runWorker } from '../runtime.ts';

const rt = boot();
const worker = await runWorker(rt);
console.log('[worker] running');
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => { worker.stop(); void rt.pool.end(); });
