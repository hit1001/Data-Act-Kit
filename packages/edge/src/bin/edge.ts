import { readFileSync } from 'node:fs';
import { parseEdgeConfig, runEdge } from '../index.ts';

const file = process.env['EDGE_CONFIG'];
if (!file) throw new Error('EDGE_CONFIG (path to the edge JSON config) is required');
const stop = await runEdge(parseEdgeConfig(JSON.parse(readFileSync(file, 'utf8'))));
console.log('[edge] running');
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => { void stop(); });
