// Fails unless every requirement R1–R16 (design §3) has all its mapped tests passing in the TAP reports
// given as arguments. Manual entries must point to an existing, signed-off checklist (design §11).
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const map = JSON.parse(readFileSync('test/traceability.json', 'utf8')) as Record<string, string[]>;
const passed = new Set<string>();
for (const file of process.argv.slice(2)) {
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*ok \d+ - (.+?)(?: # .*)?$/.exec(line);
    if (m?.[1]) passed.add(m[1].trim());
  }
}
const rows: string[] = ['| Requirement | Evidence | Status |', '|---|---|---|'];
let failed = 0;
for (let i = 1; i <= 16; i++) {
  const id = `R${i}`;
  const evidence = map[id] ?? [];
  const missing = evidence.filter((e) => e.startsWith('manual:') ? !/Signed off by: \S/.test(existsSync(e.slice(7)) ? readFileSync(e.slice(7), 'utf8') : '') : !passed.has(e));
  if (evidence.length === 0 || missing.length) failed++;
  rows.push(`| ${id} | ${evidence.join('<br>')} | ${evidence.length === 0 ? 'NO EVIDENCE' : missing.length ? `MISSING: ${missing.join('; ')}` : 'pass'} |`);
}
writeFileSync('traceability-matrix.md', rows.join('\n') + '\n');
console.log(rows.join('\n'));
if (failed) { console.error(`\n${failed} requirement(s) without passing evidence`); process.exit(1); }
