import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableQueue } from '../src/queue.ts';

const r = (v: number) => ({ datapointId: 'temp', ts: new Date(0).toISOString(), value: v });

test('batches survive restarts and are delivered in order until acknowledged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dak-q-'));
  const q = new DurableQueue(dir, 'dev-1', 7);
  assert.equal(q.append([r(1)]), 0);
  assert.equal(q.append([r(2)]), 1);
  const reopened = new DurableQueue(dir, 'dev-1', 7);
  assert.deepEqual(reopened.peek(), { deviceId: 'dev-1', seq: 0, readings: [r(1)] });
  reopened.ack(0);
  const again = new DurableQueue(dir, 'dev-1', 7);
  assert.equal(again.peek()?.seq, 1);
  assert.equal(again.append([r(3)]), 2, 'sequence numbers continue after a restart');
  again.ack(2);
  assert.equal(again.peek(), null);
  assert.equal(again.pending, 0);
});

test('acknowledged segments are removed; the newest is kept', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dak-q-'));
  const q = new DurableQueue(dir, 'dev-1', 7);
  const big = Array.from({ length: 20_000 }, (_, i) => r(i));
  for (let i = 0; i < 40; i++) q.append(big);
  const before = readdirSync(dir).filter((f) => f.startsWith('seg-')).length;
  assert.ok(before > 1);
  q.ack(39);
  assert.equal(readdirSync(dir).filter((f) => f.startsWith('seg-')).length, 1);
});
