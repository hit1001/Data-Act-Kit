// Durable store-and-forward queue (design §5.1). Batches are appended as JSON lines to segment files;
// a cursor file records the last sequence number the broker acknowledged. Nothing is deleted before it
// is acknowledged, except batches older than the configured maximum age, which are dropped with a warning.
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EdgeBatch, ReadingInput } from '@dak/core';

interface Stored { readonly seq: number; readonly at: number; readonly readings: readonly ReadingInput[] }

const SEGMENT_BYTES = 8 * 1024 * 1024;

export class DurableQueue {
  private nextSeq: number;
  private acked: number;
  private readonly dir: string;
  private readonly deviceId: string;
  private readonly maxAgeMs: number;

  constructor(dir: string, deviceId: string, maxAgeDays: number) {
    if (!(maxAgeDays > 0)) throw new RangeError('maxAgeDays must be positive');
    this.dir = dir; this.deviceId = deviceId; this.maxAgeMs = maxAgeDays * 86_400_000;
    mkdirSync(dir, { recursive: true });
    const cursor = join(dir, 'acked');
    this.acked = existsSync(cursor) ? Number(readFileSync(cursor, 'utf8')) : -1;
    const last = this.all().at(-1);
    this.nextSeq = Math.max(this.acked, last?.seq ?? -1) + 1;
  }

  private segments(): string[] {
    return readdirSync(this.dir).filter((f) => /^seg-\d{12}\.jsonl$/.test(f)).sort();
  }

  private all(): Stored[] {
    const out: Stored[] = [];
    for (const f of this.segments()) {
      for (const line of readFileSync(join(this.dir, f), 'utf8').split('\n')) {
        if (!line) continue;
        try { out.push(JSON.parse(line) as Stored); } catch { /* torn last line after a crash: ignore */ }
      }
    }
    return out;
  }

  append(readings: readonly ReadingInput[]): number {
    if (readings.length === 0) return -1;
    const seq = this.nextSeq++;
    const segs = this.segments();
    let file = segs.at(-1);
    if (!file || statSync(join(this.dir, file)).size > SEGMENT_BYTES) file = `seg-${String(seq).padStart(12, '0')}.jsonl`;
    appendFileSync(join(this.dir, file), JSON.stringify({ seq, at: Date.now(), readings } satisfies Stored) + '\n');
    return seq;
  }

  /** Oldest unacknowledged batch, after dropping batches older than the maximum age. */
  peek(): EdgeBatch | null {
    const cutoff = Date.now() - this.maxAgeMs;
    for (const s of this.all()) {
      if (s.seq <= this.acked) continue;
      if (s.at < cutoff) { console.warn(`[edge] dropping batch ${s.seq}: older than the queue's maximum age`); this.ack(s.seq); continue; }
      return { deviceId: this.deviceId, seq: s.seq, readings: s.readings };
    }
    return null;
  }

  ack(seq: number): void {
    if (seq <= this.acked) return;
    this.acked = seq;
    const tmp = join(this.dir, 'acked.tmp');
    writeFileSync(tmp, String(seq));
    renameSync(tmp, join(this.dir, 'acked'));
    // Remove segments whose every batch is acknowledged (a segment's name is its first sequence number).
    const segs = this.segments();
    for (let i = 0; i < segs.length - 1; i++) {
      const nextFirst = Number(segs[i + 1]!.slice(4, 16));
      if (nextFirst - 1 <= this.acked) rmSync(join(this.dir, segs[i]!));
    }
  }

  get pending(): number { return Math.max(0, this.nextSeq - 1 - this.acked); }
}
