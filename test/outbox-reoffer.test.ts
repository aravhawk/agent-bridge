import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore, emptyState } from '../src/store.ts';
import { reofferOverdueJobs, reconcileOutbox } from '../src/worker.ts';
import type { EnqueueJob } from '../src/worker.ts';
import type { Job, JobState, StoredMessage } from '../src/types.ts';

interface JobSpec { n: number; kind?: 'ack' | 'wake' | 'batch'; dueAt?: number; state?: JobState; leaseUntil?: number | null }

// Unit tests for the scheduled tick's outbox catch-up (no network, no queue).
const now = Date.UTC(2026, 9, 19, 17), GRACE = 10 * 60000;
const id = (n: number) => 'job_' + n.toString(16).padStart(64, '0');
// kind: 'ack' | 'wake' | 'batch'
function stateWith(jobs: JobSpec[]) {
  const state = emptyState();
  for (const { n, kind = 'batch', dueAt = now - GRACE - 1, state: jobState = 'pending', leaseUntil = null } of jobs) {
    const messageId = `m${n}`;
    state.messages[messageId] = { envelope: { kind: kind === 'ack' ? 'ack' : 'status' }, ...(kind === 'batch' ? { syncBatch: {} } : {}), jobIds: [id(n)] } as unknown as StoredMessage; // Priority reads only kind/syncBatch.
    state.jobs[id(n)] = { id: id(n), messageId, state: jobState, dueAt, leaseUntil, attempts: 0 } as Job;
  }
  return new MemoryStore(state);
}

test('reoffer (repro): a failing job is isolated; the jobs after it are still offered and the failure is counted', async () => {
  const store = stateWith([{ n: 1, kind: 'batch', dueAt: now - 3 * GRACE }, { n: 2, kind: 'ack' }]);
  const offered: string[] = [];
  const out = await reofferOverdueJobs(store, async jobId => { offered.push(jobId); if (jobId === id(2)) throw Error('FAKE_QUEUE_FAULT'); }, now,
    { pendingGraceMs: GRACE });
  assert.deepEqual(offered, [id(2), id(1)], 'the ACK first, and the batch still attempted after the ACK failed');
  assert.deepEqual(out, { scheduled: 1, failed: 1, deferred: 0 });
  // The old helper stopped at the first failure (kept unchanged for its callers).
  const old = [];
  await assert.rejects(reconcileOutbox(stateWith([{ n: 2, kind: 'ack' }, { n: 3, kind: 'ack' }]),
    async jobId => { old.push(jobId); throw Error('FAKE_QUEUE_FAULT'); }, now));
  assert.equal(old.length, 1);
});

test('reoffer (repro): a backlog over the per-run limit rotates; every job is offered, none starved, across overlapping runs', async () => {
  const store = stateWith(Array.from({ length: 101 }, (_, i) => ({ n: i + 1, dueAt: now - GRACE - 1 - i })));
  const seen = new Set(), runs = [];
  for (let run = 0; run < 3; run++) {
    // Jobs stay pending (workers have not finished them), exactly as in an outage.
    const offered: string[] = [];
    const out = await reofferOverdueJobs(store, async jobId => { offered.push(jobId); }, now + run * 1000, { pendingGraceMs: GRACE });
    runs.push(out); offered.forEach(x => seen.add(x));
    if (run === 1) assert.equal(offered[0], id(1), 'the job left out of run 1 goes first in run 2');
  }
  assert.equal(seen.size, 101, 'every overdue job offered');
  assert.deepEqual(runs.map(r => [r.scheduled, r.deferred]), [[100, 1], [100, 1], [100, 1]]);
  // Overlapping runs that read the same snapshot may offer the same jobs (harmless: the
  // worker is idempotent); the rotation still moves on, and the next run takes the rest first.
  const overlap = stateWith(Array.from({ length: 3 }, (_, i) => ({ n: i + 1 })));
  const a: string[] = [], b: string[] = [], c: string[] = [];
  await Promise.all([reofferOverdueJobs(overlap, async x => { a.push(x); }, now, { limit: 2 }),
    reofferOverdueJobs(overlap, async x => { b.push(x); }, now + 1, { limit: 2 })]);
  await reofferOverdueJobs(overlap, async x => { c.push(x); }, now + 2, { limit: 2 });
  assert.equal(c[0], [id(1), id(2), id(3)].find(x => !a.includes(x) && !b.includes(x)) ?? c[0]);
  assert.equal(new Set([...a, ...b, ...c]).size, 3, 'no job starved by overlapping runs');
});

test('reoffer: within a round ACKs, then direct messages, then batch deliveries; never-offered jobs before re-offered ones', async () => {
  const store = stateWith([{ n: 1, kind: 'batch', dueAt: now - 5 * GRACE }, { n: 2, kind: 'wake', dueAt: now - 2 * GRACE },
    { n: 3, kind: 'ack', dueAt: now - GRACE - 1 }, { n: 4, kind: 'batch', dueAt: now - 4 * GRACE }]);
  const first: string[] = [];
  await reofferOverdueJobs(store, async x => { first.push(x); }, now, { pendingGraceMs: GRACE, limit: 2 });
  assert.deepEqual(first, [id(3), id(2)], 'within a round: ACK, then WAKE, before older batches');
  const second: string[] = [];
  await reofferOverdueJobs(store, async x => { second.push(x); }, now + 1000, { pendingGraceMs: GRACE, limit: 2 });
  assert.deepEqual(second, [id(1), id(4)], 'then the batches, oldest first');
  // Rotation precedes priority: an ACK already offered in this round waits behind batches not yet offered.
  const third: string[] = [];
  await reofferOverdueJobs(store, async x => { third.push(x); }, now + 2000, { pendingGraceMs: GRACE, limit: 2 });
  assert.deepEqual(third, [id(3), id(2)], 'the next round starts again with the least recently offered');
  assert.ok(Object.values(store.snapshot().jobs).every(job => Number.isSafeInteger(job.reofferedAt)), 'rotation is durable');
});

test('reoffer: publication grace applies to pending jobs only; an expired lease is re-offered at once; finished jobs never', async () => {
  const store = stateWith([
    { n: 1, dueAt: now - GRACE + 1000 }, // pending, inside the grace: left to its own dispatch
    { n: 2, state: 'leased', dueAt: now - 1000, leaseUntil: now - 1 }, // lease expired just now
    { n: 3, state: 'leased', dueAt: now - 1000, leaseUntil: now + 30000 }, // live lease
    { n: 4, state: 'accepted', dueAt: now - 5 * GRACE }, { n: 5, state: 'dead', dueAt: now - 5 * GRACE },
  ]);
  const offered: string[] = [];
  const out = await reofferOverdueJobs(store, async x => { offered.push(x); }, now, { pendingGraceMs: GRACE });
  assert.deepEqual(offered, [id(2)]);
  assert.deepEqual(out, { scheduled: 1, failed: 0, deferred: 0 });
  await assert.rejects(reofferOverdueJobs(store, null as unknown as EnqueueJob, now), /queue_configuration_required/);
});
