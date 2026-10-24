import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { TaskKernel } from '../src/tasks.mjs';
import { TaskRetention } from '../src/task-retention.mjs';
import { MemoryStore } from '../src/store.mjs';

// Synthetic data and tiny fixture-only durations, never production settings.
const start = Date.UTC(2026, 9, 24), ownerKey = 'a'.repeat(64), otherOwner = 'b'.repeat(64);
const actor = { ownerKey, role: 'jarvis' }, peer = { ownerKey, role: 'friday' };
const settings = { terminalMs: 10, tombstoneMs: 40, creationWindowMs: 20, batchSize: 100, maxTombstones: 10 };
const code = expected => error => error.code === expected;
function timedId(now) {
  const stamp = now.toString(16).padStart(12, '0'), random = randomUUID();
  return `${stamp.slice(0, 8)}-${stamp.slice(8)}-7${random.slice(15, 18)}-${random.slice(19)}`;
}
function fixture({ retention = settings, limits } = {}) {
  let now = start, store = new MemoryStore(), kernel;
  const parts = () => ({ store, clock: () => now, leaseMs: 100,
    authorize: p => ({ dataAllowed: true, ownerKey: p.ownerKey, role: p.role, coordinate: p.role === 'jarvis' }), retention, limits });
  const reset = () => { kernel = new TaskKernel(parts()); }; reset();
  const create = (extra = {}) => ({ operation: 'create', taskId: timedId(now), commandId: randomUUID(), sequence: 1,
    assignee: 'friday', description: 'Synthetic retained evidence.', deadline: now + 100000, ...extra });
  const update = (taskId, role, operation, extra = {}) => {
    const task = store.snapshot().collaboration.tasks[taskId];
    return { operation, taskId, commandId: randomUUID(), sequence: (task.commands[role]?.through || 0) + 1,
      expectedRevision: task.revision, ...extra };
  };
  return { create, update, parts, get kernel() { return kernel; }, get store() { return store; },
    now: () => now, advance: ms => { now += ms; }, restart() { store = new MemoryStore(store.snapshot()); reset(); },
    apply: (p, command) => kernel.apply(p, command),
    sweep: (owner = ownerKey) => store.transaction(state => kernel.retention.run(state, now, owner)),
  };
}

test('retention requires explicit complete settings; disabled kernel preserves legacy UUID behavior', async () => {
  for (const invalid of [{}, { ...settings, terminalMs: 0 }, { ...settings, creationWindowMs: 300001 },
    { ...settings, batchSize: 101 }, { ...settings, maxTombstones: 1001 }])
    assert.throws(() => new TaskRetention(invalid), code('task_retention_configuration_required'));
  const f = fixture();
  const disabled = new TaskKernel({ ...f.parts(), retention: undefined });
  const command = f.create({ taskId: randomUUID() }); await disabled.apply(actor, command);
  assert.equal(f.store.snapshot().collaboration.taskIdentity, undefined);
  assert.equal(f.store.snapshot().collaboration.retiredTasks, undefined);
});

test('all explicit terminal phases compact only after evidence age and UUID creation window', async () => {
  for (const phase of ['succeeded', 'failed', 'cancelled', 'expired']) {
    const f = fixture(), create = f.create({ deadline: phase === 'expired' ? start + 1 : start + 100000 });
    await f.apply(actor, create);
    if (phase === 'cancelled') await f.apply(actor, f.update(create.taskId, 'jarvis', 'cancel'));
    else if (phase === 'expired') { f.advance(1); await f.kernel.get(actor, create.taskId); }
    else {
      const attempt = await f.apply(peer, f.update(create.taskId, 'friday', 'claim'));
      await f.apply(peer, f.update(create.taskId, 'friday', 'finish', {
        attemptId: attempt.attemptId, epoch: attempt.epoch, outcome: phase, result: 'Reported evidence.' }));
    }
    f.advance(10); assert.equal((await f.sweep()).tasks, 0, 'ID admission window still open');
    f.advance(11); assert.equal((await f.sweep()).tasks, 1);
    const data = f.store.snapshot().collaboration, tomb = data.retiredTasks[create.taskId];
    assert.equal(data.tasks[create.taskId], undefined); assert.equal(tomb.phase, phase);
    assert.equal(tomb.ownerKey, ownerKey); assert.equal(tomb.until, f.now() + settings.tombstoneMs);
    assert.deepEqual(Object.keys(tomb).sort(), ['epoch', 'ownerKey', 'phase', 'retiredAt', 'revision', 'until']);
    await assert.rejects(f.kernel.get(actor, create.taskId), code('task_retired'));
    await assert.rejects(f.kernel.get({ ...actor, ownerKey: otherOwner }, create.taskId), code('task_not_found'));
    await assert.rejects(f.apply(actor, create), code('task_retired'));
  }
});

test('queued, running and blocked tasks survive cleanup even when their deadlines are overdue and unread', async () => {
  for (const phase of ['queued', 'running', 'blocked']) {
    const f = fixture(), command = f.create({ deadline: start + 50 }); await f.apply(actor, command);
    if (phase !== 'queued') {
      const attempt = await f.apply(peer, f.update(command.taskId, 'friday', 'claim'));
      if (phase === 'blocked') await f.apply(peer, f.update(command.taskId, 'friday', 'block', {
        attemptId: attempt.attemptId, epoch: attempt.epoch, reason: 'outcome_unknown' }));
    }
    f.advance(1000);
    await f.sweep();
    assert.equal(f.store.snapshot().collaboration.tasks[command.taskId].phase, phase);
    assert.deepEqual(f.store.snapshot().collaboration.retiredTasks, {});
    assert.equal((await f.kernel.get(actor, command.taskId)).phase, 'expired');
    assert.equal((await f.sweep()).tasks, 0, 'observed expiry gets a full evidence interval');
    f.advance(settings.terminalMs); assert.equal((await f.sweep()).tasks, 1);
  }
});

test('every retained notice link pins terminal content; expired metadata is removed before the record', async () => {
  const f = fixture(), command = f.create(), first = randomUUID(), second = randomUUID();
  await f.apply(actor, command); await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel'));
  await f.store.transaction(state => { state.collaboration.noticeLinks = {
    [first]: { ownerKey, taskId: command.taskId, until: start + 30 },
    [second]: { ownerKey, taskId: command.taskId, until: start + 40 },
  }; });
  f.advance(30); assert.deepEqual(await f.sweep(), { links: 1, tombstones: 0, tasks: 0 });
  assert.ok(f.store.snapshot().collaboration.tasks[command.taskId]);
  f.advance(10); assert.deepEqual(await f.sweep(), { links: 1, tombstones: 0, tasks: 1 });
  assert.deepEqual(f.store.snapshot().collaboration.noticeLinks, {});
});

test('expired tombstones can be removed without admitting an original or modified old task ID', async () => {
  const f = fixture(), command = f.create(); await f.apply(actor, command);
  const cancel = f.update(command.taskId, 'jarvis', 'cancel'); await f.apply(actor, cancel);
  f.advance(21); await f.sweep(); f.advance(settings.tombstoneMs); await f.sweep(); f.restart();
  assert.deepEqual(f.store.snapshot().collaboration.retiredTasks, {});
  await assert.rejects(f.apply(actor, command), code('task_id_outside_creation_window'));
  await assert.rejects(f.apply(actor, { ...command, commandId: randomUUID(), deadline: f.now() + 100000 }),
    code('task_id_outside_creation_window'));
  await assert.rejects(f.apply(actor, cancel), code('task_command_sequence_conflict'));
  await f.apply(actor, f.create());
  assert.equal(Object.keys(f.store.snapshot().collaboration.tasks).length, 1);
});

test('legacy IDs compact to permanent bounded fences and new legacy IDs cannot enter after opt-in', async () => {
  const f = fixture(), legacy = new TaskKernel({ ...f.parts(), retention: undefined });
  const command = f.create({ taskId: randomUUID() }); await legacy.apply(actor, command);
  await legacy.apply(actor, f.update(command.taskId, 'jarvis', 'cancel'));
  f.advance(21); await f.sweep();
  assert.equal(f.store.snapshot().collaboration.retiredTasks[command.taskId].until, null);
  f.advance(1000000000); await f.sweep();
  await assert.rejects(f.apply(actor, { ...command, deadline: f.now() + 100000 }), code('task_retired'));
  await assert.rejects(f.apply(actor, f.create({ taskId: randomUUID() })), code('task_id_outside_creation_window'));
  const noGc = new TaskKernel({ ...f.parts(), retention: undefined });
  await assert.rejects(noGc.apply(actor, f.create({ taskId: randomUUID() })), code('task_id_outside_creation_window'));
  await assert.rejects(noGc.apply(actor, command), code('task_retired'));
  await noGc.apply(actor, f.create());
});

test('full tombstone capacity defers compaction rather than deleting identity or terminal evidence', async () => {
  const f = fixture({ retention: { ...settings, maxTombstones: 1 } });
  const a = f.create(), b = f.create();
  for (const command of [a, b]) { await f.apply(actor, command); await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel')); }
  f.advance(21); assert.equal((await f.sweep()).tasks, 1);
  assert.equal(Object.keys(f.store.snapshot().collaboration.tasks).length, 1);
  const retained = Object.values(f.store.snapshot().collaboration.tasks)[0];
  assert.equal(retained.phase, 'cancelled'); assert.equal(retained.description, 'Synthetic retained evidence.');
  f.advance(settings.tombstoneMs); assert.deepEqual(await f.sweep(), { links: 0, tombstones: 1, tasks: 1 });
});

test('cleanup mutation batches are bounded and do not touch another owner or any v1 state', async () => {
  const f = fixture({ retention: { ...settings, batchSize: 1 } }), a = f.create(), b = f.create();
  for (const command of [a, b]) { await f.apply(actor, command); await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel')); }
  await f.store.transaction(state => {
    state.collaboration.tasks.foreign = { ...structuredClone(state.collaboration.tasks[a.taskId]), ownerKey: otherOwner };
    state.collaboration.noticeLinks = {
      one: { taskId: a.taskId, ownerKey, until: start + 1 }, two: { taskId: b.taskId, ownerKey, until: start + 1 },
      foreign: { taskId: 'foreign', ownerKey: otherOwner, until: start + 1 },
    };
    state.messages.fixture = { envelope: { kind: 'probe' } }; state.receipts.fixture = { state: 'complete' };
  });
  const before = f.store.snapshot(); f.advance(21);
  for (let i = 0; i < 4; i++) assert.equal(Object.values(await f.sweep()).reduce((a, b) => a + b), 1);
  assert.deepEqual(await f.sweep(), { links: 0, tombstones: 0, tasks: 0 });
  const after = f.store.snapshot();
  assert.deepEqual(after.collaboration.tasks.foreign, before.collaboration.tasks.foreign);
  assert.deepEqual(after.collaboration.noticeLinks.foreign, before.collaboration.noticeLinks.foreign);
  for (const key of ['messages', 'receipts', 'jobs', 'subscriptions']) assert.deepEqual(after[key], before[key]);
});

test('cleanup rolls back before commit and lost commit replies do not renew tombstone retention', async () => {
  const f = fixture(), command = f.create(); await f.apply(actor, command);
  await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel')); f.advance(21);
  const before = f.store.snapshot();
  await assert.rejects(f.store.transaction(state => {
    f.kernel.retention.run(state, f.now(), ownerKey); throw Error('FIXTURE_BEFORE_CLEANUP_COMMIT');
  }), /FIXTURE_BEFORE_CLEANUP_COMMIT/);
  assert.deepEqual(f.store.snapshot(), before);
  await assert.rejects((async () => { await f.sweep(); throw Error('FIXTURE_CLEANUP_REPLY_LOST'); })(), /FIXTURE_CLEANUP_REPLY_LOST/);
  const tomb = f.store.snapshot().collaboration.retiredTasks[command.taskId];
  f.advance(1); f.restart(); await f.sweep();
  assert.deepEqual(f.store.snapshot().collaboration.retiredTasks[command.taskId], tomb);
});

test('lazy admission reuses finite record capacity through repeated complete/compact/expire cycles', async () => {
  const f = fixture({ retention: { terminalMs: 1, tombstoneMs: 3, creationWindowMs: 1, maxTombstones: 2, batchSize: 100 },
    limits: { tasks: 1 } });
  const original = f.create(); let current = original; await f.apply(actor, current);
  for (let i = 0; i < 30; i++) {
    await f.apply(actor, f.update(current.taskId, 'jarvis', 'cancel')); f.advance(2);
    current = f.create(); await f.apply(actor, current);
    const data = f.store.snapshot().collaboration;
    assert.equal(Object.keys(data.tasks).length, 1); assert.ok(Object.keys(data.retiredTasks).length <= 2);
  }
  await assert.rejects(f.apply(actor, original), code('task_id_outside_creation_window'));
});

test('durable clock fence prevents identity reuse after tombstone expiry followed by clock rollback', async () => {
  const f = fixture(), command = f.create(); await f.apply(actor, command);
  await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel'));
  f.advance(21); await f.sweep(); f.advance(settings.tombstoneMs); await f.sweep();
  const before = f.store.snapshot(); f.advance(start - f.now()); f.restart();
  await assert.rejects(f.apply(actor, command), code('task_retention_clock_regressed'));
  const noGc = new TaskKernel({ ...f.parts(), retention: undefined });
  await assert.rejects(noGc.apply(actor, command), code('task_retention_clock_regressed'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('clock rollback cannot normalize an overdue active task with a backdated terminal evidence timestamp', async () => {
  const f = fixture(), command = f.create({ deadline: start + 50 }); await f.apply(actor, command);
  f.advance(1000); await f.sweep(); const before = f.store.snapshot();
  f.advance(-940);
  await assert.rejects(f.kernel.get(actor, command.taskId), code('task_retention_clock_regressed'));
  assert.deepEqual(f.store.snapshot(), before);
  f.advance(940); assert.equal((await f.kernel.get(actor, command.taskId)).phase, 'expired');
  assert.equal((await f.sweep()).tasks, 0, 'full evidence interval starts at the observed terminal transition');
});

test('incompatible persisted identity policy and deadline overflow fail without partial cleanup', async () => {
  const f = fixture(), command = f.create(); await f.apply(actor, command);
  await f.apply(actor, f.update(command.taskId, 'jarvis', 'cancel')); f.advance(21);
  const before = f.store.snapshot();
  const mismatched = new TaskKernel({ ...f.parts(), retention: { ...settings, creationWindowMs: 10 } });
  await assert.rejects(mismatched.apply(actor, f.create()), code('task_retention_configuration_required'));
  await assert.rejects(f.store.transaction(state => new TaskRetention({ ...settings, tombstoneMs: Number.MAX_SAFE_INTEGER })
    .run(state, f.now(), ownerKey)), code('task_retention_configuration_required'));
  assert.deepEqual(f.store.snapshot(), before);
});
