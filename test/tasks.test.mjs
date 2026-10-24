import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { TaskKernel } from '../src/tasks.mjs';
import { MemoryStore, emptyState } from '../src/store.mjs';
import { retainMessages, CONTENT_RETENTION_MS } from '../src/messages.mjs';

// All data-access decisions below are deliberately fake fixtures. They do
// not prove native owner approval or supply the absent production adapter.
const start = Date.UTC(2026, 9, 24), hour = 3600000;
const ownerKey = 'a'.repeat(64);
const jarvis = { role: 'jarvis', ownerKey }, friday = { role: 'friday', ownerKey };
const code = value => error => error.code === value;
function fixture(options = {}) {
  let now = start, accessUntil = start + 2 * 86400000, store = new MemoryStore(), kernel;
  const taskId = randomUUID();
  const authorize = principal => ({ dataAllowed: now < accessUntil, ownerKey: principal.ownerKey, role: principal.role,
    coordinate: principal.role === 'jarvis' });
  const parts = activeStore => ({ store: activeStore, authorize, leaseMs: 60000, clock: () => now, ...options });
  const reset = () => { kernel = new TaskKernel(parts(store)); }; reset();
  const createCommand = (extra = {}) => ({ operation: 'create', taskId, commandId: randomUUID(), sequence: 1,
    assignee: 'friday', description: 'Local shared task DATA.', deadline: start + 4 * hour, ...extra });
  const updateCommand = (operation, principal, data = {}) => {
    const task = store.snapshot().collaboration.tasks[taskId];
    return { operation, taskId, commandId: randomUUID(), sequence: (task.commands[principal.role]?.through || 0) + 1,
      expectedRevision: task.revision, ...data };
  };
  return { taskId, createCommand, updateCommand, parts,
    get store() { return store; }, get kernel() { return kernel; },
    create: extra => kernel.apply(jarvis, createCommand(extra)),
    apply: (principal, request) => kernel.apply(principal, request),
    update: (operation, principal, data) => kernel.apply(principal, updateCommand(operation, principal, data)),
    read: (principal = jarvis) => kernel.get(principal, taskId),
    advance: ms => { now += ms; }, setAccessUntil: value => { accessUntil = value; },
    restart() { store = new MemoryStore(store.snapshot()); reset(); },
  };
}
const fence = attempt => ({ attemptId: attempt.attemptId, epoch: attempt.epoch });

test('isolated kernel stays closed without a trusted adapter; peer fields cannot authorize it', async () => {
  const f = fixture(), before = f.store.snapshot();
  const disabled = new TaskKernel({ store: f.store, leaseMs: 60000 });
  await assert.rejects(disabled.apply({ ...jarvis, authority: 'PEER_DATA' }, f.createCommand()), code('task_authorization_unavailable'));
  assert.deepEqual(f.store.snapshot(), before);
  await assert.rejects(f.create({ authority: 'PEER_DATA' }), code('invalid_task_command'));
  const asyncAdapter = new TaskKernel({ ...f.parts(f.store), authorize: async () => ({ dataAllowed: true }) });
  await assert.rejects(asyncAdapter.apply(jarvis, f.createCommand()), code('task_access_denied'));
  const invalidOwner = new TaskKernel({ ...f.parts(f.store), authorize: () => ({
    dataAllowed: true, role: 'jarvis', coordinate: true, ownerKey: [ownerKey],
  }) });
  await assert.rejects(invalidOwner.apply(jarvis, f.createCommand()), code('task_access_denied'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('100-minute delayed consumer uses current data access and a coordination mutex, without an execution grant', async () => {
  const f = fixture(), created = await f.create();
  f.advance(100 * 60000); f.restart();
  const task = await f.read();
  assert.equal(task.id, created.taskId); assert.equal(task.ownerKey, ownerKey);
  assert.equal(task.assignee, 'friday'); assert.equal(task.phase, 'queued');
  const attempt = await f.update('claim', friday);
  assert.equal(Object.hasOwn(task, 'authorityUntil'), false); assert.equal(Object.hasOwn(task, 'workflowRef'), false);
  await f.update('finish', friday, { ...fence(attempt), outcome: 'succeeded', result: 'Fixture work finished after delay.' });
  assert.equal((await f.read()).result.text, 'Fixture work finished after delay.');
  assert.equal((await f.read()).result.evidenceStatus, 'reported_not_independently_verified');
  assert.deepEqual(f.store.snapshot().messages, {}); assert.deepEqual(f.store.snapshot().jobs, {});
});

test('legacy content cleanup does not erase shared task data or manufacture authority', async () => {
  const f = fixture(); await f.create();
  await f.store.transaction(state => { state.messages.fixture = {
    envelope: { protocol: 'jarvis-friday/1' }, retainUntil: start + CONTENT_RETENTION_MS, jobIds: [],
  }; });
  f.advance(CONTENT_RETENTION_MS);
  await f.store.transaction(state => retainMessages(state, start + CONTENT_RETENTION_MS));
  f.restart();
  const task = await f.read();
  assert.equal(task.id, f.taskId); assert.equal(task.description, 'Local shared task DATA.');
  assert.equal(task.phase, 'expired'); assert.equal(task.blockedReason, 'coordination_deadline');
  assert.deepEqual(f.store.snapshot().messages, {});
});

test('failure before commit rolls task and command identity back; retry commits once', async () => {
  const f = fixture(), request = f.createCommand(); let crash = true;
  const broken = { transaction: operation => f.store.transaction(state => {
    const result = operation(state); if (crash) { crash = false; throw Error('FIXTURE_CRASH_BEFORE_COMMIT'); } return result;
  }) };
  const kernel = new TaskKernel(f.parts(broken));
  await assert.rejects(kernel.apply(jarvis, request), /FIXTURE_CRASH_BEFORE_COMMIT/);
  assert.equal(f.store.snapshot().collaboration, undefined);
  const first = await kernel.apply(jarvis, request), replay = await kernel.apply(jarvis, request);
  assert.deepEqual(replay, first); assert.equal(Object.keys(f.store.snapshot().collaboration.tasks).length, 1);
});

test('lost create/claim replies replay their exact committed results after restart', async () => {
  const f = fixture(), create = f.createCommand();
  const created = await f.apply(jarvis, create); f.restart();
  assert.deepEqual(await f.apply(jarvis, create), created);
  const request = f.updateCommand('claim', friday), claim = await f.apply(friday, request);
  f.advance(1000); f.restart();
  const duplicates = await Promise.all(Array.from({ length: 10 }, () => f.apply(friday, request)));
  for (const duplicate of duplicates) assert.deepEqual(duplicate, claim);
  assert.equal((await f.read()).lease.until, claim.leaseUntil, 'duplicate claim cannot renew a lease');
});

test('crash preserves checkpoint and mutex recovery fences an old report without authorizing external retry', async () => {
  const f = fixture(); await f.create(); const old = await f.update('claim', friday);
  await f.update('progress', friday, { ...fence(old), checkpoint: 'Step one is durably recorded.' });
  f.advance(60001); f.restart();
  let task = await f.read();
  assert.equal(task.phase, 'reconciliation_required'); assert.equal(task.blockedReason, 'lease_lost');
  assert.equal(task.checkpoint.text, 'Step one is durably recorded.');
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  await f.update('assign', jarvis, { assignee: 'friday' });
  const fresh = await f.update('claim', friday);
  assert.notEqual(fresh.attemptId, old.attemptId); assert.ok(fresh.epoch > old.epoch);
  await assert.rejects(f.update('finish', friday, { ...fence(old), outcome: 'succeeded', result: 'Stale result.' }), code('stale_task_attempt'));
  await f.update('finish', friday, { ...fence(fresh), outcome: 'succeeded', result: 'Current result.' });
  task = await f.read(); assert.equal(task.result.text, 'Current result.');
});

test('even reused attempt IDs cannot bypass the independent epoch fence', async () => {
  const fixedId = randomUUID(), f = fixture({ makeAttemptId: () => fixedId });
  await f.create(); const old = await f.update('claim', friday);
  f.advance(60001); await f.read();
  await f.update('assign', jarvis, { assignee: 'friday' });
  const fresh = await f.update('claim', friday);
  assert.equal(fresh.attemptId, old.attemptId); assert.notEqual(fresh.epoch, old.epoch);
  await assert.rejects(f.update('progress', friday, { ...fence(old), checkpoint: 'Old worker.' }), code('stale_task_attempt'));
});

test('owner/assignee isolation and live assignment cannot be overridden by another command', async () => {
  const f = fixture(); await f.create();
  await assert.rejects(f.read({ ...jarvis, ownerKey: 'b'.repeat(64) }), code('task_not_found'));
  await assert.rejects(f.update('claim', jarvis), code('task_assignee_required'));
  await f.update('claim', friday);
  await assert.rejects(f.update('assign', jarvis, { assignee: 'friday' }), code('task_busy'));
  const task = await f.read(); assert.equal(task.assignee, 'friday'); assert.equal(task.phase, 'running');
});

test('concurrent different claims commit one attempt and reject the conflicting command', async () => {
  const f = fixture(); await f.create();
  const a = f.updateCommand('claim', friday), b = f.updateCommand('claim', friday);
  const results = await Promise.allSettled([f.apply(friday, a), f.apply(friday, b)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.filter(r => r.status === 'rejected').length, 1);
  assert.equal((await f.read()).epoch, 1);
});

test('terminal result survives lost response and expiry; changed or new finishes cannot overwrite it', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday);
  const request = f.updateCommand('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Durable result.' });
  const done = await f.apply(friday, request); f.restart(); f.advance(9 * hour);
  assert.deepEqual(await f.apply(friday, request), done);
  await assert.rejects(f.apply(friday, { ...request, result: 'Changed result.' }), code('task_command_conflict'));
  await assert.rejects(f.update('finish', friday, { ...fence(claim), outcome: 'failed', result: 'Different command.' }), code('task_terminal'));
  assert.equal((await f.read()).result.text, 'Durable result.');
});

test('cancellation preserves checkpoint, invalidates mutex and rejects a late reported result', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday);
  await f.update('progress', friday, { ...fence(claim), checkpoint: 'Known work before cancellation.' });
  const request = f.updateCommand('cancel', jarvis), cancelled = await f.apply(jarvis, request);
  f.restart(); assert.deepEqual(await f.apply(jarvis, request), cancelled);
  await assert.rejects(f.update('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Late result.' }), code('task_terminal'));
  const task = await f.read();
  assert.equal(task.phase, 'cancelled'); assert.equal(task.lease, null); assert.equal(task.result, null);
  assert.equal(task.checkpoint.text, 'Known work before cancellation.');
});

test('a coordination deadline persists and fresh access cannot reopen the terminal record', async () => {
  const f = fixture(); await f.create({ deadline: start + 1000 }); const claim = await f.update('claim', friday);
  f.advance(1000); f.restart();
  let task = await f.read(); assert.equal(task.phase, 'expired'); assert.equal(task.blockedReason, 'coordination_deadline');
  await assert.rejects(f.update('assign', jarvis, { assignee: 'friday' }), code('task_terminal'));
  await assert.rejects(f.update('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Too late.' }), code('task_terminal'));
  task = await f.read(); assert.equal(task.deadline, start + 1000); assert.equal(task.phase, 'expired');
});

test('expired request context cannot read, mutate or replay; fresh admitted context does not need a parallel grant', async () => {
  const f = fixture(), create = f.createCommand(); await f.apply(jarvis, create);
  f.setAccessUntil(start + 1000); f.advance(1001);
  const before = f.store.snapshot();
  await assert.rejects(f.read(), code('task_access_denied'));
  await assert.rejects(f.update('claim', friday), code('task_access_denied'));
  await assert.rejects(f.apply(jarvis, create), code('task_access_denied'));
  assert.deepEqual(f.store.snapshot(), before);
  f.setAccessUntil(start + 2 * hour);
  assert.equal((await f.read()).phase, 'queued');
  assert.equal((await f.update('claim', friday)).phase, 'running');
});

test('rejected finish still durably records an elapsed coordination deadline', async () => {
  const f = fixture(); await f.create({ deadline: start + 1000 }); const claim = await f.update('claim', friday);
  const finish = f.updateCommand('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Must not commit.' });
  f.advance(2000);
  await assert.rejects(f.apply(friday, finish));
  const stopped = f.store.snapshot().collaboration.tasks[f.taskId];
  assert.equal(stopped.phase, 'expired'); assert.equal(stopped.deadline, start + 1000);
  assert.equal(stopped.result, null);
  assert.equal(stopped.commands.friday.through, 1, 'rejected command has no committed identity/result');
  f.restart();
  await assert.rejects(f.apply(friday, finish));
  assert.equal((await f.read()).phase, 'expired');
});

test('identity fields must be UUID strings and operation names cannot inherit object methods', async () => {
  const f = fixture();
  for (const field of ['taskId', 'commandId']) {
    const request = f.createCommand(); request[field] = [request[field]];
    await assert.rejects(f.apply(jarvis, request), code('invalid_task_command'));
  }
  for (const operation of ['toString', 'constructor', '__proto__'])
    await assert.rejects(f.apply(jarvis, { operation }), code('invalid_task_command'));
  await f.create(); const claim = await f.update('claim', friday);
  await assert.rejects(f.update('progress', friday, { ...fence(claim), attemptId: [claim.attemptId], checkpoint: 'Invalid identity type.' }),
    code('invalid_task_command'));
  await assert.rejects(f.kernel.get(jarvis, [f.taskId]), code('invalid_task_command'));
});

test('nonfinite clocks cannot return an apparently current task or admit a mutation', async () => {
  const f = fixture(); await f.create(); const before = f.store.snapshot();
  for (const value of [NaN, Infinity]) {
    const kernel = new TaskKernel({ ...f.parts(f.store), clock: () => value });
    await assert.rejects(kernel.get(jarvis, f.taskId), code('task_kernel_configuration_required'));
    await assert.rejects(kernel.apply(friday, f.updateCommand('claim', friday)), code('task_kernel_configuration_required'));
  }
  assert.deepEqual(f.store.snapshot(), before);
});

test('bounded replay cache rejects evicted commands without reapplying them; property order is canonical', async () => {
  const f = fixture({ limits: { replay: 2 } }); await f.create();
  const old = f.updateCommand('claim', friday), claim = await f.apply(friday, old);
  await f.update('progress', friday, { ...fence(claim), checkpoint: 'First checkpoint.' });
  const current = f.updateCommand('progress', friday, { ...fence(claim), checkpoint: 'Latest checkpoint.' });
  const result = await f.apply(friday, current);
  assert.deepEqual(await f.apply(friday, Object.fromEntries(Object.entries(current).reverse())), result);
  const before = f.store.snapshot();
  await assert.rejects(f.apply(friday, old), code('task_command_too_old'));
  assert.deepEqual(f.store.snapshot(), before);
  await f.update('progress', friday, { ...fence(claim), checkpoint: 'Next checkpoint.' });
  const task = f.store.snapshot().collaboration.tasks[f.taskId];
  assert.equal(task.commands.friday.recent.length, 2); assert.equal(task.commands.friday.through, 4);
  assert.equal('commands' in await f.read(), false);
});

test('capacity backpressure rolls back new tasks and progress while reserving terminal capacity', async () => {
  const count = fixture({ limits: { tasks: 1 } }); await count.create();
  const before = count.store.snapshot();
  await assert.rejects(count.create({ taskId: randomUUID() }), code('task_capacity_reached'));
  assert.deepEqual(count.store.snapshot(), before);
  for (const operation of ['finish', 'cancel']) {
    const f = fixture({ limits: { taskBytes: 5200 } }); await f.create(); const claim = await f.update('claim', friday);
    const saved = f.store.snapshot();
    await assert.rejects(f.update('progress', friday, { ...fence(claim), checkpoint: 'x'.repeat(1800) }), code('task_capacity_reached'));
    assert.deepEqual(f.store.snapshot(), saved);
    if (operation === 'finish') await f.update('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'x'.repeat(1800) });
    else await f.update('cancel', jarvis);
    assert.ok(['succeeded', 'cancelled'].includes((await f.read()).phase));
  }
});

test('unknown outcomes require explicit coordinator data reassignment, not an invented execution grant', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday);
  await f.update('block', friday, { ...fence(claim), reason: 'outcome_unknown' }); f.restart();
  assert.equal((await f.read()).blockedReason, 'outcome_unknown');
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  await f.update('assign', jarvis, { assignee: 'friday' });
  assert.equal((await f.update('claim', friday)).phase, 'running');
});

test('v1 queue stays independent of task state and storage preserves additive task data', async () => {
  for (const path of ['queue.mjs'])
    assert.equal(readFileSync(new URL('../src/' + path, import.meta.url), 'utf8').includes('./tasks.mjs'), false);
  assert.deepEqual(Object.keys(emptyState()).sort(), ['jobs', 'messages', 'receipts', 'subscriptions', 'version']);
  const f = fixture(); await f.create(); const snapshot = f.store.snapshot();
  const oldStore = new MemoryStore(snapshot); await oldStore.transaction(state => retainMessages(state, start));
  assert.deepEqual(oldStore.snapshot().collaboration, snapshot.collaboration);
  assert.deepEqual(oldStore.snapshot().jobs, {}); assert.deepEqual(oldStore.snapshot().receipts, {});
});

// The external provider below is synthetic. These tests prove ledger behavior,
// not native launch idempotency, external approval or provider verification.
const observation = (operationId, extra = {}) => ({ operationId, runRef: 'synthetic-run-1', outcome: 'succeeded',
  evidence: 'Synthetic provider fixture queried its existing run and verified its result.', result: 'Existing work finished.', ...extra });

for (const duration of [2 * 60000, 3 * hour]) test(`existing ${duration / 60000}-minute work reconciles after lease loss without relaunch`, async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday), operationId = randomUUID();
  const start = f.updateCommand('start', friday, { ...fence(claim), operationId });
  const intent = await f.apply(friday, start); assert.equal(intent.operationRecorded, true);
  let launches = 0;
  if (intent.operationRecorded) launches++; // A fake already-authorized native launch, no real external call.
  f.advance(45000); await f.update('progress', friday, { ...fence(claim), checkpoint: 'Existing run is still active.' });
  assert.equal((await f.read()).lease.until, claim.leaseUntil, 'progress does not need to keep an external run alive');
  f.advance(duration - 45000); f.restart();
  const saved = await f.read();
  assert.equal(saved.phase, 'reconciliation_required'); assert.equal(saved.externalOperation.id, operationId);
  assert.equal(saved.checkpoint.text, 'Existing run is still active.');
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  await assert.rejects(f.update('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Stale finish.' }), code('stale_task_attempt'));
  const done = await f.update('reconcile', friday, observation(operationId));
  assert.equal(done.phase, 'succeeded'); assert.equal(launches, 1);
  const result = await f.read(); assert.equal(result.result.operationId, operationId);
  assert.equal(result.externalOperation.runRef, 'synthetic-run-1');
  assert.equal(result.result.evidenceStatus, 'reported_not_independently_verified');
  assert.equal((await f.apply(friday, start)).operationRecorded, false, 'historical start replay never asks for another launch');
  assert.equal((await f.read()).phase, 'succeeded');
});

test('lost committed start reply and lost provider launch response stay ambiguous without a second launch', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday), operationId = randomUUID();
  const start = f.updateCommand('start', friday, { ...fence(claim), operationId });
  let loseReply = true;
  const kernel = new TaskKernel(f.parts({ transaction: async fn => {
    const result = await f.store.transaction(fn);
    if (loseReply) { loseReply = false; throw Error('SYNTHETIC_LOST_COMMIT_REPLY'); }
    return result;
  } }));
  await assert.rejects(kernel.apply(friday, start), /SYNTHETIC_LOST_COMMIT_REPLY/); f.restart();
  assert.equal((await f.apply(friday, start)).operationRecorded, false);
  await assert.rejects(f.update('start', friday, { ...fence(claim), operationId: randomUUID() }), code('task_operation_already_recorded'));
  await f.update('reconcile', friday, observation(operationId, { runRef: null, outcome: 'unknown',
    evidence: 'Synthetic provider response was lost; fixture cannot establish whether it started.', result: 'No retry is safe.' }));
  f.advance(60001); f.restart();
  await f.update('assign', jarvis, { assignee: 'friday' });
  assert.equal((await f.read()).phase, 'reconciliation_required');
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  assert.equal((await f.read()).externalOperation.id, operationId);
  assert.equal((await f.read()).externalOperation.runRef, null);
});

test('concurrent starts record once; reassignment fences stale workers and preserves the existing operation', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday), operationId = randomUUID();
  const start = f.updateCommand('start', friday, { ...fence(claim), operationId });
  const replies = await Promise.all([f.apply(friday, start), f.apply(friday, start)]);
  assert.deepEqual(replies.map(r => r.operationRecorded).sort(), [false, true]);
  f.advance(60001); await f.read();
  await f.update('assign', jarvis, { assignee: 'jarvis' });
  await assert.rejects(f.update('reconcile', friday, observation(operationId)), code('task_assignee_required'));
  await assert.rejects(f.update('claim', jarvis), code('task_reconciliation_required'));
  assert.equal((await f.update('reconcile', jarvis, observation(operationId))).phase, 'succeeded');
  assert.equal((await f.read()).externalOperation.id, operationId);
});

test('observing an existing running operation releases the short mutex and cannot rebind run identity or overwrite completion', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday), operationId = randomUUID();
  await f.update('start', friday, { ...fence(claim), operationId });
  await assert.rejects(f.update('finish', friday, { ...fence(claim), outcome: 'succeeded', result: 'Bypass reconciliation.' }),
    code('task_operation_reconciliation_required'));
  await f.update('reconcile', friday, observation(operationId, { outcome: 'running', result: 'Existing run acknowledged.' }));
  assert.equal((await f.read()).lease, null);
  for (const extra of [{ operationId: randomUUID() }, { runRef: 'different-run' }, { runRef: null, outcome: 'unknown' }])
    await assert.rejects(f.update('reconcile', friday, observation(operationId, extra)), code(extra.operationId ? 'task_operation_conflict' : 'task_run_conflict'));
  f.advance(hour); f.restart();
  const finish = f.updateCommand('reconcile', friday, observation(operationId));
  const done = await f.apply(friday, finish);
  f.restart(); assert.deepEqual(await f.apply(friday, finish), done);
  await assert.rejects(f.update('reconcile', friday, observation(operationId, { outcome: 'failed' })), code('task_terminal'));
  assert.equal((await f.read()).phase, 'succeeded');
});

test('cancelled or deadline-expired operations retain their identity and cannot be revived by fresh reconciliation', async () => {
  for (const stop of ['cancelled', 'expired']) {
    const f = fixture(); await f.create({ deadline: start + 120000 });
    const claim = await f.update('claim', friday), operationId = randomUUID();
    const intent = f.updateCommand('start', friday, { ...fence(claim), operationId }); await f.apply(friday, intent);
    if (stop === 'cancelled') await f.update('cancel', jarvis);
    else f.advance(120000);
    assert.equal((await f.read()).phase, stop);
    await assert.rejects(f.update('reconcile', friday, observation(operationId)), code('task_terminal'));
    await assert.rejects(f.update('assign', jarvis, { assignee: 'jarvis' }), code('task_terminal'));
    assert.equal((await f.apply(friday, intent)).operationRecorded, false);
    const task = await f.read(); assert.equal(task.phase, stop); assert.equal(task.result, null);
    assert.equal(task.externalOperation.id, operationId);
  }
});

test('expired access cannot reconcile or replay a start; fresh access reconciles without extending task lifetime', async () => {
  const f = fixture(); await f.create(); const claim = await f.update('claim', friday), operationId = randomUUID();
  const intent = f.updateCommand('start', friday, { ...fence(claim), operationId }); await f.apply(friday, intent);
  f.setAccessUntil(start + 60000); f.advance(120000); const before = f.store.snapshot();
  await assert.rejects(f.update('reconcile', friday, observation(operationId)), code('task_access_denied'));
  await assert.rejects(f.apply(friday, intent), code('task_access_denied')); assert.deepEqual(f.store.snapshot(), before);
  f.setAccessUntil(start + 4 * hour); await f.read();
  await f.update('reconcile', friday, observation(operationId));
  assert.equal((await f.read()).deadline, start + 4 * hour);
});

test('reconciliation validates bounded identity/evidence and retains room for a terminal report', async () => {
  const f = fixture({ limits: { taskBytes: 7500 } }); await f.create();
  const claim = await f.update('claim', friday), operationId = randomUUID();
  await f.update('start', friday, { ...fence(claim), operationId });
  for (const extra of [{ runRef: null }, { runRef: 'x'.repeat(256) }, { evidence: '' }, { operationId: [operationId] }])
    await assert.rejects(f.update('reconcile', friday, observation(operationId, extra)), code('invalid_task_command'));
  await assert.rejects(f.update('progress', friday, { ...fence(claim), checkpoint: 'x'.repeat(2000) }), code('task_capacity_reached'));
  await f.update('reconcile', friday, observation(operationId, { runRef: 'r'.repeat(250), evidence: 'e'.repeat(1000), result: 'x'.repeat(2000) }));
  assert.equal((await f.read()).phase, 'succeeded');
});

test('a prior-prototype blocked/lease_lost snapshot also needs explicit coordinator recovery', async () => {
  const f = fixture(); await f.create(); await f.update('claim', friday);
  await f.store.transaction(state => {
    const task = state.collaboration.tasks[f.taskId];
    task.phase = 'blocked'; task.blockedReason = 'lease_lost'; task.lease = null; task.epoch++; task.revision++;
  });
  f.restart();
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  await f.update('assign', jarvis, { assignee: 'friday' });
  assert.equal((await f.update('claim', friday)).phase, 'running');
});

test('after restart each role recovers its next sequence and only its own known command, without a private journal', async () => {
  for (const coordinator of [jarvis, friday]) {
    const assignee = coordinator === jarvis ? friday : jarvis;
    const f = fixture({ authorize: p => ({ dataAllowed: true, ownerKey, role: p.role, coordinate: true }) });
    const created = f.createCommand({ assignee: assignee.role }); await f.apply(coordinator, created); f.restart();
    const recovered = await f.kernel.get(coordinator, f.taskId, created.commandId);
    assert.equal(recovered.caller.role, coordinator.role); assert.equal(recovered.caller.nextSequence, 2);
    assert.equal(recovered.caller.command.status, 'committed'); assert.equal(recovered.caller.command.sequence, 1);
    const peer = await f.kernel.get(assignee, f.taskId, created.commandId);
    assert.deepEqual(peer.caller, { role: assignee.role, nextSequence: 1,
      command: { commandId: created.commandId, status: 'unknown' } });
    const claimCommand = { operation: 'claim', taskId: f.taskId, commandId: randomUUID(),
      sequence: peer.caller.nextSequence, expectedRevision: peer.revision };
    const claimed = await f.apply(assignee, claimCommand); f.restart();
    const fresh = await f.kernel.get(assignee, f.taskId, claimCommand.commandId);
    assert.equal(fresh.caller.nextSequence, 2); assert.equal(fresh.caller.command.result.attemptId, claimed.attemptId);
    // A subsequent command is constructed only from the public result.
    await f.apply(assignee, { operation: 'progress', taskId: fresh.id, commandId: randomUUID(),
      sequence: fresh.caller.nextSequence, expectedRevision: fresh.revision,
      attemptId: fresh.lease.id, epoch: fresh.epoch, checkpoint: 'Recovered without scratch files.' });
    assert.equal((await f.kernel.get(coordinator, f.taskId)).caller.nextSequence, 2);
    assert.equal((await f.kernel.get(assignee, f.taskId)).caller.nextSequence, 3);
    assert.equal('commands' in fresh, false); assert.equal('hash' in fresh.caller.command, false);
  }
});

test('known-command recovery suppresses launch flags and an evicted receipt remains unknown, not permission to retry work', async () => {
  const f = fixture({ limits: { replay: 2 } }); await f.create(); const claim = await f.update('claim', friday);
  const operationId = randomUUID(), intent = f.updateCommand('start', friday, { ...fence(claim), operationId });
  await f.apply(friday, intent); f.restart();
  assert.equal((await f.kernel.get(friday, f.taskId, intent.commandId)).caller.command.result.operationRecorded, false);
  await f.update('reconcile', friday, observation(operationId, { outcome: 'running' }));
  await f.update('reconcile', friday, observation(operationId, { outcome: 'unknown' })); f.restart();
  const read = await f.kernel.get(friday, f.taskId, intent.commandId);
  assert.deepEqual(read.caller.command, { commandId: intent.commandId, status: 'unknown' });
  assert.equal(read.caller.nextSequence, 5); assert.equal(read.externalOperation.id, operationId);
  await assert.rejects(f.update('claim', friday), code('task_reconciliation_required'));
  await f.apply(friday, { operation: 'reconcile', taskId: f.taskId, commandId: randomUUID(),
    sequence: read.caller.nextSequence, expectedRevision: read.revision, ...observation(operationId) });
  const before = f.store.snapshot();
  for (const commandId of [[intent.commandId], null, 'wrong'])
    await assert.rejects(f.kernel.get(friday, f.taskId, commandId), code('invalid_task_command'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('the same command ID in both role histories resolves only within the authenticated caller history', async () => {
  const f = fixture(), create = f.createCommand(); await f.apply(jarvis, create);
  await f.apply(friday, f.updateCommand('claim', friday, { commandId: create.commandId })); f.restart();
  const a = await f.kernel.get(jarvis, f.taskId, create.commandId), b = await f.kernel.get(friday, f.taskId, create.commandId);
  assert.equal(a.caller.command.result.phase, 'queued'); assert.equal(b.caller.command.result.phase, 'running');
  assert.equal(a.caller.role, 'jarvis'); assert.equal(b.caller.role, 'friday');
});
