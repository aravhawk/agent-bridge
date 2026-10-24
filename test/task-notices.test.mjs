import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { TaskKernel } from '../src/tasks.mjs';
import { TaskNoticeTransactions } from '../src/task-notices.mjs';
import { MemoryStore } from '../src/store.mjs';
import { NativeEvents, appendDeliveryJobs } from '../src/events.mjs';
import { createProtector } from '../src/webhook.mjs';
import { validateMessage, reserveMessage, retainMessages, CONTENT_RETENTION_MS } from '../src/messages.mjs';
import { verifiedMessageAuthorization } from '../src/access.mjs';
import { VERIFIED_AUTHORIZATION, SCOPES, BridgeError } from '../src/policy.mjs';
import { Bridge } from '../src/bridge.mjs';

// Fictional access contexts and v1 principals only. stageNotice is a local
// fixture, not the absent production admission adapter or native approval.
const start = Date.UTC(2026, 9, 24), hour = 3600000, ownerKey = 'a'.repeat(64);
const policyIds = { jarvis: 'c'.repeat(64), friday: 'd'.repeat(64) };
const code = value => error => error.code === value;
async function fixture(options = {}) {
  let now = start, store = new MemoryStore(), kernel, service, crash, hook, staged = 0;
  const clock = () => now, taskId = randomUUID();
  const access = (role, owner = ownerKey) => ({ role, ownerKey: owner, until: now + hour });
  const native = role => Object.defineProperty({ role, scopes: Object.values(SCOPES[role]),
    principalKey: (role === 'jarvis' ? 'a' : 'b').repeat(64) }, VERIFIED_AUTHORIZATION,
  { value: { policyId: policyIds[role], expiresAt: now + 96 * hour } });
  const events = new NativeEvents({ store, clock, protector: createProtector(randomBytes(32)), enabled: true,
    policyId: policyIds.jarvis, transport: async (_url, req) => ({ status: 200,
      body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  await events.subscribe(native('jarvis'), { name: 'bridge.message.received', arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/LOCAL_FIXTURE', secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const stageNotice = (state, principal, notice) => {
    staged++;
    const actor = native(principal.role);
    const { envelope, hash } = validateMessage({ protocol: 'jarvis-friday/1', id: notice.messageId,
      threadId: notice.taskId, from: notice.from, to: notice.to, kind: 'status', route: 'inbox',
      sentAt: new Date(now).toISOString(), expiresAt: new Date(now + hour).toISOString(),
      text: 'Local task-data notice.' }, actor, now);
    const authorization = verifiedMessageAuthorization(actor, envelope, now);
    const retainUntil = reserveMessage(state, envelope, hash, now);
    const jobIds = appendDeliveryJobs(state, envelope, now);
    state.messages[notice.messageId] = { envelope, hash, storedAt: now, jobIds, retainUntil, authorization };
    return hook?.(state, notice);
  };
  const build = () => {
    const wrapped = { transaction: async operation => {
      const mode = crash; crash = undefined;
      const result = await store.transaction(state => {
        const output = operation(state);
        if (mode === 'beforeCommit') throw Error('FIXTURE_BEFORE_COMMIT');
        return output;
      });
      if (mode === 'afterCommit') throw Error('FIXTURE_LOST_COMMIT_RESPONSE');
      return result;
    } };
    kernel = new TaskKernel({ store: wrapped, clock, leaseMs: 60000,
      authorize: context => ({ dataAllowed: context.until > now, ownerKey: context.ownerKey,
        role: context.role, coordinate: context.role === 'jarvis' }), ...options.kernel });
    service = new TaskNoticeTransactions({ kernel, stageNotice, linkRetentionMs: 48 * hour, ...options.links });
  }; build();
  const create = (extra = {}) => ({ operation: 'create', taskId, commandId: randomUUID(), sequence: 1,
    assignee: 'friday', description: 'Durable coordination DATA.', deadline: start + 72 * hour, ...extra });
  const update = (operation, role, data = {}) => {
    const task = store.snapshot().collaboration.tasks[taskId];
    return { operation, taskId, commandId: randomUUID(), sequence: (task.commands[role]?.through || 0) + 1,
      expectedRevision: task.revision, ...data };
  };
  return { taskId, access, native, create, update, clock, get store() { return store; },
    get kernel() { return kernel; }, get service() { return service; }, staged: () => staged,
    crash: mode => { crash = mode; }, hook: fn => { hook = fn; }, advance: ms => { now += ms; },
    restart() { store = new MemoryStore(store.snapshot()); build(); } };
}
const fence = claim => ({ attemptId: claim.attemptId, epoch: claim.epoch });
const notice = () => ({ messageId: randomUUID() });

test('rejected async adapters roll back without unhandled rejection or raw callback output', () => {
  const imports = ['tasks', 'task-notices', 'store'].map(name => new URL(`../src/${name}.mjs`, import.meta.url).href);
  const child = spawnSync(process.execPath, ['--unhandled-rejections=strict', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { randomUUID } from 'node:crypto';
    import { TaskKernel } from ${JSON.stringify(imports[0])};
    import { TaskNoticeTransactions } from ${JSON.stringify(imports[1])};
    import { MemoryStore } from ${JSON.stringify(imports[2])};
    const denied = async () => { throw Error('RAW_FIXTURE_CALLBACK_MUST_NOT_ESCAPE'); };
    const allowed = () => ({ dataAllowed:true, ownerKey:'a'.repeat(64), role:'jarvis', coordinate:true });
    for (const asynchronous of ['admission', 'staging']) {
      const store = new MemoryStore(), before = store.snapshot();
      const kernel = new TaskKernel({ store, leaseMs:10, clock:()=>100,
        authorize:asynchronous==='admission' ? denied : allowed });
      const service = new TaskNoticeTransactions({ kernel, stageNotice:denied, linkRetentionMs:100 });
      const command = { operation:'create', taskId:randomUUID(), commandId:randomUUID(), sequence:1,
        assignee:'friday', description:'Fixture only.', deadline:1000 };
      await assert.rejects(service.apply({}, command, { messageId:randomUUID() }),
        e=>e.code===(asynchronous==='admission' ? 'task_access_denied' : 'task_notice_stage_invalid'));
      assert.deepEqual(store.snapshot(), before);
    }
    await new Promise(resolve=>setImmediate(resolve));
    process.stdout.write('sanitized rollback verified');
  `], { encoding: 'utf8', timeout: 10000 });
  assert.equal(child.error, undefined); assert.equal(child.status, 0, child.stderr);
  assert.equal(child.signal, null); assert.equal(child.stderr, '');
  assert.equal(child.stdout, 'sanitized rollback verified');
});

test('one transaction stores task, unchanged v1 event notice, durable alias and command binding', async () => {
  const f = await fixture(), n = notice();
  const result = await f.service.apply(f.access('jarvis'), f.create(), n);
  const state = f.store.snapshot(), link = state.collaboration.noticeLinks[n.messageId];
  assert.equal(result.noticeMessageId, n.messageId); assert.equal(link.taskId, f.taskId);
  assert.equal(link.recipient, 'friday'); assert.equal(link.revision, result.revision);
  const job = state.jobs[state.messages[n.messageId].jobIds[0]];
  assert.deepEqual(JSON.parse(job.body), { event: 'bridge.message.received', data: { messageId: n.messageId } });
  assert.equal(state.collaboration.tasks[f.taskId].commands.jarvis.recent[0].noticeId, n.messageId);
  assert.deepEqual(state.receipts, {});
});

test('fresh data access resolves exact native messageId after source expiry without claiming its expired receipt', async () => {
  const f = await fixture(), n = notice(), old = f.access('friday');
  await f.service.apply(f.access('jarvis'), f.create(), n); f.advance(hour + 1); f.restart();
  const bridge = new Bridge({ store: f.store, clock: f.clock, messagePolicyIds: policyIds });
  assert.equal((await bridge.read(f.native('friday'), { messageId: n.messageId })).expired, true);
  await assert.rejects(bridge.claim(f.native('friday'), { messageId: n.messageId }), code('message_authorization_inactive'));
  const before = f.store.snapshot();
  await assert.rejects(f.service.getByMessageId(old, n.messageId), code('task_access_denied'));
  assert.deepEqual(f.store.snapshot(), before);
  const resolved = await f.service.getByMessageId(f.access('friday'), n.messageId);
  assert.equal(resolved.task.id, f.taskId); assert.equal(resolved.task.phase, 'queued');
  assert.deepEqual(f.store.snapshot().receipts, {});
});

test('alias survives actual 24-hour message/job cleanup and resolves the retained task after restart', async () => {
  const f = await fixture(), n = notice(); await f.service.apply(f.access('jarvis'), f.create(), n);
  f.advance(CONTENT_RETENTION_MS + 1);
  await f.store.transaction(state => retainMessages(state, f.clock())); f.restart();
  assert.equal(f.store.snapshot().messages[n.messageId], undefined); assert.deepEqual(f.store.snapshot().jobs, {});
  const resolved = await f.service.getByMessageId(f.access('friday'), n.messageId);
  assert.equal(resolved.task.id, f.taskId); assert.equal(resolved.task.description, 'Durable coordination DATA.');
  assert.deepEqual(f.store.snapshot().receipts, {});
});

test('bounded alias expiry prunes only metadata; canonical task stays readable and old replay does not republish', async () => {
  const f = await fixture(), n = notice(), command = f.create();
  const first = await f.service.apply(f.access('jarvis'), command, n);
  f.advance(48 * hour);
  await assert.rejects(f.service.getByMessageId(f.access('friday'), n.messageId), code('task_notice_not_found'));
  assert.equal(f.store.snapshot().collaboration.noticeLinks[n.messageId], undefined);
  assert.equal((await f.kernel.get(f.access('friday'), f.taskId)).id, f.taskId);
  assert.deepEqual(await f.service.apply(f.access('jarvis'), command, n), first);
  assert.equal(f.staged(), 1); assert.equal(f.store.snapshot().collaboration.noticeLinks[n.messageId], undefined);
});

test('failure after notice staging rolls back task, notice, jobs, alias and replay state', async () => {
  const f = await fixture(), n = notice(), command = f.create(), before = f.store.snapshot();
  f.hook(() => { throw Error('FIXTURE_STAGE_FAILURE'); });
  await assert.rejects(f.service.apply(f.access('jarvis'), command, n), /FIXTURE_STAGE_FAILURE/);
  assert.deepEqual(f.store.snapshot(), before);
  f.hook(undefined); await f.service.apply(f.access('jarvis'), command, n);
  assert.equal(Object.keys(f.store.snapshot().messages).length, 1);
});

for (const mode of ['beforeCommit', 'afterCommit']) {
  test(`${mode}: retry has one logical task/notice/link and never extends the original alias`, async () => {
    const f = await fixture(), n = notice(), command = f.create();
    f.crash(mode); await assert.rejects(f.service.apply(f.access('jarvis'), command, n), /FIXTURE_/);
    if (mode === 'beforeCommit') assert.equal(f.store.snapshot().collaboration, undefined);
    const saved = f.store.snapshot().collaboration?.noticeLinks[n.messageId];
    f.advance(1000); f.restart();
    await f.service.apply(f.access('jarvis'), command, n);
    const state = f.store.snapshot();
    assert.equal(Object.keys(state.collaboration.tasks).length, 1);
    assert.equal(Object.keys(state.collaboration.noticeLinks).length, 1); assert.equal(Object.keys(state.messages).length, 1);
    if (saved) assert.deepEqual(state.collaboration.noticeLinks[n.messageId], saved);
    assert.equal(f.staged(), mode === 'beforeCommit' ? 2 : 1);
  });
}

test('concurrent exact retries share one notice; changed bindings and reused native IDs conflict atomically', async () => {
  const f = await fixture(), n = notice(), command = f.create();
  const results = await Promise.all(Array.from({ length: 10 }, () => f.service.apply(f.access('jarvis'), command, n)));
  for (const result of results) assert.deepEqual(result, results[0]);
  assert.equal(f.staged(), 1);
  const before = f.store.snapshot();
  await assert.rejects(f.service.apply(f.access('jarvis'), command, notice()), code('task_notice_conflict'));
  await assert.rejects(f.service.apply(f.access('jarvis'), f.create({ taskId: randomUUID() }), n), code('task_notice_id_conflict'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('link capacity never evicts a live alias and reserves one terminal notice slot', async () => {
  const f = await fixture({ links: { maxLinksPerTask: 3 } }), first = notice();
  await f.service.apply(f.access('jarvis'), f.create(), first);
  const claim = await f.service.apply(f.access('friday'), f.update('claim', 'friday'), notice());
  const command = f.update('progress', 'friday', { ...fence(claim), checkpoint: 'Must roll back at capacity.' });
  const extra = notice(), before = f.store.snapshot();
  await assert.rejects(f.service.apply(f.access('friday'), command, extra), code('task_notice_capacity_reached'));
  assert.deepEqual(f.store.snapshot(), before);
  await f.service.apply(f.access('jarvis'), f.update('cancel', 'jarvis'), notice());
  assert.equal(Object.keys(f.store.snapshot().collaboration.noticeLinks).length, 3);
  assert.equal((await f.service.getByMessageId(f.access('friday'), first.messageId)).task.phase, 'cancelled');
});

test('global alias capacity rejects new work without losing the existing task', async () => {
  const f = await fixture({ links: { maxLinks: 2 } }); await f.service.apply(f.access('jarvis'), f.create(), notice());
  const before = f.store.snapshot();
  await assert.rejects(f.service.apply(f.access('jarvis'), f.create({ taskId: randomUUID() }), notice()), code('task_notice_capacity_reached'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('expired aliases free bounded slots without evicting task records', async () => {
  const f = await fixture({ links: { maxLinksPerTask: 2, linkRetentionMs: 1000 } }), first = notice();
  await f.service.apply(f.access('jarvis'), f.create(), first);
  await assert.rejects(f.service.apply(f.access('friday'), f.update('claim', 'friday'), notice()), code('task_notice_capacity_reached'));
  f.advance(1000);
  await f.service.apply(f.access('friday'), f.update('claim', 'friday'), notice());
  assert.equal(f.store.snapshot().collaboration.noticeLinks[first.messageId], undefined);
  assert.equal(Object.keys(f.store.snapshot().collaboration.tasks).length, 1);
});

test('alias lookup enforces injected fresh access, owner and recipient without modifying receipts', async () => {
  const f = await fixture(), n = notice(); await f.service.apply(f.access('jarvis'), f.create(), n);
  const before = f.store.snapshot();
  await assert.rejects(f.service.getByMessageId(f.access('jarvis'), n.messageId), code('task_notice_not_found'));
  await assert.rejects(f.service.getByMessageId(f.access('friday', 'b'.repeat(64)), n.messageId), code('task_not_found'));
  await assert.rejects(f.service.getByMessageId(f.access('friday'), randomUUID()), code('task_notice_not_found'));
  await assert.rejects(f.service.getByMessageId(f.access('friday'), [n.messageId]), code('invalid_task_notice'));
  assert.deepEqual(f.store.snapshot(), before);
});

test('old notice resolves latest data; bare kernel mutations preserve aliases and cannot invent retroactive notices', async () => {
  const f = await fixture(), n = notice(); await f.service.apply(f.access('jarvis'), f.create(), n);
  const command = f.update('claim', 'friday'), claim = await f.kernel.apply(f.access('friday'), command);
  await f.kernel.apply(f.access('friday'), f.update('progress', 'friday', { ...fence(claim), checkpoint: 'Latest report.' }));
  const resolved = await f.service.getByMessageId(f.access('friday'), n.messageId);
  assert.equal(resolved.noticeRevision, 1); assert.equal(resolved.task.revision, 3);
  assert.equal(resolved.task.checkpoint.text, 'Latest report.');
  await assert.rejects(f.service.apply(f.access('friday'), command, notice()), code('task_notice_conflict'));
  assert.equal(f.staged(), 1);
});

test('asynchronous or mismatched notice staging is rejected with no partial task write', async () => {
  for (const mode of ['async', 'wrongRecipient']) {
    const f = await fixture(), before = f.store.snapshot();
    f.hook((state, notice) => {
      if (mode === 'async') return Promise.resolve();
      state.messages[notice.messageId].envelope.to = notice.from;
    });
    await assert.rejects(f.service.apply(f.access('jarvis'), f.create(), notice()), code('task_notice_stage_invalid'));
    assert.deepEqual(f.store.snapshot(), before);
  }
});

test('opt-in notice admission respects owner/batch cleanup; lookup prunes only its exact expired alias', async () => {
  const f = await fixture({ kernel: { retention: { terminalMs: 10, tombstoneMs: 40,
    creationWindowMs: 20, batchSize: 1, maxTombstones: 10 } } });
  const stamp = start.toString(16).padStart(12, '0'), random = randomUUID();
  const taskId = `${stamp.slice(0, 8)}-${stamp.slice(8)}-7${random.slice(15, 18)}-${random.slice(19)}`;
  await f.service.apply(f.access('jarvis'), f.create({ taskId }), notice());
  const own = Array.from({ length: 5 }, () => randomUUID()), foreign = Array.from({ length: 5 }, () => randomUUID());
  await f.store.transaction(state => {
    for (const [ids, owner] of [[own, ownerKey], [foreign, 'b'.repeat(64)]])
      for (const id of ids) state.collaboration.noticeLinks[id] = {
        taskId, revision: 1, recipient: 'friday', ownerKey: owner, createdAt: start, until: start + 1 };
  });
  f.advance(2);
  await f.service.apply(f.access('friday'), { operation: 'claim', taskId, commandId: randomUUID(),
    sequence: 1, expectedRevision: 1 }, notice());
  let links = f.store.snapshot().collaboration.noticeLinks;
  assert.equal(own.filter(id => !links[id]).length, 1);
  assert.equal(foreign.filter(id => links[id]).length, 5);
  const target = own.find(id => links[id]);
  await assert.rejects(f.service.getByMessageId(f.access('friday'), target), code('task_notice_not_found'));
  links = f.store.snapshot().collaboration.noticeLinks;
  assert.equal(own.filter(id => !links[id]).length, 2);
  assert.equal(foreign.filter(id => links[id]).length, 5);
  const before = f.store.snapshot();
  await assert.rejects(f.service.getByMessageId(f.access('friday'), foreign[0]), code('task_notice_not_found'));
  assert.deepEqual(f.store.snapshot(), before);
});
