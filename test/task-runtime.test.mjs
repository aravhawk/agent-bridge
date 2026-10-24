import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createRuntime } from '../src/runtime.mjs';
import { emptyState } from '../src/store.mjs';
import { SCOPES } from '../src/policy.mjs';
import { resourceFor } from '../src/resource.mjs';
import { TOPIC } from '../src/queue.mjs';
import { ISSUER } from './fixtures/provider.mjs';
import { registerHooks } from 'node:module';

const hour = 3600000, owner = 'offline-runtime-task-owner';
const on = { enabled: true, leaseMs: 60000, linkRetentionMs: 48 * hour, purgeEnabled: false };
const names = ['bridge_task_command', 'bridge_task_get', 'bridge_task_from_notice'];
const ordinary = ['bridge_health', 'bridge_read', 'bridge_receipt_claim', 'bridge_receipt_complete', 'bridge_status', 'bridge_message_send'];
const code = expected => error => error.code === expected;
const data = value => value.result?.structuredContent;
const errorCode = value => value.error?.message || data(value)?.error;

// Actual runtime/verifier/PostgresStore/queue/worker, with a serialized fake SQL
// connection and fake transports. No deployment/native catalog is contacted.
async function fixture({ taskData, overrides = {}, stats = {}, apiAssembly = false } = {}) {
  let now = Date.now(), document = emptyState(), tail = Promise.resolve();
  const sends = [], posts = [];
  const clock = () => now;
  class Pool {
    constructor() { stats.pools = (stats.pools || 0) + 1; }
    on() {} async end() {}
    async connect() {
      const previous = tail; let unlock; tail = new Promise(resolve => { unlock = resolve; }); await previous;
      let pending;
      return { release() { unlock(); }, async query(sql, args) {
        if (sql === 'BEGIN') pending = structuredClone(document);
        if (sql.startsWith('SELECT document')) return { rows: [{ document: structuredClone(pending) }] };
        if (sql.startsWith('UPDATE bridge_runtime_v1')) pending = JSON.parse(args[0]);
        if (sql === 'COMMIT') document = pending;
        return { rows: [] };
      } };
    }
  }
  const env = { BRIDGE_OAUTH_ISSUER: ISSUER, BRIDGE_ALLOWED_SUBJECT_SHA256: createHash('sha256').update(owner).digest('hex'),
    BRIDGE_OAUTH_CONTRACT_VERIFIED: 'true', BRIDGE_SUBSCRIPTIONS_ENABLED: 'true', BRIDGE_DELIVERY_ENABLED: 'true',
    BRIDGE_SUBSCRIPTION_STORAGE_KEY: randomBytes(32).toString('base64'),
    DATABASE_URL: 'postgresql://fixture.neon.tech/neondb?sslmode=require',
    BRIDGE_RECEIVER_POLICY: 'inbox-v1', FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'true',
    FRIDAY_RECEIVER_ID: 'jarvis-friday-bridge-inbox', FRIDAY_WEBHOOK_URL: 'https://receiver.example.test/runtime-tasks',
    FRIDAY_WEBHOOK_KEY: 'OFFLINE_FIXTURE_ONLY', ...overrides };
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const options = { env, Pool, taskData, clock, keyResolver: publicKey,
    queueClient: { async send(topic, payload, options) {
      assert.equal(topic, TOPIC);
      if (payload.dispatchMessageId) assert.equal(document.messages[payload.dispatchMessageId], undefined, 'native prearm precedes content');
      sends.push({ payload, options });
    }, handleCallback: handler => handler },
    transportFactory: () => async (url, request) => {
      const body = JSON.parse(request.body);
      if (body.type === 'verification') return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
      posts.push({ recipient: url === env.FRIDAY_WEBHOOK_URL ? 'friday' : 'jarvis', body });
      return { status: 202 };
    } };
  let rt = createRuntime(options);
  let apiHandle;
  if (apiAssembly) {
    // Exercise the real API entrypoint and real verifier/runtime. Only its
    // private constructor dependencies and default v1 singleton are fixtures.
    const key = 'activation_' + randomUUID().replaceAll('-', ''), stub = 'activation:' + key;
    const entry = new URL('../api/index.mjs', import.meta.url); entry.searchParams.set('fixture', key);
    globalThis[key] = { createRuntime: supplied => { stats.assemblies = (stats.assemblies || 0) + 1;
      return createRuntime({ ...options, ...supplied }); }, runtime: rt };
    const hook = registerHooks({
      resolve(specifier, context, next) {
        return context.parentURL === entry.href && specifier === '../src/runtime.mjs'
          ? { url: stub, shortCircuit: true } : next(specifier, context);
      },
      load(url, context, next) {
        return url === stub ? { format: 'module', shortCircuit: true,
          source: `const f=globalThis[${JSON.stringify(key)}]; export const createRuntime=f.createRuntime; export const runtime=f.runtime;` }
          : next(url, context);
      }
    });
    try { apiHandle = (await import(entry.href)).handle; } finally { hook.deregister(); delete globalThis[key]; }
  }
  const sign = (role, scopes = Object.values(SCOPES[role])) => new SignJWT({ [env.BRIDGE_OAUTH_SCOPE_CLAIM || 'scope']: scopes.join(' ') })
    .setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER).setSubject(owner).setAudience(resourceFor(role))
    .setIssuedAt(Math.floor(now / 1000)).setExpirationTime(Math.floor(now / 1000) + 96 * 3600).sign(privateKey);
  const tokens = { jarvis: await sign('jarvis'), friday: await sign('friday') };
  const rpc = async (role, method, params, token = tokens[role], handler) => {
    handler ||= apiHandle || rt.handler(role);
    const response = await handler(new Request(resourceFor(role), { method: 'POST', headers: {
      'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, ...await response.json() };
  };
  const tool = (role, name, args, token) => rpc(role, 'tools/call', { name, arguments: args }, token);
  return { get rt() { return rt; }, env, stats, sends, posts, sign, rpc, tool, clock, state: () => structuredClone(document),
    restart: () => { rt = createRuntime(options); },
    advance: ms => { now += ms; },
    list: async role => (await rpc(role, 'tools/list', {})).result.tools,
    subscribe: () => rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' },
      ttlMs: null, delivery: { mode: 'webhook', url: 'https://callback.example.test/runtime-tasks',
        secret: 'whsec_' + randomBytes(32).toString('base64') } }),
    create: assignee => ({ operation: 'create', taskId: randomUUID(), commandId: randomUUID(), sequence: 1,
      assignee, description: 'Offline runtime teamwork data.', deadline: now + 72 * hour }),
    notice: () => ({ messageId: randomUUID(), sentAt: new Date(now).toISOString(), expiresAt: new Date(now + hour).toISOString() }),
    update: (taskId, role, operation, extra = {}) => {
      const task = document.collaboration.tasks[taskId];
      return { operation, taskId, commandId: randomUUID(), sequence: (task.commands[role]?.through || 0) + 1,
        expectedRevision: task.revision, ...extra };
    },
    consume: payload => rt.queueHandler()(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }),
  };
}

test('default/explicit-off runtime catalogs remain exactly v1 for both directions; env/request flags cannot enable tasks', async () => {
  const normal = await fixture(), off = await fixture({ taskData: { enabled: false }, overrides: {
    BRIDGE_TASK_DATA_ENABLED: 'true', BRIDGE_TASK_PURGE_ENABLED: 'true' } });
  for (const role of ['jarvis', 'friday']) {
    const a = await normal.list(role), b = await off.list(role);
    assert.deepEqual(a, b);
    assert.deepEqual(a.map(t => t.name).sort(), [...ordinary, ...(role === 'jarvis' ?
      ['bridge_subscription_status', 'bridge_friday_webhook_diagnostic'] : [])].sort());
    for (const name of names) assert.equal(errorCode(await off.tool(role, name, {})), 'tool_not_available');
    assert.equal(errorCode(await off.rpc(role, 'tools/list', { taskData: on })), 'invalid_params');
  }
  assert.equal(normal.stats.pools || 0, 0); assert.equal(off.stats.pools || 0, 0);
  assert.deepEqual(off.state(), emptyState()); assert.equal(off.sends.length, 0); assert.equal(off.posts.length, 0);
});

test('real activation entrypoint enables tasks only with verified policy and preserves v1 on optional cold assembly failure', async () => {
  const active = await fixture({ apiAssembly: true }), base = await fixture();
  for (const role of ['jarvis', 'friday']) {
    assert.deepEqual((await active.list(role)).filter(t => !names.includes(t.name)), await base.list(role));
    assert.deepEqual((await active.list(role)).filter(t => names.includes(t.name)).map(t => t.name), names);
  }
  assert.equal(active.stats.assemblies, 1); assert.equal(active.stats.pools || 0, 0);
  active.env.BRIDGE_DELIVERY_ENABLED = 'false';
  assert.equal((await active.list('jarvis')).some(t => names.includes(t.name)), false);
  assert.equal(data(await active.tool('jarvis', 'bridge_health', {})).authenticated, true);
  for (const setting of [{ BRIDGE_DELIVERY_ENABLED: 'false' }, { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'false' },
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false' }, { BRIDGE_RECEIVER_POLICY: '' }]) {
    const fallback = await fixture({ apiAssembly: true, overrides: setting });
    for (const role of ['jarvis', 'friday']) {
      assert.equal((await fallback.list(role)).some(t => names.includes(t.name)), false);
      assert.equal(data(await fallback.tool(role, 'bridge_health', {})).authenticated, true);
      assert.equal(errorCode(await fallback.tool(role, 'bridge_task_get', { taskId: randomUUID() })), 'tool_not_available');
    }
    // Existing withdrawal remains callable even with an unattested contract.
    const unsub = await fallback.rpc('jarvis', 'events/unsubscribe', { name: 'bridge.message.received',
      arguments: { recipient: 'jarvis' }, delivery: { mode: 'webhook', url: 'https://callback.example.test/runtime-tasks' } });
    assert.equal(unsub.status, 200); assert.ok(unsub.result);
    assert.equal(fallback.stats.assemblies, 1, 'failed optional assembly is cached as v1-only for this instance');
  }
});

test('both roles recover an uncertain command and finish an existing run after runtime restart using only public reads', async () => {
  const f = await fixture({ taskData: on }); await f.subscribe();
  for (const coordinator of ['jarvis', 'friday']) {
    const peer = coordinator === 'jarvis' ? 'friday' : 'jarvis', create = f.create(peer), firstNotice = f.notice();
    const send = (role, command, notice = f.notice()) => f.tool(role, 'bridge_task_command', { command, notice });
    await send(coordinator, create, firstNotice); f.restart();
    const own = data(await f.tool(coordinator, 'bridge_task_get', { taskId: create.taskId, commandId: create.commandId }));
    assert.equal(own.caller.nextSequence, 2); assert.equal(own.caller.command.status, 'committed');
    assert.equal(own.caller.command.noticeMessageId, firstNotice.messageId);
    const lookup = data(await f.tool(peer, 'bridge_task_from_notice', { messageId: firstNotice.messageId,
      commandId: create.commandId }, await f.sign(peer, [SCOPES[peer].ack])));
    assert.deepEqual(lookup.task.caller, { role: peer, nextSequence: 1,
      command: { commandId: create.commandId, status: 'unknown' } });
    const claimId = randomUUID();
    await send(peer, { operation: 'claim', taskId: create.taskId, commandId: claimId,
      sequence: lookup.task.caller.nextSequence, expectedRevision: lookup.task.revision });
    f.restart();
    const claimed = data(await f.tool(peer, 'bridge_task_get', { taskId: create.taskId, commandId: claimId }));
    assert.equal(claimed.caller.command.status, 'committed');
    const startId = randomUUID(), operationId = randomUUID();
    assert.equal(data(await send(peer, { operation: 'start', taskId: create.taskId, commandId: startId,
      sequence: claimed.caller.nextSequence, expectedRevision: claimed.revision,
      attemptId: claimed.lease.id, epoch: claimed.epoch, operationId })).operationRecorded, true);
    f.advance(2 * hour); f.restart();
    const fresh = data(await f.tool(peer, 'bridge_task_from_notice', { messageId: firstNotice.messageId, commandId: startId })).task;
    assert.equal(fresh.phase, 'reconciliation_required'); assert.equal(fresh.caller.command.result.operationRecorded, false);
    assert.equal(fresh.externalOperation.id, operationId); assert.equal(fresh.caller.nextSequence, 3);
    assert.equal(data(await send(peer, { operation: 'reconcile', taskId: fresh.id, commandId: randomUUID(),
      sequence: fresh.caller.nextSequence, expectedRevision: fresh.revision, operationId: fresh.externalOperation.id,
      runRef: 'synthetic-existing-run', outcome: 'succeeded', evidence: 'Synthetic existing result queried; no new launch.',
      result: 'Recovered without scratch files.' })).phase, 'succeeded');
    assert.equal(errorCode(await f.tool(peer, 'bridge_task_get', { taskId: fresh.id, commandId: [startId] })), 'invalid_task_command');
    assert.equal(errorCode(await f.tool(peer, 'bridge_task_from_notice', { messageId: firstNotice.messageId, commandId: [startId] })), 'invalid_task_command');
  }
});

test('explicit opt-in adds only three identical directional task catalogs and strict argument schemas without storage access', async () => {
  const active = await fixture({ taskData: on }), base = await fixture();
  const directional = [];
  for (const role of ['jarvis', 'friday']) {
    const catalog = await active.list(role), tasks = catalog.filter(t => names.includes(t.name));
    assert.deepEqual(catalog.filter(t => !names.includes(t.name)), await base.list(role));
    assert.deepEqual(tasks.map(t => t.name), names); directional.push(tasks);
    const schema = tasks[0].inputSchema;
    assert.equal(schema.additionalProperties, false); assert.deepEqual(schema.required, ['command', 'notice']);
    assert.deepEqual(schema.properties.notice.required, ['messageId', 'sentAt', 'expiresAt']);
    assert.equal(schema.properties.notice.additionalProperties, false);
    const commands = schema.properties.command.oneOf;
    assert.deepEqual(commands.map(c => c.properties.operation.const).sort(), ['assign', 'block', 'cancel', 'claim', 'create', 'finish', 'progress', 'reconcile', 'start']);
    for (const command of commands) {
      assert.equal(command.additionalProperties, false);
      assert.deepEqual(command.required, Object.keys(command.properties));
      assert.equal(command.properties.taskId.format, 'uuid'); assert.equal(command.properties.commandId.format, 'uuid');
      assert.equal(command.properties.sequence.minimum, 1);
      assert.equal(command.required.includes('expectedRevision'), command.properties.operation.const !== 'create');
    }
    assert.deepEqual(tasks[1].inputSchema.required, ['taskId']);
    assert.deepEqual(tasks[2].inputSchema.required, ['messageId']);
    assert.equal(tasks[1].inputSchema.properties.commandId.format, 'uuid');
    assert.equal(tasks[2].inputSchema.properties.commandId.format, 'uuid');
    for (const task of tasks) assert.equal(task.inputSchema.additionalProperties, false);
  }
  assert.deepEqual(directional[0], directional[1]); assert.equal(active.stats.pools || 0, 0);
  assert.deepEqual(active.state(), emptyState()); assert.equal(active.sends.length, 0);
});

test('opt-in actual runtime assembles both task directions through prearm, event ID, fresh read and claim/checkpoint/result', async () => {
  const f = await fixture({ taskData: on }); assert.ok((await f.subscribe()).result.id);
  for (const role of ['jarvis', 'friday']) {
    const peer = role === 'jarvis' ? 'friday' : 'jarvis', command = f.create(peer), notice = f.notice();
    const send = async (actor, request, n = f.notice()) => f.tool(actor, 'bridge_task_command', { command: request, notice: n });
    assert.equal(data(await send(role, command, notice)).phase, 'queued');
    const envelope = f.state().messages[notice.messageId].envelope;
    assert.equal(envelope.from, role); assert.equal(envelope.to, peer); assert.equal(envelope.threadId, command.taskId);
    await f.consume({ dispatchMessageId: notice.messageId }); await f.consume({ dispatchMessageId: notice.messageId });
    const event = f.posts.at(-1); assert.equal(event.recipient, peer); assert.equal(event.body.data.messageId, notice.messageId);
    assert.equal(event.body.event || event.body.name, 'bridge.message.received');
    f.advance(100 * 60000);
    const read = await f.tool(peer, 'bridge_task_from_notice', { messageId: event.body.data.messageId }, await f.sign(peer, [SCOPES[peer].ack]));
    assert.equal(data(read).task.phase, 'queued'); assert.equal(data(read).task.id, command.taskId);
    assert.equal(data(await f.tool(peer, 'bridge_read', { messageId: notice.messageId })).expired, true);
    assert.equal(errorCode(await f.tool(peer, 'bridge_receipt_claim', { messageId: notice.messageId })), 'message_authorization_inactive');
    const claim = data(await send(peer, f.update(command.taskId, peer, 'claim')));
    const fence = { attemptId: claim.attemptId, epoch: claim.epoch };
    assert.equal(claim.phase, 'running');
    assert.equal(data(await send(peer, f.update(command.taskId, peer, 'progress', { ...fence, checkpoint: 'Runtime checkpoint.' }))).phase, 'running');
    const operationId = randomUUID(), start = f.update(command.taskId, peer, 'start', { ...fence, operationId }), intentNotice = f.notice();
    assert.equal(data(await send(peer, start, intentNotice)).operationRecorded, true);
    f.advance(2 * hour); // Existing native work outlives the short mutex; the fixture never relaunches it.
    const current = data(await f.tool(peer, 'bridge_task_get', { taskId: command.taskId }, await f.sign(peer)));
    assert.equal(current.phase, 'reconciliation_required'); assert.equal(current.externalOperation.id, operationId);
    assert.equal(errorCode(await send(peer, f.update(command.taskId, peer, 'claim'))), 'task_reconciliation_required');
    assert.equal(data(await send(peer, start, intentNotice)).operationRecorded, false);
    const finished = data(await send(peer, f.update(command.taskId, peer, 'reconcile', {
      operationId, runRef: 'synthetic-runtime-existing-run', outcome: 'succeeded',
      evidence: 'Synthetic existing-run result verified by the local workflow fixture.', result: 'Runtime reported result.' })));
    await f.consume({ dispatchMessageId: finished.noticeMessageId });
    const resultEvent = f.posts.at(-1); assert.equal(resultEvent.recipient, role);
    const resolved = data(await f.tool(role, 'bridge_task_from_notice', { messageId: resultEvent.body.data.messageId })).task;
    assert.equal(resolved.result.text, 'Runtime reported result.'); assert.equal(resolved.checkpoint.text, 'Runtime checkpoint.');
    assert.equal(resolved.result.evidenceStatus, 'reported_not_independently_verified');
  }
  assert.deepEqual(f.state().receipts, {}); assert.equal(f.state().collaboration.retiredTasks, undefined);
  assert.equal(f.state().collaboration.taskIdentity, undefined);
});

test('opt-in rejects absent or unverified policy before constructing storage or exposing a catalog', async () => {
  for (const overrides of [{ BRIDGE_OAUTH_ISSUER: undefined }, { BRIDGE_ALLOWED_SUBJECT_SHA256: undefined },
    { BRIDGE_OAUTH_CONTRACT_VERIFIED: 'false' }, { BRIDGE_RECEIVER_POLICY: '' },
    { FRIDAY_WEBHOOK_CONTRACT_VERIFIED: 'false' }, { BRIDGE_DELIVERY_ENABLED: 'false' }]) {
    const stats = {};
    await assert.rejects(fixture({ taskData: on, overrides, stats }), code('task_runtime_policy_required'));
    assert.equal(stats.pools || 0, 0);
  }
  for (const overrides of [{ BRIDGE_ALLOWED_SUBJECT: owner }, { BRIDGE_OAUTH_SCOPE_CLAIM: 'unverified_claim' }])
    await assert.rejects(fixture({ taskData: on, overrides }), code('task_access_configuration_required'));
});

test('runtime opt-in is strict, server-bound and refuses permanent purge independently', async () => {
  for (const taskData of [{ ...on, purgeEnabled: true }, { ...on, purgeEnabled: 'false' }, { ...on, retention: {} }])
    await assert.rejects(fixture({ taskData }), code('task_purge_not_enabled'));
  for (const taskData of [true, [], { ...on, enabled: 'true' }, { enabled: true }, { ...on, policy: {} }, { ...on, ownerKey: 'a'.repeat(64) }])
    await assert.rejects(fixture({ taskData }), code('task_runtime_configuration_required'));
});

test('every accepted option bound is validated before advertising a catalog or constructing storage', async () => {
  for (const extra of [{ maxLinks: 0 }, { maxLinks: 1001 }, { maxLinksPerTask: 0 }, { maxLinksPerTask: 33 }]) {
    const stats = {};
    await assert.rejects(fixture({ taskData: { ...on, ...extra }, stats }), code('task_notice_configuration_required'));
    assert.equal(stats.pools || 0, 0);
  }
  for (const limits of [null, [], { tasks: 0 }, { tasks: 101 }, { bytes: 1048577 }, { taskBytes: 16385 }, { replay: 33 }, { unknown: 1 }]) {
    const stats = {};
    await assert.rejects(fixture({ taskData: { ...on, limits }, stats }), code('task_kernel_configuration_required'));
    assert.equal(stats.pools || 0, 0);
  }
  const valid = await fixture({ taskData: { ...on, limits: { tasks: 2, replay: 2 }, maxLinks: 4, maxLinksPerTask: 3 } });
  assert.equal((await valid.list('friday')).filter(t => names.includes(t.name)).length, 3);
  assert.equal(valid.stats.pools || 0, 0);
});

test('opt-in runtime rejects catalog-incompatible arguments in both directions without queue publication or task mutation', async () => {
  const f = await fixture({ taskData: on });
  for (const role of ['jarvis', 'friday']) {
    for (const [name, args, expected] of [
      ['bridge_task_get', { taskId: 'not-a-uuid' }, 'invalid_task_command'],
      ['bridge_task_get', { taskId: randomUUID(), ownerKey: 'a'.repeat(64) }, 'invalid_params'],
      ['bridge_task_from_notice', { messageId: 'not-a-uuid' }, 'invalid_task_notice'],
      ['bridge_task_command', { command: { ...f.create('friday'), operation: 'unknown' }, notice: f.notice() }, 'invalid_task_command'],
      ['bridge_task_command', { command: f.create('friday'), notice: { ...f.notice(), from: role } }, 'invalid_params'],
    ]) assert.equal(errorCode(await f.tool(role, name, args)), expected);
  }
  assert.deepEqual(f.state(), emptyState()); assert.equal(f.sends.length, 0); assert.equal(f.posts.length, 0);
});

test('an existing opt-in handler closes task discovery/calls if verified runtime policy is withdrawn', async () => {
  const f = await fixture({ taskData: on }), handler = f.rt.handler('jarvis');
  const list = () => f.rpc('jarvis', 'tools/list', {}, undefined, handler);
  assert.equal((await list()).result.tools.filter(t => names.includes(t.name)).length, 3);
  f.env.FRIDAY_WEBHOOK_CONTRACT_VERIFIED = 'false';
  assert.equal((await list()).result.tools.some(t => names.includes(t.name)), false);
  assert.equal(errorCode(await f.rpc('jarvis', 'tools/call', { name: 'bridge_task_get', arguments: { taskId: randomUUID() } },
    undefined, handler)), 'tool_not_available');
  assert.equal(f.stats.pools || 0, 0); assert.deepEqual(f.state(), emptyState());
});
