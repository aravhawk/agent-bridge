import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { MemoryStore } from '../src/store.mjs';
import { Bridge } from '../src/bridge.mjs';
import { TaskKernel } from '../src/tasks.mjs';
import { TaskIntegration, TASK_TOOLS } from '../src/task-integration.mjs';
import { createMcpHandler } from '../src/mcp.mjs';
import { NativeEvents } from '../src/events.mjs';
import { createProtector } from '../src/webhook.mjs';
import { DeliveryWorker } from '../src/worker.mjs';
import { createQueueAdapter, TOPIC } from '../src/queue.mjs';
import { createAccessVerifier, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.mjs';
import { resourceFor, metadataFor } from '../src/resource.mjs';
import { CONTENT_RETENTION_MS, retainMessages } from '../src/messages.mjs';
import { ISSUER } from './fixtures/provider.mjs';

const start = Date.UTC(2026, 9, 24), hour = 3600000;
const ownerKey = 'a'.repeat(64), subject = 'offline-task-prototype-fixture';
const code = expected => error => error.code === expected;
const content = response => response.result?.structuredContent;
const errorCode = response => response.error?.message || content(response)?.error;
const fence = attempt => ({ attemptId: attempt.attemptId, epoch: attempt.epoch });

// Real local JWT verification, fake pinned owner and injected data admission.
// This fixture is NOT a proposed production owner/scope adapter. No network,
// real token, database, webhook, receiver or hosted assistant is involved.
async function fixture({ subscribe = true, capability = true, healthOnly = false, retention, maxLinks } = {}) {
  let now = start, inner = new MemoryStore(), fault, prearmFailure = false, afterDispatch, dataAllowed = true;
  const clock = () => now, calls = [], deliveries = [], published = new Map();
  const store = { transaction: async operation => {
    let failAfter = false;
    const output = await inner.transaction(state => {
      const result = operation(state);
      if (fault && state.messages[fault.messageId] && state.collaboration?.tasks[fault.taskId]) {
        const mode = fault.mode; fault = undefined;
        if (mode === 'beforeCommit') throw Error('PRIVATE_FIXTURE_COMMIT_FAILURE');
        failAfter = true;
      }
      return result;
    });
    if (failAfter) throw Error('PRIVATE_FIXTURE_COMMIT_RESPONSE_LOST');
    return output;
  } };
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const tokens = {}, verified = {};
  const verifier = role => createAccessVerifier({ issuer: ISSUER, audience: resourceFor(role), subject, role,
    keyResolver: publicKey, currentDate: new Date(now) });
  async function token(role, scopes = Object.values(SCOPES[role]), ttl = 96 * hour) {
    return new SignJWT({ scope: scopes.join(' ') }).setProtectedHeader({ alg: 'RS256' }).setIssuer(ISSUER)
      .setAudience(resourceFor(role)).setSubject(subject).setIssuedAt(now / 1000)
      .setExpirationTime((now + ttl) / 1000).sign(privateKey);
  }
  for (const role of ['jarvis', 'friday']) {
    tokens[role] = await token(role);
    verified[role] = await verifier(role)(new Request(resourceFor(role), { headers: { authorization: 'Bearer ' + tokens[role] } }));
  }
  const policyIds = Object.fromEntries(Object.entries(verified).map(([role, p]) => [role, p[VERIFIED_AUTHORIZATION].policyId]));
  const admitted = new Set(Object.values(verified).map(p => p.principalKey));
  const kernel = new TaskKernel({ store, clock, leaseMs: 60000, retention, authorize: p => ({
    dataAllowed: dataAllowed && admitted.has(p.principalKey) && p[VERIFIED_AUTHORIZATION]?.expiresAt > now,
    ownerKey, role: p.role, coordinate: p.role === 'jarvis',
  }) });
  const protector = createProtector(randomBytes(32));
  const transport = async (_url, request) => {
    const body = JSON.parse(request.body);
    if (body.type === 'verification') return { status: 200, body: JSON.stringify({ challenge: body.challenge }) };
    deliveries.push({ role: 'jarvis', body }); return { status: 202 };
  };
  const events = new NativeEvents({ store, clock, protector, transport, policyId: policyIds.jarvis, enabled: true });
  const worker = new DeliveryWorker({ store, clock, protector, transport, enabled: true, messagePolicyIds: policyIds,
    policyId: policyIds.jarvis, accessAllowed: async () => true,
    webhookSender: async job => { deliveries.push({ role: 'friday', body: JSON.parse(job.body) }); return { status: 202 }; } });
  const queue = createQueueAdapter({ store, clock, worker, enabled: true, maintenanceEnabled: true, client: {
    async send(topic, payload, options) {
      assert.equal(topic, TOPIC); calls.push({ payload, options });
      if (payload.dispatchMessageId) {
        assert.equal(inner.snapshot().messages[payload.dispatchMessageId], undefined, 'prearm precedes content commit');
        if (prearmFailure) { prearmFailure = false; throw Error('PRIVATE_FIXTURE_PREARM_FAILURE'); }
        await afterDispatch?.(payload.dispatchMessageId);
      }
      if (!published.has(options.idempotencyKey)) published.set(options.idempotencyKey, payload);
    },
  } });
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: policyIds,
    prepareMessage: id => queue.prepareMessage(id), prepareReceipt: id => queue.prepareReceipt(id) });
  const tasks = new TaskIntegration({ enabled: capability, kernel, bridge, linkRetentionMs: 48 * hour, maxLinks,
    purgeEnabled: retention !== undefined });
  const handler = role => createMcpHandler({ enabled: true, verify: req => verifier(role)(req), bridge, events,
    scheduleJobs: ids => queue.scheduleJobs(ids), health: () => ({}), tasks, healthOnly, resourceMetadataUrl: metadataFor(role) });
  const rpc = async (role, method, params, bearer = tokens[role]) => {
    const response = await handler(role)(new Request(resourceFor(role), { method: 'POST', headers: {
      'content-type': 'application/json', authorization: 'Bearer ' + bearer },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }));
    return { status: response.status, headers: response.headers, ...await response.json() };
  };
  const tool = (role, name, args, bearer) => rpc(role, 'tools/call', { name, arguments: args }, bearer);
  if (subscribe) await rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' },
    ttlMs: null, delivery: { mode: 'webhook', url: 'https://callback.example.test/task-fixture',
      secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const create = (extra = {}) => ({ operation: 'create', taskId: randomUUID(), commandId: randomUUID(), sequence: 1,
    assignee: 'friday', description: 'Offline teamwork DATA.', deadline: now + 72 * hour, ...extra });
  const notice = (extra = {}) => ({ messageId: randomUUID(), sentAt: new Date(now).toISOString(),
    expiresAt: new Date(now + hour).toISOString(), ...extra });
  const update = (taskId, role, operation, extra = {}) => {
    const task = inner.snapshot().collaboration.tasks[taskId];
    return { operation, taskId, commandId: randomUUID(), sequence: (task.commands[role]?.through || 0) + 1,
      expectedRevision: task.revision, ...extra };
  };
  return { store, bridge, kernel, tasks, events, queue, calls, deliveries, published, rpc, tool, create, notice, update, token,
    state: () => inner.snapshot(), advance: ms => { now += ms; }, restart: () => { inner = new MemoryStore(inner.snapshot()); },
    fault: (mode, command, n) => { fault = { mode, taskId: command.taskId, messageId: n.messageId }; },
    failPrearm: () => { prearmFailure = true; }, afterDispatch: fn => { afterDispatch = fn; },
    denyData: () => { dataAllowed = false; },
    consume: payload => queue.consume(payload, { topicName: TOPIC, region: 'iad1', deliveryCount: 1 }),
    command: (role, command, n = notice(), bearer) => tool(role, 'bridge_task_command', { command, notice: n }, bearer),
  };
}

test('task capability is default-off, absent from ordinary/health-only catalogs and rejects direct calls', async () => {
  assert.equal(new TaskIntegration().enabled, false);
  await assert.rejects(new TaskIntegration().get({}, { taskId: randomUUID() }), code('task_integration_disabled'));
  for (const opts of [{ capability: false }, { healthOnly: true }]) {
    const f = await fixture(opts), before = f.state();
    const names = (await f.rpc('jarvis', 'tools/list', {})).result.tools.map(t => t.name);
    assert.equal(names.some(name => name.startsWith('bridge_task_')), false);
    for (const t of TASK_TOOLS) {
      const response = await f.tool('jarvis', t.name, {});
      assert.equal(response.status, 403); assert.equal(errorCode(response), 'tool_not_available');
    }
    assert.deepEqual(f.state(), before); assert.equal(f.calls.length, 0);
  }
  const f = await fixture();
  assert.throws(() => new TaskIntegration({ enabled: true, kernel: new TaskKernel({ store: f.store, leaseMs: 10 }),
    bridge: f.bridge, linkRetentionMs: hour }), code('task_integration_configuration_required'));
});

test('native notice -> 100-minute delayed exact-ID read -> task claim/checkpoint/result uses real local MCP/queue path', async () => {
  const f = await fixture(), command = f.create(), n = f.notice();
  const sent = await f.command('jarvis', command, n);
  assert.equal(sent.status, 200); assert.equal(content(sent).phase, 'queued');
  assert.equal(content(sent).noticeMessageId, n.messageId); assert.equal(content(sent).scheduling, 'requested');
  assert.equal('jobIds' in content(sent), false);
  const jobId = f.state().messages[n.messageId].jobIds[0];
  await f.consume({ jobId }); await f.consume({ jobId });
  assert.equal(f.deliveries.length, 1);
  assert.deepEqual(f.deliveries[0].body, { event: 'bridge.message.received', data: { messageId: n.messageId } });
  f.advance(100 * 60000); f.restart();
  const read = await f.tool('friday', 'bridge_task_from_notice', { messageId: f.deliveries[0].body.data.messageId });
  assert.equal(content(read).task.id, command.taskId); assert.equal(content(read).task.phase, 'queued');
  assert.equal(content(await f.tool('friday', 'bridge_read', { messageId: n.messageId })).expired, true);
  assert.equal(errorCode(await f.tool('friday', 'bridge_receipt_claim', { messageId: n.messageId })), 'message_authorization_inactive');
  const claim = content(await f.command('friday', f.update(command.taskId, 'friday', 'claim')));
  assert.equal(claim.phase, 'running');
  await f.command('friday', f.update(command.taskId, 'friday', 'progress', { ...fence(claim), checkpoint: 'Checkpoint persisted.' }));
  const result = content(await f.command('friday', f.update(command.taskId, 'friday', 'finish', {
    ...fence(claim), outcome: 'succeeded', result: 'Reported result.' })));
  assert.equal(result.phase, 'succeeded');
  await f.consume({ jobId: f.state().messages[result.noticeMessageId].jobIds[0] });
  const event = f.deliveries.at(-1).body;
  assert.equal(event.name, 'bridge.message.received'); assert.equal(event.data.messageId, result.noticeMessageId);
  const resolved = content(await f.tool('jarvis', 'bridge_task_from_notice', { messageId: event.data.messageId })).task;
  assert.equal(resolved.checkpoint.text, 'Checkpoint persisted.');
  assert.equal(resolved.result.text, 'Reported result.'); assert.equal(resolved.result.evidenceStatus, 'reported_not_independently_verified');
  assert.deepEqual(f.state().receipts, {});
});

test('actual v1 cleanup removes content/jobs but fresh verified MCP access resolves the original notice link', async () => {
  const f = await fixture(), command = f.create(), n = f.notice(); await f.command('jarvis', command, n);
  const stale = await f.token('friday', Object.values(SCOPES.friday), 1000);
  f.advance(CONTENT_RETENTION_MS + 1);
  await f.store.transaction(state => retainMessages(state, start + CONTENT_RETENTION_MS + 1)); f.restart();
  assert.equal(f.state().messages[n.messageId], undefined); assert.deepEqual(f.state().jobs, {});
  const denied = await f.tool('friday', 'bridge_task_from_notice', { messageId: n.messageId }, stale);
  assert.equal(denied.status, 401); assert.match(denied.headers.get('www-authenticate'), /resource_metadata=/);
  const read = await f.tool('friday', 'bridge_task_from_notice', { messageId: n.messageId }, await f.token('friday'));
  assert.equal(content(read).task.id, command.taskId); assert.equal(content(read).task.phase, 'queued');
  const before = f.state(), calls = f.calls.length;
  await f.command('jarvis', command, n);
  assert.deepEqual(f.state(), before); assert.equal(f.calls.length, calls);
});

for (const mode of ['beforeCommit', 'afterCommit']) {
  test(`${mode}: atomic task/notice rollback or committed retry survives restart without duplicate/renewal`, async () => {
    const f = await fixture(), command = f.create(), n = f.notice(); f.fault(mode, command, n);
    const failed = await f.command('jarvis', command, n);
    assert.equal(errorCode(failed), 'bridge_unavailable'); assert.doesNotMatch(JSON.stringify(failed), /PRIVATE_FIXTURE/);
    const saved = f.state().collaboration?.noticeLinks[n.messageId];
    if (mode === 'beforeCommit') {
      assert.equal(f.state().collaboration, undefined); assert.deepEqual(f.state().messages, {}); assert.deepEqual(f.state().jobs, {});
      await assert.rejects(f.consume({ dispatchMessageId: n.messageId }), /bridge_job_pending/);
    } else {
      assert.equal(f.calls.some(call => call.payload.jobId), false, 'MCP never reached postcommit scheduling');
      await f.consume({ dispatchMessageId: n.messageId });
      assert.equal(f.deliveries.length, 1, 'prearmed dispatch recovers committed notice without client retry');
    }
    f.advance(1000); f.restart();
    const retry = await f.command('jarvis', command, n); assert.equal(content(retry).phase, 'queued');
    const state = f.state();
    assert.equal(Object.keys(state.messages).length, 1); assert.equal(Object.keys(state.jobs).length, 1);
    assert.equal(Object.keys(state.collaboration.tasks).length, 1); assert.equal(Object.keys(state.collaboration.noticeLinks).length, 1);
    if (saved) assert.deepEqual(state.collaboration.noticeLinks[n.messageId], saved);
    const until = state.collaboration.noticeLinks[n.messageId].until;
    const originalExpiry = state.messages[n.messageId].envelope.expiresAt;
    const second = await f.command('jarvis', command, { ...n, expiresAt: new Date(start + 2 * hour).toISOString() });
    assert.equal(content(second).noticeMessageId, n.messageId);
    assert.equal(f.state().collaboration.noticeLinks[n.messageId].until, until);
    assert.equal(f.state().messages[n.messageId].envelope.expiresAt, originalExpiry);
    await f.consume({ dispatchMessageId: n.messageId }); await f.consume({ dispatchMessageId: n.messageId });
    assert.equal(f.deliveries.length, 1);
  });
}

test('prearm failure saves no task/content/jobs and exact retry uses existing v1 preparation', async () => {
  const f = await fixture(), command = f.create(), n = f.notice(); f.failPrearm();
  assert.equal(errorCode(await f.command('jarvis', command, n)), 'bridge_unavailable');
  assert.equal(f.state().collaboration, undefined); assert.deepEqual(f.state().messages, {}); assert.deepEqual(f.state().jobs, {});
  assert.ok(f.state().messagePreparations[n.messageId]);
  const retry = await f.command('jarvis', command, n); assert.equal(content(retry).phase, 'queued');
  assert.equal(f.state().probeAdmissions.jarvis.length, 1); assert.equal(Object.keys(f.state().jobs).length, 1);
});

for (const mode of ['beforeCommit', 'afterCommit']) test(`${mode}: launch intent, notice and replay launch suppression commit atomically`, async () => {
  const f = await fixture(), command = f.create(); await f.command('jarvis', command);
  const claim = content(await f.command('friday', f.update(command.taskId, 'friday', 'claim')));
  const operationId = randomUUID(), intent = f.update(command.taskId, 'friday', 'start', { ...fence(claim), operationId }), n = f.notice();
  f.fault(mode, intent, n);
  assert.equal(errorCode(await f.command('friday', intent, n)), 'bridge_unavailable');
  if (mode === 'beforeCommit') {
    assert.equal(f.state().collaboration.tasks[command.taskId].externalOperation, undefined);
    assert.equal(f.state().collaboration.noticeLinks[n.messageId], undefined);
    assert.equal(f.state().messages[n.messageId], undefined);
  } else assert.equal(f.state().collaboration.tasks[command.taskId].externalOperation.id, operationId);
  f.restart();
  const retry = content(await f.command('friday', intent, n));
  assert.equal(retry.operationRecorded, mode === 'beforeCommit');
  assert.equal(retry.noticeMessageId, n.messageId);
  const saved = f.state().collaboration;
  assert.equal(content(await f.command('friday', intent, n)).operationRecorded, false);
  assert.deepEqual(f.state().collaboration, saved);
});

test('concurrent duplicate commands keep one task/notice and changed notice IDs or command bodies conflict', async () => {
  const f = await fixture(), command = f.create(), n = f.notice();
  const replies = await Promise.all(Array.from({ length: 10 }, () => f.command('jarvis', command, n)));
  for (const reply of replies) assert.equal(content(reply).noticeMessageId, n.messageId);
  const before = f.state(), calls = f.calls.length;
  assert.equal(errorCode(await f.command('jarvis', command, f.notice())), 'task_notice_conflict');
  assert.equal(errorCode(await f.command('jarvis', { ...command, description: 'Changed.' }, n)), 'task_command_conflict');
  assert.deepEqual(f.state(), before); assert.equal(f.calls.length, calls);
  assert.equal(Object.keys(before.messages).length, 1); assert.equal(Object.keys(before.jobs).length, 1);
});

test('full v1 admission still enforces scope, return path, lifetime, capacity, canary and rate gates', async () => {
  for (const scenario of ['scope', 'return_path', 'lifetime', 'capacity', 'canary']) {
    const f = await fixture({ subscribe: scenario !== 'return_path' }), command = f.create();
    let n = f.notice(), bearer;
    if (scenario === 'scope') bearer = await f.token('jarvis', [SCOPES.jarvis.ack]);
    if (scenario === 'lifetime') n = f.notice({ expiresAt: new Date(start + hour + 1).toISOString() });
    if (scenario === 'capacity') await f.store.transaction(state => {
      for (let i = 0; i < 100; i++) state.messages[`capacity-fixture-${i}`] = {
        envelope: { protocol: 'jarvis-friday/1', kind: 'status' }, retainUntil: start + hour };
    });
    if (scenario === 'canary') f.bridge.canary = { messageId: randomUUID(), subscriptionId: 'sub_' + 'c'.repeat(64),
      from: start, until: start + 60000 };
    const before = f.state(), response = await f.command('jarvis', command, n, bearer);
    assert.equal(errorCode(response), { scope: 'insufficient_scope', return_path: 'return_subscription_required',
      lifetime: 'invalid_message_lifetime', capacity: 'message_capacity_reached', canary: 'friday_canary_only' }[scenario]);
    assert.deepEqual(f.state(), before); assert.equal(f.calls.length, 0);
  }
  const f = await fixture();
  for (let i = 0; i < 10; i++) assert.equal(content(await f.command('jarvis', f.create())).phase, 'queued');
  const before = f.state(), calls = f.calls.length;
  assert.equal(errorCode(await f.command('jarvis', f.create())), 'message_rate_limited');
  assert.deepEqual(f.state(), before); assert.equal(f.calls.length, calls);
});

test('return-path withdrawal after prearm rolls back final task/notice mutation', async () => {
  const f = await fixture(), command = f.create(), n = f.notice();
  f.afterDispatch(async () => f.store.transaction(state => {
    for (const subscription of Object.values(state.subscriptions)) subscription.active = false;
  }));
  assert.equal(errorCode(await f.command('jarvis', command, n)), 'return_subscription_required');
  assert.equal(f.state().collaboration, undefined); assert.deepEqual(f.state().messages, {}); assert.deepEqual(f.state().jobs, {});
  assert.ok(f.state().messagePreparations[n.messageId]);
});

test('task admission denial precedes prearm; cancellation and mutex crash fence stale reports through MCP', async () => {
  const f = await fixture(), command = f.create(); await f.command('jarvis', command);
  const old = content(await f.command('friday', f.update(command.taskId, 'friday', 'claim')));
  await f.command('friday', f.update(command.taskId, 'friday', 'progress', { ...fence(old), checkpoint: 'Before crash.' }));
  f.advance(60001); f.restart();
  assert.equal(errorCode(await f.command('friday', f.update(command.taskId, 'friday', 'claim', {
    expectedRevision: content(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId })).revision }))), 'task_reconciliation_required');
  await f.command('jarvis', f.update(command.taskId, 'jarvis', 'assign', { assignee: 'friday' }));
  const fresh = content(await f.command('friday', f.update(command.taskId, 'friday', 'claim', {
    expectedRevision: content(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId })).revision })));
  assert.ok(fresh.epoch > old.epoch);
  const before = f.state(), calls = f.calls.length;
  assert.equal(errorCode(await f.command('friday', f.update(command.taskId, 'friday', 'finish', {
    ...fence(old), outcome: 'succeeded', result: 'Stale.' }))), 'stale_task_attempt');
  assert.deepEqual(f.state(), before); assert.equal(f.calls.length, calls);
  await f.command('jarvis', f.update(command.taskId, 'jarvis', 'cancel'));
  assert.equal(errorCode(await f.command('friday', f.update(command.taskId, 'friday', 'finish', {
    ...fence(fresh), outcome: 'succeeded', result: 'Late.' }))), 'task_terminal');
  const task = content(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId }));
  assert.equal(task.phase, 'cancelled'); assert.equal(task.checkpoint.text, 'Before crash.'); assert.equal(task.result, null);
  const saved = f.state(), count = f.calls.length; f.denyData();
  assert.equal(errorCode(await f.command('jarvis', f.create())), 'task_access_denied');
  assert.equal(errorCode(await f.tool('friday', 'bridge_task_from_notice', {
    messageId: Object.keys(saved.collaboration.noticeLinks)[0] })), 'task_access_denied');
  assert.deepEqual(f.state(), saved); assert.equal(f.calls.length, count);
});

test('opt-in terminal cleanup frees task capacity through MCP and preserves old-ID replay fences', async () => {
  const f = await fixture({ retention: { terminalMs: 24 * hour, tombstoneMs: 7 * 24 * hour,
    creationWindowMs: 300000, batchSize: 100, maxTombstones: 1000 } });
  const timed = () => {
    const stamp = (start + elapsed).toString(16).padStart(12, '0'), random = randomUUID();
    return `${stamp.slice(0, 8)}-${stamp.slice(8)}-7${random.slice(15, 18)}-${random.slice(19)}`;
  };
  let elapsed = 0;
  const old = f.create({ taskId: timed() }), n = f.notice();
  await f.command('jarvis', old, n);
  await f.command('jarvis', f.update(old.taskId, 'jarvis', 'cancel'));
  const active = f.create({ taskId: timed() }); await f.command('jarvis', active);
  f.advance(49 * hour); elapsed += 49 * hour; f.restart();
  const next = f.create({ taskId: timed() });
  assert.equal(content(await f.command('jarvis', next)).phase, 'queued');
  const data = f.state().collaboration;
  assert.equal(data.tasks[old.taskId], undefined); assert.equal(data.retiredTasks[old.taskId].phase, 'cancelled');
  assert.ok(data.tasks[active.taskId]); assert.equal(data.tasks[active.taskId].phase, 'queued');
  assert.equal(errorCode(await f.tool('friday', 'bridge_task_from_notice', { messageId: n.messageId })), 'task_notice_not_found');
  assert.equal(errorCode(await f.tool('jarvis', 'bridge_task_get', { taskId: old.taskId })), 'task_retired');
  const calls = f.calls.length;
  assert.equal(errorCode(await f.command('jarvis', old, n)), 'task_retired'); assert.equal(f.calls.length, calls);
  f.advance(7 * 24 * hour); elapsed += 7 * 24 * hour;
  const freshToken = await f.token('jarvis');
  // Operator-only synthetic cleanup, followed by fresh local verified access.
  await f.store.transaction(state => f.kernel.retention.run(state, start + elapsed, ownerKey));
  assert.equal(f.state().collaboration.retiredTasks[old.taskId], undefined);
  const before = f.calls.length;
  assert.equal(errorCode(await f.command('jarvis', { ...old, deadline: start + elapsed + hour }, n, freshToken)),
    'task_id_outside_creation_window');
  assert.equal(f.calls.length, before); assert.equal(f.state().collaboration.tasks[old.taskId], undefined);
});

test('one-item cleanup batches make progress at full notice capacity before prearm/final insertion', async () => {
  const f = await fixture({ retention: { terminalMs: 24 * hour, tombstoneMs: 7 * 24 * hour,
    creationWindowMs: 300000, batchSize: 1, maxTombstones: 1000 }, maxLinks: 2 });
  const timed = when => {
    const stamp = when.toString(16).padStart(12, '0'), random = randomUUID();
    return `${stamp.slice(0, 8)}-${stamp.slice(8)}-7${random.slice(15, 18)}-${random.slice(19)}`;
  };
  const first = f.create({ taskId: timed(start) });
  await f.command('jarvis', first); await f.command('jarvis', f.update(first.taskId, 'jarvis', 'cancel'));
  assert.equal(Object.keys(f.state().collaboration.noticeLinks).length, 2);
  f.advance(49 * hour);
  const next = f.create({ taskId: timed(start + 49 * hour) });
  assert.equal(content(await f.command('jarvis', next)).phase, 'queued');
  assert.equal(Object.keys(f.state().collaboration.noticeLinks).length, 1);
  assert.equal(f.state().collaboration.tasks[first.taskId].phase, 'cancelled');
  assert.equal(f.state().collaboration.tasks[next.taskId].phase, 'queued');
});
