import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createTaskAccess } from '../src/task-access.ts';
import { createTaskCapability } from '../src/task-capability.ts';
import { TaskKernel } from '../src/tasks.ts';
import { TaskIntegration } from '../src/task-integration.ts';
import { MemoryStore, emptyState } from '../src/store.ts';
import { Bridge } from '../src/bridge.ts';
import { NativeEvents } from '../src/events.ts';
import { createProtector } from '../src/webhook.ts';
import { createMcpHandler } from '../src/mcp.ts';
import { authorizationPolicyId, createAccessVerifier, SCOPES, VERIFIED_AUTHORIZATION } from '../src/policy.ts';
import { resourceFor } from '../src/resource.ts';
import { ISSUER } from './fixtures/provider.ts';
import type { BridgeError } from '../src/policy.ts';
import type { TaskLimits } from '../src/tasks.ts';
import type { TaskAccessDecision, TaskAccessPolicy, TaskAccessRequest } from '../src/task-access.ts';
import type { TaskAccessGrant } from '../src/tasks.ts';
import type { TaskCapabilityOptions } from '../src/task-capability.ts';
import type { McpTasks } from '../src/mcp.ts';
import type { TransportRequest, TransportResponse } from '../src/webhook.ts';
import type { BridgeState, Principal, ResourceDenial, Transition } from '../src/types.ts';
import type { RpcReply, RpcResponse, TaskToolOutput, ToolCallResult } from './types.ts';

interface SignOptions { owner?: string; issuer?: string; scopes?: string[]; ttl?: number; claim?: string }

const start = Date.UTC(2026, 9, 24), hour = 3600000, subject = 'offline-task-access-owner';
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const policy = { issuer: ISSUER, subjectHash: digest(subject) };
const code = (expected: string) => (error: BridgeError) => error.code === expected;
const data = (response: RpcReply) => response.result?.structuredContent;
const errorCode = (response: RpcReply) => response.error?.message || data(response)?.error;

// Synthetic issuer/owner/keypair only. Real local resource verification and
// release factory; never reads credentials, changes grants or calls a network.
async function fixture({ limits, maxLinks }: { limits?: Partial<TaskLimits>; maxLinks?: number } = {}) {
  let now = start, locked: BridgeState | undefined, afterPrepare: ((id: string) => unknown) | undefined;
  const inner = new MemoryStore(), prepared: string[] = [], scheduled: string[] = [], decisions: string[] = [];
  const store = { transaction: <T>(operation: Transition<T>) => inner.transaction(state => {
    locked = state;
    try { return operation(state); } finally { locked = undefined; }
  }) };
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const clock = () => now;
  const sign = (role: string, { owner = subject, issuer = ISSUER, scopes = Object.values(SCOPES[role]!), ttl = 96 * hour,
    claim = 'scope' }: SignOptions = {}) => new SignJWT({ [claim]: scopes.join(' ') }).setProtectedHeader({ alg: 'RS256' })
    .setIssuer(issuer).setSubject(owner).setAudience(resourceFor(role)).setIssuedAt(Math.floor(now / 1000))
    .setExpirationTime((now + ttl) / 1000).sign(privateKey);
  const verify = (role: string, config: { issuer: string; subject?: string; subjectHash?: string; scopeClaim?: string } = policy) => createAccessVerifier({ ...config, role, audience: resourceFor(role),
    keyResolver: publicKey, currentDate: new Date(now) });
  const request = (role: string, token: string, body?: object) => new Request(resourceFor(role), { method: 'POST', headers: {
    authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  const principal = async (role: string, options: SignOptions = {}) => verify(role, { issuer: options.issuer || ISSUER,
    subjectHash: digest(options.owner || subject), scopeClaim: options.claim || 'scope' })(request(role, await sign(role, options)));
  const tokens: Record<string, string> = { jarvis: await sign('jarvis'), friday: await sign('friday') };
  const policies = Object.fromEntries(['jarvis', 'friday'].map(role => [role,
    authorizationPolicyId({ ...policy, role, audience: resourceFor(role) })]));
  const events = new NativeEvents({ store, clock, enabled: true, policyId: policies.jarvis,
    protector: createProtector(randomBytes(32)), transport: async (_url: string, req: TransportRequest): Promise<TransportResponse> => ({ status: 200,
      body: JSON.stringify({ challenge: JSON.parse(req.body).challenge }) }) });
  const bridge = new Bridge({ store, clock, dailyEnabled: true, messagePolicyIds: policies,
    prepareMessage: async (id: string) => { prepared.push(id); await afterPrepare?.(id); } });
  const tasks = createTaskCapability({ enabled: true, store, bridge, policy, clock, leaseMs: 60000,
    linkRetentionMs: 48 * hour, limits, maxLinks });
  const actual = tasks.kernel.authorize;
  tasks.kernel.authorize = (p, r, time, state) => {
    assert.ok(locked, 'admission runs inside the transaction');
    // Preview uses a disposable clone; final mutation/read uses the locked row.
    // Both must contain this transaction's current denial fences, never a cache.
    assert.deepEqual(state, locked);
    decisions.push(r!.operation!); return actual!(p, r, time, state);
  };
  const handler = (role: string) => createMcpHandler({ enabled: true, bridge, events, tasks: tasks as McpTasks, verify: req => verify(role)(req),
    scheduleJobs: async (ids: string[]) => { scheduled.push(...ids); }, health: () => ({}) });
  const rpc = async (role: string, method: string, params?: object, token = tokens[role]!): Promise<RpcReply> => {
    const response = await handler(role)(request(role, token, { jsonrpc: '2.0', id: 1, method, params }));
    return { status: response.status, ...await response.json() as RpcResponse<ToolCallResult<TaskToolOutput>> };
  };
  const tool = (role: string, name: string, args: object, token?: string) => rpc(role, 'tools/call', { name, arguments: args }, token);
  await rpc('jarvis', 'events/subscribe', { name: 'bridge.message.received', arguments: { recipient: 'jarvis' }, ttlMs: null,
    delivery: { mode: 'webhook', url: 'https://callback.example.test/access-fixture',
      secret: 'whsec_' + randomBytes(32).toString('base64') } });
  const create = (extra: Record<string, unknown> = {}) => ({ operation: 'create', taskId: randomUUID(), commandId: randomUUID(), sequence: 1,
    assignee: 'friday', description: 'Synthetic data coordination.', deadline: now + 72 * hour, ...extra });
  const notice = () => ({ messageId: randomUUID(), sentAt: new Date(now).toISOString(), expiresAt: new Date(now + hour).toISOString() });
  const update = (taskId: string, role: string, operation: string, extra: Record<string, unknown> = {}) => {
    const task = inner.snapshot().collaboration!.tasks[taskId];
    return { operation, taskId, commandId: randomUUID(), sequence: (task!.commands[role]?.through || 0) + 1,
      expectedRevision: task!.revision, ...extra };
  };
  return { store, bridge, tasks, principal, sign, create, notice, update, tool, rpc, clock, prepared, scheduled, decisions,
    state: () => inner.snapshot(), advance: (ms: number) => { now += ms; }, afterPrepare: (fn: (id: string) => unknown) => { afterPrepare = fn; },
    deny: (p: Principal) => store.transaction(state => { (state.resourceDenials ||= {})[p.principalKey] = { status: 'denied' } as ResourceDenial; }),
    command: (role: string, command: object, n: object = notice(), token?: string) => tool(role, 'bridge_task_command', { command, notice: n }, token),
  };
}

test('release factory is default-off and rejects independent permanent-purge activation', async () => {
  assert.equal(createTaskCapability().enabled, false);
  const f = await fixture(), config = { enabled: true, store: f.store, bridge: f.bridge, policy,
    clock: f.clock, leaseMs: 60000, linkRetentionMs: hour };
  // Deliberately invalid purge/retention activations.
  for (const settings of [{ purgeEnabled: true }, { purgeEnabled: 'false' }, { retention: {} }])
    assert.throws(() => createTaskCapability({ ...config, ...settings } as TaskCapabilityOptions), code('task_purge_not_enabled'));
  assert.equal(f.tasks.kernel.retention, null); assert.equal(f.tasks.options.pruneExpiredLinks, false);
  const retention = { terminalMs: 1, tombstoneMs: 1, creationWindowMs: 1 };
  const experimental = new TaskKernel({ store: f.store, clock: f.clock, leaseMs: 1,
    authorize: createTaskAccess(policy), retention });
  assert.throws(() => new TaskIntegration({ enabled: true, kernel: experimental, bridge: f.bridge, linkRetentionMs: hour }),
    code('task_purge_not_enabled'));
});

test('release factory refuses mismatched delivery policy or an absent native prearm hook', async () => {
  const f = await fixture(), config = { enabled: true, store: f.store, policy, clock: f.clock,
    leaseMs: 60000, linkRetentionMs: hour };
  const wrong = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true,
    messagePolicyIds: { ...f.bridge.messagePolicyIds, friday: 'f'.repeat(64) }, prepareMessage: async () => {} });
  assert.throws(() => createTaskCapability({ ...config, bridge: wrong }), code('task_bridge_policy_mismatch'));
  const missing = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true, messagePolicyIds: f.bridge.messagePolicyIds });
  assert.throws(() => createTaskCapability({ ...config, bridge: missing }), code('task_bridge_configuration_required'));
});

test('shared owner is derived solely from trusted issuer/pin, not role-specific principal keys or request identity', async () => {
  const f = await fixture(), jarvis = await f.principal('jarvis'), friday = await f.principal('friday');
  const hashed = createTaskAccess(policy), raw = createTaskAccess({ issuer: ISSUER, subject });
  // A request-supplied owner key is ignored; both decisions are grants.
  const a = hashed(jarvis, { operation: 'create', ownerKey: 'b'.repeat(64) } as TaskAccessRequest, start, emptyState()) as TaskAccessGrant;
  const b = hashed(friday, { operation: 'create' }, start, emptyState()) as TaskAccessGrant;
  assert.notEqual(jarvis.principalKey, friday.principalKey); assert.equal(a.ownerKey, b.ownerKey);
  assert.equal(a.ownerKey, (raw(jarvis, { operation: 'read' }, start, emptyState()) as TaskAccessGrant).ownerKey);
  assert.equal(a.ownerKey, digest(JSON.stringify(['bridge-task-owner/v1', ISSUER, policy.subjectHash])));
  assert.equal(a.coordinate, true); assert.equal(b.coordinate, true);
  const other = await f.principal('jarvis', { owner: 'other-offline-owner' });
  const config = { issuer: ISSUER, subjectHash: digest('other-offline-owner') };
  assert.notEqual((createTaskAccess(config)(other, { operation: 'read' }, start, emptyState()) as TaskAccessGrant).ownerKey, a.ownerKey);
  for (const bad of [{}, { ...policy, subject }, { ...policy, issuer: 'http://fixture.invalid' },
    { ...policy, scopeClaim: 'arbitrary' }, { ...policy, subjectHash: 'x' }])
    assert.throws(() => createTaskAccess(bad), code('task_access_configuration_required'));
});

test('existing ACK admits reads; every command/replay needs ACK plus the current directional SEND', async () => {
  const f = await fixture(), admit = createTaskAccess(policy), state = emptyState();
  for (const role of ['jarvis', 'friday']) {
    const ack = await f.principal(role, { scopes: [SCOPES[role]!.ack] });
    const send = await f.principal(role, { scopes: [SCOPES[role]!.probe] });
    const both = await f.principal(role);
    assert.equal(admit(ack, { operation: 'read' }, start, state).dataAllowed, true);
    assert.equal(admit(send, { operation: 'read' }, start, state).dataAllowed, false);
    for (const operation of ['create', 'assign', 'claim', 'progress', 'finish', 'block', 'cancel', 'start', 'reconcile']) {
      assert.equal(admit(ack, { operation }, start, state).dataAllowed, false);
      assert.equal(admit(send, { operation }, start, state).dataAllowed, false);
      assert.equal(admit(both, { operation }, start, state).dataAllowed, true);
    }
    assert.equal(admit(both, { operation: 'unknown' }, start, state).dataAllowed, false);
  }
});

test('long-run reconciliation uses fresh verified access and final-transaction expiry/denial fences', async () => {
  for (const mode of ['fresh', 'scope', 'expires_during_prearm', 'denied_during_prearm']) {
    const f = await fixture(), command = f.create(); await f.command('jarvis', command);
    const claim = data(await f.command('friday', f.update(command.taskId, 'friday', 'claim'))), operationId = randomUUID();
    await f.command('friday', f.update(command.taskId, 'friday', 'start', { attemptId: claim!.attemptId, epoch: claim!.epoch, operationId }));
    const expired = await f.sign('friday', { ttl: 1000 }); f.advance(2 * 60000);
    assert.equal(errorCode(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId }, expired)), 'unauthorized');
    assert.equal(data(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId }, await f.sign('friday')))!.phase, 'reconciliation_required');
    const reconcile = f.update(command.taskId, 'friday', 'reconcile', { operationId, runRef: 'synthetic-access-existing-run',
      outcome: 'succeeded', evidence: 'The synthetic workflow queried its existing run.', result: 'Existing result.' });
    const before = f.state(), token = await f.sign('friday', mode === 'scope' ? { scopes: [SCOPES.friday!.ack] }
      : mode === 'expires_during_prearm' ? { ttl: 1000 } : {});
    if (mode === 'expires_during_prearm') f.afterPrepare(async () => f.advance(2000));
    if (mode === 'denied_during_prearm') {
      const principal = await f.principal('friday'); f.afterPrepare(() => f.deny(principal));
    }
    const result = await f.command('friday', reconcile, f.notice(), token);
    if (mode === 'fresh') assert.equal(data(result)!.phase, 'succeeded');
    else {
      assert.equal(errorCode(result), 'task_access_denied');
      assert.deepEqual(f.state().collaboration, before.collaboration, 'rejected reconciliation preserves operation/result/sequence/links');
    }
  }
});

test('crossed role/owner/current policy, missing transaction state and expired proof all fail closed', async () => {
  const f = await fixture(), admit = createTaskAccess(policy), state = emptyState(), p = await f.principal('jarvis');
  const swapped = Object.defineProperty({ ...p, role: 'friday' }, VERIFIED_AUTHORIZATION,
    { value: p[VERIFIED_AUTHORIZATION] });
  const missing = { ...p };
  for (const bad of [swapped, missing, await f.principal('jarvis', { owner: 'other-offline-owner' }),
    await f.principal('jarvis', { issuer: 'https://other.example.test' }), await f.principal('jarvis', { claim: 'scp' }),
    { role: 'toString', principalKey: p.principalKey, scopes: p.scopes }])
    assert.equal(admit(bad, { operation: 'read' }, start, state).dataAllowed, false);
  assert.equal(admit(p, { operation: 'read' }, start).dataAllowed, false);
  assert.equal(admit(p, { operation: 'read' }, NaN, state).dataAllowed, false);
  assert.equal(admit(p, { operation: 'read' }, p[VERIFIED_AUTHORIZATION].expiresAt, state).dataAllowed, false);
  assert.equal(admit(p, { operation: 'read' }, start, { ...state, resourceDenials: [] } as unknown as BridgeState).dataAllowed, false);
});

test('both real local resource principals coordinate one task through the release factory; wrong recipient is hidden', async () => {
  const f = await fixture(), command = f.create(), n = f.notice();
  const created = data(await f.command('jarvis', command, n)); assert.equal(created!.phase, 'queued');
  assert.equal(errorCode(await f.tool('jarvis', 'bridge_task_from_notice', { messageId: n.messageId })), 'task_notice_not_found');
  const read = data(await f.tool('friday', 'bridge_task_from_notice', { messageId: n.messageId },
    await f.sign('friday', { scopes: [SCOPES.friday!.ack] })));
  assert.equal(read!.task!.id, command.taskId);
  const attempt = data(await f.command('friday', f.update(command.taskId, 'friday', 'claim')));
  assert.equal(attempt!.phase, 'running');
  const fence = { attemptId: attempt!.attemptId, epoch: attempt!.epoch };
  await f.command('friday', f.update(command.taskId, 'friday', 'progress', { ...fence, checkpoint: 'Verified context checkpoint.' }));
  const finished = data(await f.command('friday', f.update(command.taskId, 'friday', 'finish', {
    ...fence, outcome: 'succeeded', result: 'Reported fixture result.' })));
  const final = data(await f.tool('jarvis', 'bridge_task_from_notice', { messageId: finished!.noticeMessageId }))!.task;
  assert.equal(final!.result!.evidenceStatus, 'reported_not_independently_verified');
  assert.equal(final!.checkpoint!.text, 'Verified context checkpoint.'); assert.deepEqual(f.state().receipts, {});
  const before = f.state();
  assert.equal(errorCode(await f.tool('friday', 'bridge_task_from_notice', { messageId: randomUUID() })), 'task_notice_not_found');
  assert.deepEqual(f.state(), before); assert.ok(f.decisions.includes('read') && f.decisions.includes('finish'));
});

test('Friday can coordinate the reverse assignment while stored coordinator and assignee checks stay intact', async () => {
  const f = await fixture(), command = f.create({ assignee: 'jarvis' }), n = f.notice();
  assert.equal(data(await f.command('friday', command, n))!.phase, 'queued');
  assert.equal(data(await f.tool('jarvis', 'bridge_task_from_notice', { messageId: n.messageId }))!.task!.coordinator, 'friday');
  const before = f.state();
  assert.equal(errorCode(await f.command('jarvis', f.update(command.taskId, 'jarvis', 'cancel'))), 'task_coordinator_required');
  assert.deepEqual(f.state(), before);
  const attempt = data(await f.command('jarvis', f.update(command.taskId, 'jarvis', 'claim')));
  const fence = { attemptId: attempt!.attemptId, epoch: attempt!.epoch };
  assert.equal(errorCode(await f.command('friday', f.update(command.taskId, 'friday', 'finish', {
    ...fence, outcome: 'succeeded', result: 'Wrong assignee.' }))), 'task_assignee_required');
  const result = data(await f.command('jarvis', f.update(command.taskId, 'jarvis', 'finish', {
    ...fence, outcome: 'succeeded', result: 'Jarvis report.' })));
  const read = data(await f.tool('friday', 'bridge_task_from_notice', { messageId: result!.noticeMessageId }))!.task;
  assert.equal(read!.phase, 'succeeded'); assert.equal(read!.result!.text, 'Jarvis report.');
});

test('no tool identity fields can select an owner or bypass the native resource verifier', async () => {
  const f = await fixture(), command = f.create(), n = f.notice(), before = f.state();
  assert.equal(errorCode(await f.command('jarvis', { ...command, ownerKey: 'b'.repeat(64) }, n)), 'invalid_task_command');
  assert.equal(errorCode(await f.tool('jarvis', 'bridge_task_command', {
    command, notice: n, policy: { subjectHash: digest('other-offline-owner') } })), 'invalid_params');
  const wrongOwner = await f.sign('jarvis', { owner: 'other-offline-owner' });
  assert.equal(errorCode(await f.command('jarvis', command, n, wrongOwner)), 'forbidden_subject');
  assert.equal(errorCode(await f.command('jarvis', command, n, await f.sign('friday'))), 'unauthorized');
  assert.deepEqual(f.state(), before); assert.equal(f.prepared.length, 0);
});

test('configured owner rotation cannot read or mutate another owner retained record', async () => {
  const f = await fixture(), command = f.create(); await f.command('jarvis', command);
  const nextPolicy = { issuer: ISSUER, subjectHash: digest('other-offline-owner') };
  const nextBridge = new Bridge({ store: f.store, clock: f.clock, dailyEnabled: true, prepareMessage: f.bridge.prepareMessage,
    messagePolicyIds: Object.fromEntries(['jarvis', 'friday'].map(role => [role,
      authorizationPolicyId({ ...nextPolicy, role, audience: resourceFor(role) })])) });
  const next = createTaskCapability({ enabled: true, store: f.store, bridge: nextBridge, policy: nextPolicy,
    clock: f.clock, leaseMs: 60000, linkRetentionMs: hour });
  const other = await f.principal('jarvis', { owner: 'other-offline-owner' }), before = f.state();
  await assert.rejects(next.get(other, { taskId: command.taskId }), code('task_not_found'));
  await assert.rejects(next.apply(other, { command, notice: f.notice() }), code('task_not_found'));
  assert.deepEqual(f.state(), before);
});

test('denial between prearm and final insertion is checked under final transaction before task/notice commit', async () => {
  const f = await fixture(), actor = await f.principal('friday'), command = f.create({ assignee: 'jarvis' }), n = f.notice();
  f.afterPrepare(() => f.deny(actor));
  const response = await f.command('friday', command, n);
  assert.equal(errorCode(response), 'task_access_denied'); assert.equal(response.status, 403);
  assert.equal(f.prepared.length, 1); assert.equal(f.state().collaboration, undefined);
  assert.deepEqual(f.state().messages, {}); assert.deepEqual(f.state().jobs, {});
  assert.ok(f.state().messagePreparations![n.messageId]);
});

test('token proof expiring during prearm rejects final mutation even after initial verification', async () => {
  const f = await fixture(), command = f.create({ assignee: 'jarvis' });
  f.afterPrepare(() => { f.advance(1000); });
  assert.equal(errorCode(await f.command('friday', command, f.notice(), await f.sign('friday', { ttl: 1000 }))), 'task_access_denied');
  assert.equal(f.state().collaboration, undefined); assert.deepEqual(f.state().messages, {});
});

test('cached replay rechecks scope/expiry/denial and cannot reschedule work through revoked access', async () => {
  const f = await fixture(), command = f.create(), n = f.notice();
  const first = data(await f.command('jarvis', command, n)), prepared = f.prepared.length;
  assert.equal(data(await f.command('jarvis', command, n))!.noticeMessageId, first!.noticeMessageId);
  assert.equal(f.prepared.length, prepared);
  const before = f.state(), scheduled = f.scheduled.length;
  assert.equal(errorCode(await f.command('jarvis', command, n, await f.sign('jarvis', { scopes: [SCOPES.jarvis!.ack] }))), 'task_access_denied');
  assert.deepEqual(f.state(), before); assert.equal(f.scheduled.length, scheduled);
  const short = await f.sign('jarvis', { ttl: 1000 }); f.advance(1000);
  assert.equal(errorCode(await f.command('jarvis', command, n, short)), 'unauthorized');
  const p = await f.principal('jarvis'); await f.deny(p); const denied = f.state();
  assert.equal(errorCode(await f.command('jarvis', command, n)), 'task_access_denied');
  assert.equal(errorCode(await f.tool('jarvis', 'bridge_task_get', { taskId: command.taskId })), 'task_access_denied');
  assert.equal(errorCode(await f.tool('jarvis', 'bridge_task_from_notice', { messageId: randomUUID() })), 'task_access_denied');
  assert.deepEqual(f.state(), denied); assert.equal(f.scheduled.length, scheduled);
  assert.equal(data(await f.tool('friday', 'bridge_task_get', { taskId: command.taskId }))!.id, command.taskId,
    'existing resource-local denial is not silently converted into global owner revocation');
});

test('purge-off candidate retains terminal records/expired links and blocks at finite capacity', async () => {
  const f = await fixture({ limits: { tasks: 1 } }), command = f.create(), n = f.notice();
  await f.command('jarvis', command, n); await f.command('jarvis', f.update(command.taskId, 'jarvis', 'cancel'));
  f.advance(49 * hour); const before = f.state().collaboration;
  assert.equal(errorCode(await f.tool('friday', 'bridge_task_from_notice', { messageId: n.messageId })), 'task_notice_not_found');
  assert.deepEqual(f.state().collaboration, before, 'logical alias expiry does not physically purge it');
  assert.equal(errorCode(await f.command('jarvis', f.create())), 'task_capacity_reached');
  assert.deepEqual(f.state().collaboration, before);
  assert.equal(data(await f.tool('jarvis', 'bridge_task_get', { taskId: command.taskId }))!.phase, 'cancelled');
  assert.equal(f.state().collaboration!.taskIdentity, undefined); assert.equal(f.state().collaboration!.retiredTasks, undefined);
});

test('purge-off link pressure preserves active state and reserved terminal-notice capacity', async () => {
  const f = await fixture({ maxLinks: 2 }), command = f.create(); await f.command('jarvis', command);
  const before = f.state().collaboration;
  assert.equal(errorCode(await f.command('friday', f.update(command.taskId, 'friday', 'claim'))), 'task_notice_capacity_reached');
  assert.deepEqual(f.state().collaboration, before); assert.equal(before!.tasks[command.taskId]!.phase, 'queued');
  assert.equal(data(await f.command('jarvis', f.update(command.taskId, 'jarvis', 'cancel')))!.phase, 'cancelled');
  assert.equal(Object.keys(f.state().collaboration!.noticeLinks!).length, 2);
});
