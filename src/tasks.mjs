import { createHash, randomUUID } from 'node:crypto';
import { BridgeError } from './policy.mjs';
import { TaskRetention, checkNewTaskId, checkTaskClock, retiredTask } from './task-retention.mjs';
import { PEER_IDS } from './config.mjs';

// Task DATA kernel. The default production runtime does not construct it;
// explicit trusted assembly is required. No execution adapter, timer or sender.
// The injected callback admits DATA access only. Claims are coordination
// mutexes and results are reports, never permission/proof of external work.
const terminal = phase => ['succeeded', 'failed', 'cancelled', 'expired'].includes(phase);
const roles = PEER_IDS;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const id = value => typeof value === 'string' && uuid.test(value);
const caps = { tasks: 100, bytes: 1048576, taskBytes: 16384, replay: 32 };
const terminalReserve = 4096;
const fail = (code, status = 409) => { throw new BridgeError(code, status); };
const integer = value => Number.isSafeInteger(value) && value >= 1;
const bytes = value => Buffer.byteLength(JSON.stringify(value));
function shape(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail('invalid_task_command', 400);
}
function text(value, limit) {
  if (typeof value !== 'string' || !value.trim() || bytes(value) > limit) fail('invalid_task_command', 400);
}
function command(input) {
  const definitions = {
    create: ['assignee', 'description', 'deadline'], assign: ['assignee'], claim: [],
    progress: ['attemptId', 'epoch', 'checkpoint'], finish: ['attemptId', 'epoch', 'outcome', 'result'],
    block: ['attemptId', 'epoch', 'reason'], cancel: [],
    start: ['attemptId', 'epoch', 'operationId'],
    reconcile: ['operationId', 'runRef', 'outcome', 'evidence', 'result'],
  };
  if (typeof input?.operation !== 'string' || !Object.hasOwn(definitions, input.operation)) fail('invalid_task_command', 400);
  const fields = definitions[input.operation];
  const keys = ['operation', 'taskId', 'commandId', 'sequence', ...(input.operation === 'create' ? [] : ['expectedRevision']), ...fields];
  shape(input, keys);
  if (!id(input.taskId) || !id(input.commandId) || !integer(input.sequence) ||
      (input.operation !== 'create' && !integer(input.expectedRevision))) fail('invalid_task_command', 400);
  if (['create', 'assign'].includes(input.operation) && !roles.includes(input.assignee)) fail('invalid_task_command', 400);
  if (input.operation === 'create') {
    text(input.description, 4096);
    if (!integer(input.deadline)) fail('invalid_task_command', 400);
  }
  if (['progress', 'finish', 'block', 'start'].includes(input.operation) &&
      (!id(input.attemptId) || !integer(input.epoch))) fail('invalid_task_command', 400);
  if (['start', 'reconcile'].includes(input.operation) && !id(input.operationId)) fail('invalid_task_command', 400);
  if (input.operation === 'reconcile') {
    if (!['running', 'unknown', 'succeeded', 'failed'].includes(input.outcome) ||
        (input.runRef === null && input.outcome !== 'unknown')) fail('invalid_task_command', 400);
    if (input.runRef !== null) text(input.runRef, 256);
    text(input.evidence, 1024); text(input.result, 2048);
  }
  if (input.operation === 'progress') text(input.checkpoint, 2048);
  if (input.operation === 'finish') {
    if (!['succeeded', 'failed'].includes(input.outcome)) fail('invalid_task_command', 400);
    text(input.result, 2048);
  }
  if (input.operation === 'block' && !['waiting_dependency', 'outcome_unknown', 'capability_missing'].includes(input.reason))
    fail('invalid_task_command', 400);
  // Fixed field ordering makes property-order-only retransmissions identical.
  return Object.fromEntries(keys.map(key => [key, input[key]]));
}
function collection(state) {
  const value = state.collaboration;
  if (value && (value.version !== 1 || !value.tasks || typeof value.tasks !== 'object' || Array.isArray(value.tasks)))
    fail('task_storage_version_mismatch', 503);
  return value;
}
function stop(task, phase, reason, now) {
  task.phase = phase; task.blockedReason = reason; task.lease = null;
  task.epoch++; task.revision++; task.updatedAt = now;
}
function normalize(task, now) {
  if (terminal(task.phase)) return;
  if (now >= task.deadline) stop(task, 'expired', 'coordination_deadline', now);
  else if (task.phase === 'running' && task.lease.until <= now)
    stop(task, 'reconciliation_required', 'lease_lost', now);
}
function output(task) {
  return { taskId: task.id, revision: task.revision, phase: task.phase, epoch: task.epoch,
    ...(task.externalOperation ? { operationId: task.externalOperation.id } : {}),
    ...(task.lease ? { attemptId: task.lease.id, leaseUntil: task.lease.until } : {}) };
}
function view(task, role, commandId) {
  const { commands, ...safe } = task;
  const history = commands[role], next = (history?.through || 0) + 1;
  const entry = commandId === undefined ? undefined : history?.recent.find(item => item.id === commandId);
  // Expose one caller-owned cached receipt, never peer journals or payloads.
  // Missing history is ambiguous (including eviction), not proof of noncommit.
  const recovery = commandId === undefined ? {} : { command: entry ? {
    commandId, status: 'committed', sequence: entry.sequence,
    ...(entry.noticeId ? { noticeMessageId: entry.noticeId } : {}),
    result: { ...entry.result, ...(Object.hasOwn(entry.result, 'operationRecorded') ? { operationRecorded: false } : {}) },
  } : { commandId, status: 'unknown' } };
  return structuredClone({ ...safe, caller: { role, nextSequence: Number.isSafeInteger(next) ? next : null, ...recovery } });
}
export function validateTaskLimits(limits = {}) {
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)) fail('task_kernel_configuration_required', 503);
  const values = { ...caps, ...limits };
  if (Object.keys(limits).some(key => !Object.hasOwn(caps, key)) ||
      Object.entries(values).some(([key, value]) => !integer(value) || value > caps[key]))
    fail('task_kernel_configuration_required', 503);
  return values;
}

export class TaskKernel {
  constructor({ store, authorize, clock = Date.now, makeAttemptId = randomUUID, leaseMs, limits = {}, retention }) {
    if (!store?.transaction || !integer(leaseMs)) fail('task_kernel_configuration_required', 503);
    this.store = store; this.authorize = authorize; this.clock = clock;
    this.makeAttemptId = makeAttemptId; this.leaseMs = leaseMs;
    this.retention = retention === undefined ? null : new TaskRetention(retention);
    this.limits = validateTaskLimits(limits);
  }
  decision(principal, request, task, now, state) {
    if (typeof this.authorize !== 'function') fail('task_authorization_unavailable', 503);
    // This callback is trusted and synchronous. State is the current locked
    // transaction document, never request context or a separately cached read.
    // No request field is accepted as an authorization decision.
    const value = this.authorize(principal, Object.freeze({ operation: request.operation,
      taskId: request.taskId, assignee: request.assignee || task?.assignee }), now, state);
    if (value?.then) {
      // Async adapters are unsupported. Observe rejection without admitting or
      // awaiting the decision, so it cannot escape as an unhandled exception.
      Promise.resolve(value).catch(() => {});
      fail('task_access_denied', 403);
    }
    if (value?.dataAllowed !== true || !roles.includes(value.role) || typeof value.ownerKey !== 'string' ||
        !/^[a-f0-9]{64}$/.test(value.ownerKey || '')) fail('task_access_denied', 403);
    if (task && value.ownerKey !== task.ownerKey) fail('task_not_found', 404);
    return value;
  }
  now() {
    const value = this.clock();
    if (!Number.isSafeInteger(value)) fail('task_kernel_configuration_required', 503);
    return value;
  }
  capacity(state) {
    const saved = collection(state), tasks = Object.values(saved.tasks);
    const reserve = task => terminal(task.phase) ? 0 : terminalReserve;
    if (tasks.length > this.limits.tasks || tasks.some(task => bytes(task) + reserve(task) > this.limits.taskBytes) ||
        bytes(saved) + tasks.reduce((sum, task) => sum + reserve(task), 0) > this.limits.bytes ||
        bytes(state) + tasks.reduce((sum, task) => sum + reserve(task), 0) > 4194304)
      fail('task_capacity_reached', 429);
  }
  readState(state, principal, id, commandId) {
    if (typeof id !== 'string' || !uuid.test(id) ||
        (commandId !== undefined && (typeof commandId !== 'string' || !uuid.test(commandId))))
      fail('invalid_task_command', 400);
    const now = this.now(), task = collection(state)?.tasks[id], retired = retiredTask(state, id);
    const access = this.decision(principal, { operation: 'read', taskId: id }, task || retired, now, state);
    checkTaskClock(state, now);
    if (retired) fail('task_retired', 410);
    if (!task) fail('task_not_found', 404);
    normalize(task, now);
    return { task: view(task, access.role, commandId), role: access.role, ownerKey: access.ownerKey, now };
  }
  async get(principal, id, commandId) {
    return this.store.transaction(state => this.readState(state, principal, id, commandId).task);
  }
  change(task, access, request, now) {
    const history = task?.commands[access.role];
    const hash = createHash('sha256').update(JSON.stringify(request)).digest('hex');
    const prior = history?.recent.find(entry => entry.id === request.commandId || entry.sequence === request.sequence);
    if (prior) {
      if (prior.hash !== hash || prior.id !== request.commandId) fail('task_command_conflict');
      // A lost start reply is ambiguous: replay must never look like a newly
      // recorded launch intent. This fact is DATA, not execution permission.
      return { task, result: { ...prior.result,
        ...(request.operation === 'start' ? { operationRecorded: false } : {}) }, duplicate: true };
    }
    if (request.sequence <= (history?.through || 0)) fail('task_command_too_old');
    if (request.sequence !== (history?.through || 0) + 1) fail('task_command_sequence_conflict');
    const coordinate = () => {
      if (access.coordinate !== true || (task && access.role !== task.coordinator)) fail('task_coordinator_required', 403);
    };
    if (request.operation === 'create') {
      if (task) fail('task_id_conflict');
      coordinate();
      if (request.deadline <= now) fail('task_deadline_passed');
      task = { id: request.taskId, ownerKey: access.ownerKey, coordinator: access.role,
        assignee: request.assignee, description: request.description, deadline: request.deadline,
        phase: 'queued', blockedReason: null,
        revision: 1, epoch: 0, lease: null, checkpoint: null, result: null,
        createdAt: now, updatedAt: now, commands: {} };
    } else {
      if (!task) fail('task_not_found', 404);
      if (request.expectedRevision !== task.revision) fail('task_revision_conflict');
      if (terminal(task.phase)) fail('task_terminal');
      if (['assign', 'cancel'].includes(request.operation)) coordinate();
      else {
        if (access.role !== task.assignee) fail('task_assignee_required', 403);
      }
      if (request.operation === 'assign') {
        if (task.phase === 'running') fail('task_busy');
        task.assignee = request.assignee;
        task.phase = task.externalOperation ? 'reconciliation_required' : 'queued';
        task.blockedReason = task.externalOperation ? 'external_operation' : null; task.lease = null; task.epoch++;
      } else if (request.operation === 'cancel') {
        task.phase = 'cancelled'; task.blockedReason = null; task.lease = null; task.epoch++;
      } else if (request.operation === 'claim') {
        if (task.externalOperation || task.phase === 'reconciliation_required') fail('task_reconciliation_required');
        if (task.phase === 'running') fail('task_busy');
        if (task.phase === 'blocked') fail('task_reconciliation_required');
        const id = this.makeAttemptId();
        if (typeof id !== 'string' || !uuid.test(id)) fail('task_kernel_configuration_required', 503);
        task.epoch++; task.phase = 'running'; task.blockedReason = null;
        task.lease = { id, epoch: task.epoch, role: access.role,
          until: Math.min(now + this.leaseMs, task.deadline) };
      } else if (request.operation === 'reconcile') {
        const operation = task.externalOperation;
        if (!operation || operation.id !== request.operationId) fail('task_operation_conflict');
        if (operation.runRef !== null && operation.runRef !== request.runRef) fail('task_run_conflict');
        // Native workflow checks the actual run before reporting. These fields
        // never prove provider identity, idempotency or external authority.
        operation.runRef = request.runRef;
        operation.observation = { outcome: request.outcome, evidence: request.evidence,
          ...(['running', 'unknown'].includes(request.outcome) ? { text: request.result } : {}),
          at: now, evidenceStatus: 'reported_not_independently_verified' };
        task.lease = null; task.epoch++;
        task.phase = ['succeeded', 'failed'].includes(request.outcome) ? request.outcome : 'reconciliation_required';
        task.blockedReason = task.phase === 'reconciliation_required' ? 'external_' + request.outcome : null;
        if (terminal(task.phase)) task.result = { outcome: request.outcome, text: request.result, at: now,
          commandId: request.commandId, operationId: operation.id,
          evidenceStatus: 'reported_not_independently_verified' };
      } else {
        if (task.phase !== 'running' || task.lease?.id !== request.attemptId || task.epoch !== request.epoch || task.lease.until <= now)
          fail('stale_task_attempt');
        if (request.operation === 'progress') task.checkpoint = { text: request.checkpoint, sequence: request.sequence, at: now };
        if (request.operation === 'start') {
          if (task.externalOperation) fail('task_operation_already_recorded');
          task.externalOperation = { id: request.operationId, runRef: null, recordedAt: now,
            attemptId: task.lease.id, epoch: task.epoch, observation: null };
        }
        if (request.operation === 'block') {
          task.phase = task.externalOperation ? 'reconciliation_required' : 'blocked';
          task.blockedReason = request.reason; task.lease = null; task.epoch++;
        }
        if (request.operation === 'finish') {
          if (task.externalOperation) fail('task_operation_reconciliation_required');
          task.phase = request.outcome; task.lease = null; task.epoch++;
          task.result = { outcome: request.outcome, text: request.result, at: now, commandId: request.commandId,
            evidenceStatus: 'reported_not_independently_verified' };
        }
      }
      task.revision++; task.updatedAt = now;
    }
    const result = { ...output(task), ...(request.operation === 'start' ? { operationRecorded: true } : {}) };
    const cache = task.commands[access.role] ||= { through: 0, recent: [] };
    cache.through = request.sequence;
    cache.recent = [...cache.recent, { id: request.commandId, sequence: request.sequence, hash, result }].slice(-this.limits.replay);
    return { task, result };
  }
  stage(state, principal, input) {
    const request = command(input);
    const now = this.now(), before = collection(state)?.tasks[request.taskId];
    const access = this.decision(principal, request, before || retiredTask(state, request.taskId), now, state);
    checkTaskClock(state, now);
    this.retention?.run(state, now, access.ownerKey);
    const saved = collection(state)?.tasks[request.taskId];
    // Persist time-based stopping even when this command is rejected. This
    // deadline bounds coordination state; it grants no execution authority.
    if (saved) normalize(saved, now);
    try {
      if (retiredTask(state, request.taskId)) fail('task_retired', 410);
      if (request.operation === 'create' && !saved) checkNewTaskId(state, request.taskId, now, this.retention);
      // Command changes live on a copy until every check passes. Rejecting
      // the command must not consume its sequence, change ownership/result,
      // or roll a stopped lifecycle back to a live mutex.
      const changed = this.change(saved ? structuredClone(saved) : undefined, access, request, now);
      if (!changed.duplicate) {
        const next = { ...collection(state), version: 1, tasks: { ...collection(state)?.tasks, [request.taskId]: changed.task } };
        this.capacity({ ...state, collaboration: next });
        state.collaboration = next;
      }
      return { result: changed.result, duplicate: changed.duplicate === true,
        role: access.role, ownerKey: access.ownerKey, now };
    } catch (error) {
      if (!(error instanceof BridgeError)) throw error;
      return { failure: { code: error.code, status: error.status } };
    }
  }
  async apply(principal, input) {
    const outcome = await this.store.transaction(state => this.stage(state, principal, input));
    if (outcome.failure) fail(outcome.failure.code, outcome.failure.status);
    return outcome.result;
  }
}
