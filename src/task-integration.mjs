import { BridgeError } from './policy.mjs';
import { ownKeys } from './events.mjs';
import { MESSAGE_PROTOCOL } from './messages.mjs';
import { TaskNoticeTransactions } from './task-notices.mjs';

const id = { type: 'string', format: 'uuid' };
const number = { type: 'integer', minimum: 1 };
const text = maxLength => ({ type: 'string', minLength: 1, maxLength });
const object = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const fields = {
  create: { assignee: { enum: ['jarvis', 'friday'] }, description: text(4096), deadline: number },
  assign: { assignee: { enum: ['jarvis', 'friday'] } }, claim: {},
  progress: { attemptId: id, epoch: number, checkpoint: text(2048) },
  finish: { attemptId: id, epoch: number, outcome: { enum: ['succeeded', 'failed'] }, result: text(2048) },
  block: { attemptId: id, epoch: number, reason: { enum: ['waiting_dependency', 'outcome_unknown', 'capability_missing'] } }, cancel: {},
  start: { attemptId: id, epoch: number, operationId: id },
  reconcile: { operationId: id, runRef: { type: ['string', 'null'], minLength: 1, maxLength: 256 },
    outcome: { enum: ['running', 'unknown', 'succeeded', 'failed'] }, evidence: text(1024), result: text(2048) },
};
const tool = (name, description, inputSchema, readOnlyHint = false) => ({ name, description, inputSchema,
  annotations: { readOnlyHint, destructiveHint: false, idempotentHint: true, openWorldHint: false } });
export const TASK_TOOLS = [
  tool('bridge_task_command', 'Coordinate task DATA and notify the peer. Claims are mutexes; reports never authorize execution.',
    object({ command: { oneOf: Object.entries(fields).map(([operation, extra]) => object({
      operation: { const: operation }, taskId: id, commandId: id, sequence: number,
      ...(operation === 'create' ? {} : { expectedRevision: number }), ...extra })) },
      notice: object({ messageId: id, sentAt: { type: 'string', format: 'date-time' }, expiresAt: { type: 'string', format: 'date-time' } }) })),
  tool('bridge_task_get', 'Read current task DATA and caller sequence; optionally recover one caller command by ID. Never poll.',
    { ...object({ taskId: id, commandId: id }), required: ['taskId'] }, true),
  tool('bridge_task_from_notice', 'Resolve this exact native event message ID to current task DATA. Never claims an expired receipt.',
    { ...object({ messageId: id, commandId: id }), required: ['messageId'] }, true),
];
const fail = (code, status = 503) => { throw new BridgeError(code, status); };

// Trusted runtime constructor opt-in is required; no environment/request switch.
// Permanent purge is separately off; only synthetic retention fixtures opt in.
export class TaskIntegration {
  constructor({ enabled = false, kernel, bridge, linkRetentionMs, maxLinks, maxLinksPerTask, purgeEnabled = false } = {}) {
    this.enabled = enabled === true;
    if (!this.enabled) return;
    if (kernel?.retention && purgeEnabled !== true) fail('task_purge_not_enabled');
    if (!kernel?.stage || typeof kernel.authorize !== 'function' || kernel.store !== bridge?.store ||
        !bridge.prepareMessageSend || !bridge.stageMessage)
      fail('task_integration_configuration_required');
    this.kernel = kernel; this.bridge = bridge;
    this.options = { kernel, linkRetentionMs, maxLinks, maxLinksPerTask, pruneExpiredLinks: purgeEnabled === true };
    this.notices = new TaskNoticeTransactions({ ...this.options, stageNotice: () => fail('task_notice_stage_invalid') });
  }
  active() { if (!this.enabled) fail('task_integration_disabled'); }
  async apply(principal, input) {
    this.active(); ownKeys(input, ['command', 'notice']); ownKeys(input.notice, ['messageId', 'sentAt', 'expiresAt']);
    if (typeof input.notice.messageId !== 'string' ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.notice.messageId))
      fail('invalid_task_notice', 400);
    const { command, notice } = structuredClone(input);
    // Validate task admission on a disposable copy BEFORE queue prearming.
    // No candidate task command or new notice/link commits before final v1 insertion.
    const preview = await this.kernel.store.transaction(state => {
      const staged = this.kernel.stage(structuredClone(state), principal, command);
      // Commit only admitted retention here, not the candidate task command.
      // This lets small batches reclaim capacity even if notice staging fails.
      if (!staged.failure) this.kernel.retention?.run(state, staged.now, staged.ownerKey);
      return staged;
    });
    const binding = { messageId: notice.messageId };
    // Like task command replay, transport times are immutable after commit:
    // replay returns the original binding and never republishes or renews it.
    if (preview.failure || preview.duplicate) return this.notices.apply(principal, command, binding);
    const envelope = { protocol: MESSAGE_PROTOCOL, id: notice.messageId, from: principal.role,
      to: principal.role === 'jarvis' ? 'friday' : 'jarvis', kind: 'status', route: 'inbox', threadId: command.taskId,
      sentAt: notice.sentAt, expiresAt: notice.expiresAt, text: 'Shared task data updated.' };
    await this.bridge.prepareMessageSend(principal, envelope);
    const notices = new TaskNoticeTransactions({ ...this.options,
      stageNotice: (state, actor) => this.bridge.stageMessage(state, actor, envelope) });
    return notices.apply(principal, command, binding);
  }
  async get(principal, params) {
    this.active(); ownKeys(params, ['taskId', 'commandId'], ['taskId']);
    return this.kernel.get(principal, params.taskId, params.commandId);
  }
  async getByMessageId(principal, params) {
    this.active(); ownKeys(params, ['messageId', 'commandId'], ['messageId']);
    return this.notices.getByMessageId(principal, params.messageId, params.commandId);
  }
}
