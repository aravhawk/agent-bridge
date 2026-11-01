import { BridgeError } from './policy.ts';
import { ownKeys } from './events.ts';
import { MESSAGE_PROTOCOL } from './messages.ts';
import { TaskNoticeTransactions } from './task-notices.ts';
import { PEER_IDS, counterpart } from './config.ts';
import type { TaskKernel } from './tasks.ts';
import type { TaskNoticeTransactionOptions } from './task-notices.ts';
import type { BridgeState, Principal, Store } from './types.ts';

/** The v1 message admission surface task notices reuse (implemented by the bridge). */
export interface TaskBridge {
  store: Store;
  messagePolicyIds?: Readonly<Record<string, string>> | undefined;
  prepareMessage?: unknown;
  prepareMessageSend(principal: Principal | null | undefined, input: unknown): Promise<unknown>;
  stageMessage(state: BridgeState, principal: Principal | null | undefined, input: unknown): unknown;
}
export interface TaskIntegrationOptions {
  enabled?: boolean; kernel?: TaskKernel | undefined; bridge?: TaskBridge | undefined; linkRetentionMs?: number | undefined;
  maxLinks?: number | undefined; maxLinksPerTask?: number | undefined; purgeEnabled?: boolean;
}
type JsonSchema = Record<string, unknown>;
export interface ToolDefinition {
  name: string; description: string; inputSchema: JsonSchema;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean; idempotentHint: boolean; openWorldHint: boolean };
}

const id = { type: 'string', format: 'uuid' };
const number = { type: 'integer', minimum: 1 };
const text = (maxLength: number): JsonSchema => ({ type: 'string', minLength: 1, maxLength });
const object = (properties: Record<string, JsonSchema>): JsonSchema => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const fields: Record<string, Record<string, JsonSchema>> = {
  create: { assignee: { enum: [...PEER_IDS] }, description: text(4096), deadline: number },
  assign: { assignee: { enum: [...PEER_IDS] } }, claim: {},
  progress: { attemptId: id, epoch: number, checkpoint: text(2048) },
  finish: { attemptId: id, epoch: number, outcome: { enum: ['succeeded', 'failed'] }, result: text(2048) },
  block: { attemptId: id, epoch: number, reason: { enum: ['waiting_dependency', 'outcome_unknown', 'capability_missing'] } }, cancel: {},
  start: { attemptId: id, epoch: number, operationId: id },
  reconcile: { operationId: id, runRef: { type: ['string', 'null'], minLength: 1, maxLength: 256 },
    outcome: { enum: ['running', 'unknown', 'succeeded', 'failed'] }, evidence: text(1024), result: text(2048) },
};
const tool = (name: string, description: string, inputSchema: JsonSchema, readOnlyHint = false): ToolDefinition => ({ name, description, inputSchema,
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
// Explicitly typed so a bare fail(...) statement narrows control flow.
const fail: (code: string, status?: number) => never = (code, status = 503) => { throw new BridgeError(code, status); };

// Trusted runtime constructor opt-in is required; no environment/request switch.
// Permanent purge is separately off; only synthetic retention fixtures opt in.
export class TaskIntegration {
  declare enabled: boolean; declare kernel: TaskKernel; declare bridge: TaskBridge;
  declare options: Omit<TaskNoticeTransactionOptions, 'stageNotice'>; declare notices: TaskNoticeTransactions;
  constructor({ enabled = false, kernel, bridge, linkRetentionMs, maxLinks, maxLinksPerTask, purgeEnabled = false }: TaskIntegrationOptions = {}) {
    this.enabled = enabled === true;
    if (!this.enabled) return;
    if (kernel?.retention && purgeEnabled !== true) fail('task_purge_not_enabled');
    if (!kernel?.stage || typeof kernel.authorize !== 'function' || kernel.store !== bridge?.store ||
        !bridge!.prepareMessageSend || !bridge!.stageMessage)
      fail('task_integration_configuration_required');
    this.kernel = kernel!; this.bridge = bridge!; // Both checked above.
    this.options = { kernel: kernel!, linkRetentionMs, maxLinks, maxLinksPerTask, pruneExpiredLinks: purgeEnabled === true };
    this.notices = new TaskNoticeTransactions({ ...this.options, stageNotice: () => fail('task_notice_stage_invalid') });
  }
  active(): void { if (!this.enabled) fail('task_integration_disabled'); }
  async apply(principal: Principal | null | undefined, input: unknown) {
    this.active(); ownKeys(input, ['command', 'notice']); ownKeys(input.notice, ['messageId', 'sentAt', 'expiresAt']);
    if (typeof input.notice.messageId !== 'string' ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.notice.messageId))
      fail('invalid_task_notice', 400);
    // The clone of the shape checked above.
    const { command, notice } = structuredClone(input) as { command: unknown; notice: { messageId: string; sentAt?: unknown; expiresAt?: unknown } };
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
    // stage() admitted this principal and validated the command.
    const envelope = { protocol: MESSAGE_PROTOCOL, id: notice.messageId, from: principal!.role,
      to: counterpart(principal!.role), kind: 'status', route: 'inbox', threadId: (command as { taskId: string }).taskId,
      sentAt: notice.sentAt, expiresAt: notice.expiresAt, text: 'Shared task data updated.' };
    await this.bridge.prepareMessageSend(principal, envelope);
    const notices = new TaskNoticeTransactions({ ...this.options,
      stageNotice: (state, actor) => this.bridge.stageMessage(state, actor, envelope) });
    return notices.apply(principal, command, binding);
  }
  async get(principal: Principal | null | undefined, params: unknown) {
    this.active(); ownKeys(params, ['taskId', 'commandId'], ['taskId']);
    return this.kernel.get(principal, params.taskId, params.commandId);
  }
  async getByMessageId(principal: Principal | null | undefined, params: unknown) {
    this.active(); ownKeys(params, ['messageId', 'commandId'], ['messageId']);
    return this.notices.getByMessageId(principal, params.messageId, params.commandId);
  }
}
