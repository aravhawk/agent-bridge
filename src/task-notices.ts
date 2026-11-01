import { BridgeError } from './policy.ts';
import { counterpart } from './config.ts';
import { MESSAGE_PROTOCOL } from './messages.ts';
import type { StageFailure, TaskKernel } from './tasks.ts';
import type { BridgeState, Millis, Principal, Role, Task, TaskCommand, TaskNoticeLink } from './types.ts';

export interface TaskNoticeOptions { linkRetentionMs?: number | undefined; maxLinks?: number | undefined; maxLinksPerTask?: number | undefined }
/** What stageNotice may stage: one v1 status message for this exact task change. */
export interface TaskNoticeContext {
  readonly messageId: string; readonly taskId: string; readonly revision: number; readonly from: Role; readonly to: Role;
  readonly createdAt: Millis;
}
/** Must synchronously stage the notice through the existing v1 admission path. */
export type StageNotice = (state: BridgeState, principal: Principal | null | undefined, context: TaskNoticeContext) => unknown;
export interface TaskNoticeTransactionOptions extends TaskNoticeOptions {
  kernel: TaskKernel; stageNotice: StageNotice; pruneExpiredLinks?: boolean;
}
type Outcome<T> = { failure?: undefined; result: T } | StageFailure;

// Isolated transaction helper: no sender, queue, principal derivation or scope
// mapping. stageNotice must synchronously use the existing v1 admission path.
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const terminal = (task: Task): boolean => ['succeeded', 'failed', 'cancelled', 'expired'].includes(task.phase);
const positive = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;
// Explicitly typed so a bare fail(...) statement narrows control flow.
const fail: (code: string, status?: number) => never = (code, status = 409) => { throw new BridgeError(code, status); };
function links(state: BridgeState): Record<string, TaskNoticeLink> {
  const value = state.collaboration?.noticeLinks;
  if (value !== undefined && (!value || typeof value !== 'object' || Array.isArray(value))) fail('task_notice_storage_invalid', 503);
  return value || {};
}
function prune(saved: Record<string, TaskNoticeLink>, now: Millis): void {
  for (const [id, link] of Object.entries(saved)) if (link.until <= now) delete saved[id];
}
function result<T>(outcome: Outcome<T>): T {
  if (outcome.failure) fail(outcome.failure.code, outcome.failure.status);
  return outcome.result;
}
export function validateTaskNoticeOptions({ linkRetentionMs, maxLinks = 1000, maxLinksPerTask = 32 }: TaskNoticeOptions = {}):
  { linkRetentionMs: number; maxLinks: number; maxLinksPerTask: number } {
  if (!positive(linkRetentionMs) || !positive(maxLinks) || maxLinks > 1000 ||
      !positive(maxLinksPerTask) || maxLinksPerTask > 32) fail('task_notice_configuration_required', 503);
  return { linkRetentionMs, maxLinks, maxLinksPerTask };
}

export class TaskNoticeTransactions {
  declare kernel: TaskKernel; declare stageNotice: StageNotice; declare linkRetentionMs: number;
  declare maxLinks: number; declare maxLinksPerTask: number; declare pruneExpiredLinks: boolean;
  constructor({ kernel, stageNotice, linkRetentionMs, maxLinks = 1000, maxLinksPerTask = 32, pruneExpiredLinks = true }: TaskNoticeTransactionOptions) {
    if (!kernel?.stage || !kernel?.readState || typeof stageNotice !== 'function' || typeof pruneExpiredLinks !== 'boolean')
      fail('task_notice_configuration_required', 503);
    this.kernel = kernel; this.stageNotice = stageNotice;
    Object.assign(this, validateTaskNoticeOptions({ linkRetentionMs, maxLinks, maxLinksPerTask }));
    this.pruneExpiredLinks = pruneExpiredLinks;
  }
  capacity(state: BridgeState): void {
    const tasks = Object.values(state.collaboration!.tasks), saved = Object.values(links(state));
    // Reserve one alias slot for a terminal report/cancel. This reserves counts
    // only, not room for v1 message/job bytes or space against legacy writers.
    if (saved.length + tasks.filter(task => !terminal(task)).length > this.maxLinks || tasks.some(task =>
      saved.filter(link => link.taskId === task.id).length + (terminal(task) ? 0 : 1) > this.maxLinksPerTask))
      fail('task_notice_capacity_reached', 429);
    this.kernel.capacity(state);
  }
  async apply(principal: Principal | null | undefined, command: unknown,
    // Callers bind a validated message ID; its shape is re-checked below before any use.
    notice: { readonly messageId: string } | null | undefined) {
    if (!notice || typeof notice !== 'object' || Array.isArray(notice) ||
        Object.keys(notice).length !== 1 || !uuid(notice.messageId)) fail('invalid_task_notice', 400);
    const outcome = await this.kernel.store.transaction(state => {
      const staged = this.kernel.stage(state, principal, command);
      if (staged.failure) return staged;
      // stage() validated the command and recorded (or replayed) its entry under the caller's role.
      const entry = state.collaboration!.tasks[(command as TaskCommand).taskId]!.commands[staged.role]!.recent
        .find(item => item.sequence === (command as TaskCommand).sequence)!;
      if (staged.duplicate) {
        if (entry.noticeId !== notice.messageId) fail('task_notice_conflict');
        return { result: { ...staged.result, noticeMessageId: entry.noticeId,
          jobIds: state.messages[entry.noticeId as string]?.jobIds || [] } };
      }
      const saved = links(state);
      // Opt-in retention already performed its bounded, owner-scoped batch.
      // The legacy all-alias prune must not bypass that policy or budget.
      if (this.pruneExpiredLinks && !this.kernel.retention) prune(saved, staged.now);
      if (saved[notice.messageId] || state.messages[notice.messageId] || state.messageIds?.[notice.messageId])
        fail('task_notice_id_conflict');
      const until = staged.now + this.linkRetentionMs;
      if (!Number.isSafeInteger(until)) fail('task_notice_configuration_required', 503);
      const recipient = counterpart(staged.role)!; // The authorizer admitted a peer role, which has a counterpart.
      const context = Object.freeze({ messageId: notice.messageId, taskId: (command as TaskCommand).taskId,
        revision: staged.result.revision, from: staged.role, to: recipient, createdAt: staged.now });
      const callbackResult = this.stageNotice(state, principal, context);
      if ((callbackResult as { then?: unknown } | null | undefined)?.then) {
        // Reject async staging and observe its rejection without logging data.
        Promise.resolve(callbackResult).catch(() => {});
        fail('task_notice_stage_invalid', 503);
      }
      const envelope = state.messages[notice.messageId]?.envelope;
      if (envelope?.protocol !== MESSAGE_PROTOCOL || envelope.id !== notice.messageId ||
          envelope.kind !== 'status' || envelope.from !== staged.role || envelope.to !== recipient ||
          envelope.route !== 'inbox' || envelope.threadId !== (command as TaskCommand).taskId)
        fail('task_notice_stage_invalid', 503);
      entry.noticeId = notice.messageId;
      saved[notice.messageId] = { taskId: (command as TaskCommand).taskId, revision: staged.result.revision,
        recipient, ownerKey: staged.ownerKey, createdAt: staged.now, until };
      state.collaboration!.noticeLinks = saved;
      this.capacity(state);
      return { result: { ...staged.result, noticeMessageId: notice.messageId,
        jobIds: state.messages[notice.messageId]!.jobIds || [] } };
    });
    return result(outcome);
  }
  async getByMessageId(principal: Principal | null | undefined, messageId: unknown, commandId?: unknown) {
    if (!uuid(messageId)) fail('invalid_task_notice', 400);
    if (commandId !== undefined && !uuid(commandId)) fail('invalid_task_command', 400);
    const outcome = await this.kernel.store.transaction(state => {
      const saved = links(state), link = saved[messageId];
      if (!link) {
        this.kernel.decision(principal, { operation: 'read', taskId: messageId }, undefined, this.kernel.now(), state);
        fail('task_notice_not_found', 404);
      }
      const read = this.kernel.readState(state, principal, link.taskId, commandId);
      if (read.role !== link.recipient || read.ownerKey !== link.ownerKey) fail('task_notice_not_found', 404);
      if (this.pruneExpiredLinks) {
        if (this.kernel.retention) {
          if (link.until <= read.now) delete saved[messageId];
        } else prune(saved, read.now);
      }
      if (link.until <= read.now) return { failure: { code: 'task_notice_not_found', status: 404 } };
      return { result: { messageId, noticeRevision: link.revision, task: read.task } };
    });
    return result(outcome);
  }
}
