import { BridgeError } from './policy.ts';
import type { BridgeState, Millis, RetiredTask, Task } from './types.ts';

export interface TaskRetentionOptions {
  terminalMs?: number; tombstoneMs?: number; creationWindowMs?: number; maxTombstones?: number; batchSize?: number;
}
/** The creation-window rule: the stored identity, or a retention policy before it is installed. */
interface CreationRule { creationWindowMs: number; observedAt?: Millis }

// Explicitly typed so a bare fail() statement narrows control flow.
const fail: () => never = () => { throw new BridgeError('task_retention_configuration_required', 503); };
const positive = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0;
const terminal = (task: Task): boolean => ['succeeded', 'failed', 'cancelled', 'expired'].includes(task.phase);
const birth = (id: string): number | null => id[14] === '7' ? Number.parseInt(id.slice(0, 8) + id.slice(9, 13), 16) : null;
function identity(state: BridgeState, policy?: CreationRule | null): CreationRule | null | undefined {
  const saved = state.collaboration?.taskIdentity;
  if (saved !== undefined && (!saved || saved.version !== 1 || !positive(saved.creationWindowMs) ||
      saved.creationWindowMs > 300000 || !Number.isSafeInteger(saved.observedAt))) fail();
  if (saved && policy && saved.creationWindowMs !== policy.creationWindowMs) fail();
  return saved || policy;
}
export function retiredTask(state: BridgeState, id: string): RetiredTask | undefined {
  const saved = state.collaboration?.retiredTasks;
  if (saved !== undefined && (!saved || typeof saved !== 'object' || Array.isArray(saved))) fail();
  return saved?.[id];
}
export function checkTaskClock(state: BridgeState, now: Millis): void {
  // An absent identity compares undefined > now, which is false.
  if ((identity(state)?.observedAt as Millis) > now) throw new BridgeError('task_retention_clock_regressed', 503);
}
export function checkNewTaskId(state: BridgeState, id: string, now: Millis, policy?: CreationRule | null): void {
  const rule = identity(state, policy);
  checkTaskClock(state, now);
  if (rule && (birth(id) === null || Math.abs(now - birth(id)!) > rule.creationWindowMs))
    throw new BridgeError('task_id_outside_creation_window', 409);
}

// Optional, fixture-configured DATA lifecycle. No runtime wiring, timer, queue,
// public cleanup tool or access grant. Run only inside the existing transaction.
export class TaskRetention {
  declare terminalMs: number; declare tombstoneMs: number; declare creationWindowMs: number;
  declare maxTombstones: number; declare batchSize: number;
  constructor({ terminalMs, tombstoneMs, creationWindowMs, maxTombstones = 1000, batchSize = 100 }: TaskRetentionOptions = {}) {
    if (![terminalMs, tombstoneMs, creationWindowMs, maxTombstones, batchSize].every(positive) ||
        (creationWindowMs as number) > 300000 || maxTombstones > 1000 || batchSize > 100) fail();
    Object.assign(this, { terminalMs, tombstoneMs, creationWindowMs, maxTombstones, batchSize });
  }
  run(state: BridgeState, now: Millis, ownerKey: string): { links: number; tombstones: number; tasks: number } {
    if (!Number.isSafeInteger(now) || typeof ownerKey !== 'string' || !/^[a-f0-9]{64}$/.test(ownerKey)) fail();
    identity(state, this); retiredTask(state, '');
    const data = state.collaboration ||= { version: 1, tasks: {} };
    if ((data.taskIdentity?.observedAt as Millis) > now) throw new BridgeError('task_retention_clock_regressed', 503);
    data.taskIdentity ||= { version: 1, creationWindowMs: this.creationWindowMs, observedAt: now };
    data.taskIdentity.observedAt = now;
    const retired = data.retiredTasks ||= {}, links = data.noticeLinks === undefined ? {} : data.noticeLinks;
    if (!links || typeof links !== 'object' || Array.isArray(links) || Object.keys(retired).length > this.maxTombstones) fail();
    let budget = this.batchSize;
    const removed = { links: 0, tombstones: 0, tasks: 0 };
    for (const [id, link] of Object.entries(links)) {
      if (budget && link.ownerKey === ownerKey && link.until <= now) {
        delete links[id]; removed.links++; budget--;
      }
    }
    for (const [id, record] of Object.entries(retired)) {
      if (budget && record.ownerKey === ownerKey && record.until !== null && record.until <= now) {
        delete retired[id]; removed.tombstones++; budget--;
      }
    }
    for (const [id, task] of Object.entries(data.tasks)) {
      // Never normalize/evict active or unseen overdue tasks. An observed
      // terminal transition starts its full evidence-retention interval.
      if (!budget || task.ownerKey !== ownerKey || !terminal(task) || now - task.updatedAt < this.terminalMs ||
          Object.values(links).some(link => link.taskId === id) ||
          Object.keys(retired).length >= this.maxTombstones) continue;
      const at = birth(id);
      if (at !== null && now <= at + this.creationWindowMs) continue;
      const until = at === null ? null : now + this.tombstoneMs;
      if (until !== null && !Number.isSafeInteger(until)) fail();
      // Legacy non-time-bound IDs retain a compact permanent identity fence.
      // Once the policy is installed, no new such IDs can enter this store.
      retired[id] = { ownerKey, phase: task.phase, revision: task.revision, epoch: task.epoch, retiredAt: now, until };
      delete data.tasks[id]; removed.tasks++; budget--;
    }
    return removed;
  }
}
