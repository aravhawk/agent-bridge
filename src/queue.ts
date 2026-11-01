import { QUEUE_TOPIC, QUEUE_REGION } from './release.ts';
import { dailyMessage, retainMessages, CONTENT_RETENTION_MS } from './messages.ts';
import { BridgeError } from './policy.ts';
import { digest } from './events.ts';
import type { Job, JsonObject, Millis, Store } from './types.ts';

/** The publish side of the Vercel Queue client this adapter uses. */
export interface QueueSendOptions { region: string; delaySeconds: number; retentionSeconds: number; idempotencyKey: string }
export interface QueueClient { send(topic: string, payload: JsonObject, options: QueueSendOptions): Promise<unknown> }
/** Delivery metadata supplied by the queue SDK (never by a request). */
export interface QueueMetadata {
  topicName?: string; region?: string; deliveryCount: number; messageId?: unknown;
  createdAt?: { getTime?: () => number }; expiresAt?: { getTime?: () => number };
}
export interface JobRunner { run(jobId: string): Promise<unknown> }
export interface QueueAdapterOptions {
  client: QueueClient; store: Store; worker: JobRunner; enabled?: boolean; maintenanceEnabled?: boolean; clock?: () => Millis;
}
/** A queue payload: one work key (and optionally recoveryUntil); untrusted until checked. */
export type QueuePayload = Record<string, unknown> & { recoveryUntil?: unknown; jobId?: string | undefined };
type Payload = QueuePayload;

export const TOPIC = QUEUE_TOPIC;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const idPattern = /^job_[a-f0-9]{64}$/;
class RetryJob extends Error {
  declare afterSeconds: number;
  declare recoverable: boolean;
  constructor(afterSeconds: number, recoverable = true) { super('bridge_job_pending'); this.afterSeconds = afterSeconds; this.recoverable = recoverable; }
}
const recoveryBudgetMs = 3600000, handoffAt = 18;
export function createQueueAdapter({ client, store, worker, enabled = false, maintenanceEnabled = false, clock = Date.now }: QueueAdapterOptions) {
  const gate = () => { if (!enabled) throw new BridgeError('queue_not_enabled', 503); };
  async function publish(payload: JsonObject, key: string, delaySeconds = 1): Promise<void> {
    await client.send(TOPIC, payload, { region: QUEUE_REGION, delaySeconds,
      retentionSeconds: Math.min(604800, Math.max(3600, delaySeconds + 3600)), idempotencyKey: key });
  }
  async function handoff(message: Payload, workKey: string, metadata: QueueMetadata): Promise<boolean> {
    const createdAt = metadata.createdAt?.getTime?.(), expiresAt = metadata.expiresAt?.getTime?.();
    if (!Number.isSafeInteger(createdAt) || (createdAt as number) > clock() ||
        !Number.isSafeInteger(expiresAt) || (expiresAt as number) <= (createdAt as number) ||
        typeof metadata.messageId !== 'string' || !metadata.messageId || metadata.messageId.length > 256)
      throw new BridgeError('queue_recovery_metadata_required', 503);
    // Both are safe integers (checked above); recoveryUntil was validated by consume.
    const until = Math.min(expiresAt as number, (createdAt as number) + recoveryBudgetMs, (message.recoveryUntil as number | undefined) ?? Infinity);
    const remaining = Math.floor((until - clock()) / 1000);
    if (remaining <= 60) return false;
    // Publish before acknowledging the old item, outside the synchronous SDK
    // retry hook. Ambiguous publishes reuse the same key. Every descendant
    // retains the absolute deadline, including across delayed commits/restarts.
    await client.send(TOPIC, { [workKey]: message[workKey], recoveryUntil: until },
      { region: QUEUE_REGION, delaySeconds: 60, retentionSeconds: remaining,
        idempotencyKey: 'recovery:' + digest(JSON.stringify([metadata.messageId, until])) });
    return true;
  }
  return {
    async prepareMessage(id: string) {
      gate(); if (!uuid.test(id)) throw new BridgeError('invalid_message_id', 400);
      await publish({ cleanupMessageId: id }, `cleanup:${id}:content`, CONTENT_RETENTION_MS / 1000);
      await publish({ dispatchMessageId: id }, `dispatch:${id}:${Math.floor(clock() / 60000)}`);
    },
    async prepareReceipt(id: string) {
      gate(); if (!uuid.test(id)) throw new BridgeError('invalid_message_id', 400);
      await publish({ dispatchReceiptOf: id }, `receipt:${id}:${Math.floor(clock() / 60000)}`);
    },
    async scheduleJobs(ids: unknown) {
      gate();
      if (!Array.isArray(ids) || ids.length > 100 || ids.some(id => !idPattern.test(id as string))) {
        throw new BridgeError('invalid_job_ids', 400);
      }
      for (const id of [...new Set(ids as string[])]) {
        const job: Job | undefined = await store.transaction(s => s.jobs[id]);
        if (!job || ['accepted', 'dead'].includes(job.state)) continue;
        const due = Math.max(job.dueAt, job.leaseUntil || 0);
        const now = clock();
        // DB identity and fencing own idempotence. The epoch allows explicit
        // backend reconciliation to recover a previously exhausted queue item.
        await client.send(TOPIC, { jobId: id }, { region: QUEUE_REGION, retentionSeconds: 3600,
          delaySeconds: Math.max(0, Math.ceil((due - now) / 1000)),
          idempotencyKey: `${id}:${job.attempts}:${job.leaseId || 'pending'}:${Math.floor(now / 600000)}` });
      }
    },
    async consume(message: Payload, metadata: QueueMetadata) {
      if (metadata.topicName !== TOPIC || metadata.region !== QUEUE_REGION) return;
      const key = message && Object.keys(message).length === 1 ? Object.keys(message)[0] : null;
      // message[key] is a UUID string (checked) wherever it is used below.
      if (key === 'cleanupMessageId' && maintenanceEnabled && uuid.test(message[key] as string)) {
        const next = await store.transaction(state => {
          retainMessages(state, clock());
          return state.messages[message[key] as string]?.retainUntil || state.messageIds?.[message[key] as string]?.until;
        });
        // Chain one delayed native cleanup for the remaining tombstone. No
        // receiving assistant, clock daemon or interval participates.
        if ((next as Millis) > clock()) await publish(message, `cleanup:${message[key]}:${next}`,
          Math.max(1, Math.ceil(((next as Millis) - clock()) / 1000)));
        return;
      }
      gate();
      // A continuation retains one identifier and one absolute deadline. The
      // private SDK supplies metadata; request callers cannot publish payloads.
      const keys = message && Object.keys(message);
      const workKey = keys?.find(k => k !== 'recoveryUntil');
      const dispatch = ['dispatchMessageId', 'dispatchReceiptOf'].includes(workKey as string) && uuid.test(message[workKey as string] as string);
      const direct = workKey === 'jobId' && idPattern.test(message[workKey] as string);
      // Either check passing implies a work key, so keys and workKey are defined below.
      if ((!dispatch && !direct) || keys!.some(k => k !== workKey && k !== 'recoveryUntil')) return;
      if (Object.hasOwn(message, 'recoveryUntil') &&
          (!Number.isSafeInteger(message.recoveryUntil) || (message.recoveryUntil as number) <= clock())) return;
      try {
        if (dispatch) {
          const ids = await store.transaction(state => {
            const id = workKey === 'dispatchMessageId' ? message[workKey] as string : state.receipts[message[workKey as string] as string]?.ackMessageId;
            const saved = state.messages[id as string];
            return dailyMessage(saved?.envelope) ? saved!.jobIds : null;
          });
          if (!ids) throw new RetryJob(5, false); // An absent commit must not spawn continuations.
          // Missing commits get 20 x 5-second retries. Preparation keys rotate
          // each minute so a later sender retry cannot reuse an exhausted item.
          for (const id of ids) await worker.run(id);
          const pending = await store.transaction(state => ids.map(id => state.jobs[id]).filter(job => job && !['accepted', 'dead'].includes(job.state)));
          if (pending.length) throw new RetryJob(Math.max(1, Math.min(300,
            Math.ceil((Math.min(...pending.map(job => Math.max(job!.dueAt, job!.leaseUntil || 0))) - clock()) / 1000)))); // filtered to present jobs
          return;
        }
        // Only an identifier and optional deadline come through the queue.
        // Credentials/destinations are loaded from durable state by the worker.
        await worker.run(message.jobId as string);
        const job = await store.transaction(s => s.jobs[message.jobId as string]);
        if (job && !['accepted', 'dead'].includes(job.state)) {
          const due = Math.max(job.dueAt, job.leaseUntil || 0);
          throw new RetryJob(Math.max(1, Math.min(300, Math.ceil((due - clock()) / 1000))));
        }
      } catch (error) {
        if (metadata.deliveryCount >= handoffAt && !(error instanceof RetryJob && !error.recoverable) &&
            await handoff(message, workKey as string, metadata)) return;
        throw error;
      }
    },
    retry(error: unknown, metadata: QueueMetadata) {
      // The async consumer hands off eligible work before this hard cap. An
      // outage that also prevents all handoff publishes can still exhaust it.
      if (metadata.deliveryCount >= 20) return { acknowledge: true as const };
      return { afterSeconds: error instanceof RetryJob ? error.afterSeconds : 60 };
    },
  };
}
