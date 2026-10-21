import { QUEUE_TOPIC } from './release.mjs';
import { dailyMessage, retainMessages, CONTENT_RETENTION_MS } from './messages.mjs';
import { BridgeError } from './policy.mjs';
import { digest } from './events.mjs';

export const TOPIC = QUEUE_TOPIC;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const idPattern = /^job_[a-f0-9]{64}$/;
class RetryJob extends Error {
  constructor(afterSeconds, recoverable = true) { super('bridge_job_pending'); this.afterSeconds = afterSeconds; this.recoverable = recoverable; }
}
const recoveryBudgetMs = 3600000, handoffAt = 18;
export function createQueueAdapter({ client, store, worker, enabled = false, maintenanceEnabled = false, clock = Date.now }) {
  const gate = () => { if (!enabled) throw new BridgeError('queue_not_enabled', 503); };
  async function publish(payload, key, delaySeconds = 1) {
    await client.send(TOPIC, payload, { region: 'iad1', delaySeconds,
      retentionSeconds: Math.min(604800, Math.max(3600, delaySeconds + 3600)), idempotencyKey: key });
  }
  async function handoff(message, workKey, metadata) {
    const createdAt = metadata.createdAt?.getTime?.(), expiresAt = metadata.expiresAt?.getTime?.();
    if (!Number.isSafeInteger(createdAt) || createdAt > clock() ||
        !Number.isSafeInteger(expiresAt) || expiresAt <= createdAt ||
        typeof metadata.messageId !== 'string' || !metadata.messageId || metadata.messageId.length > 256)
      throw new BridgeError('queue_recovery_metadata_required', 503);
    const until = Math.min(expiresAt, createdAt + recoveryBudgetMs, message.recoveryUntil ?? Infinity);
    const remaining = Math.floor((until - clock()) / 1000);
    if (remaining <= 60) return false;
    // Publish before acknowledging the old item, outside the synchronous SDK
    // retry hook. Ambiguous publishes reuse the same key. Every descendant
    // retains the absolute deadline, including across delayed commits/restarts.
    await client.send(TOPIC, { [workKey]: message[workKey], recoveryUntil: until },
      { region: 'iad1', delaySeconds: 60, retentionSeconds: remaining,
        idempotencyKey: 'recovery:' + digest(JSON.stringify([metadata.messageId, until])) });
    return true;
  }
  return {
    async prepareMessage(id) {
      gate(); if (!uuid.test(id)) throw new BridgeError('invalid_message_id', 400);
      await publish({ cleanupMessageId: id }, `cleanup:${id}:content`, CONTENT_RETENTION_MS / 1000);
      await publish({ dispatchMessageId: id }, `dispatch:${id}:${Math.floor(clock() / 60000)}`);
    },
    async prepareReceipt(id) {
      gate(); if (!uuid.test(id)) throw new BridgeError('invalid_message_id', 400);
      await publish({ dispatchReceiptOf: id }, `receipt:${id}:${Math.floor(clock() / 60000)}`);
    },
    async scheduleJobs(ids) {
      gate();
      if (!Array.isArray(ids) || ids.length > 100 || ids.some(id => !idPattern.test(id))) {
        throw new BridgeError('invalid_job_ids', 400);
      }
      for (const id of [...new Set(ids)]) {
        const job = await store.transaction(s => s.jobs[id]);
        if (!job || ['accepted', 'dead'].includes(job.state)) continue;
        const due = Math.max(job.dueAt, job.leaseUntil || 0);
        const now = clock();
        // DB identity and fencing own idempotence. The epoch allows explicit
        // backend reconciliation to recover a previously exhausted queue item.
        await client.send(TOPIC, { jobId: id }, { region: 'iad1', retentionSeconds: 3600,
          delaySeconds: Math.max(0, Math.ceil((due - now) / 1000)),
          idempotencyKey: `${id}:${job.attempts}:${job.leaseId || 'pending'}:${Math.floor(now / 600000)}` });
      }
    },
    async consume(message, metadata) {
      if (metadata.topicName !== TOPIC || metadata.region !== 'iad1') return;
      const key = message && Object.keys(message).length === 1 ? Object.keys(message)[0] : null;
      if (key === 'cleanupMessageId' && maintenanceEnabled && uuid.test(message[key])) {
        const next = await store.transaction(state => {
          retainMessages(state, clock());
          return state.messages[message[key]]?.retainUntil || state.messageIds?.[message[key]]?.until;
        });
        // Chain one delayed native cleanup for the remaining tombstone. No
        // receiving assistant, clock daemon or interval participates.
        if (next > clock()) await publish(message, `cleanup:${message[key]}:${next}`,
          Math.max(1, Math.ceil((next - clock()) / 1000)));
        return;
      }
      gate();
      // A continuation retains one identifier and one absolute deadline. The
      // private SDK supplies metadata; request callers cannot publish payloads.
      const keys = message && Object.keys(message);
      const workKey = keys?.find(k => k !== 'recoveryUntil');
      const dispatch = ['dispatchMessageId', 'dispatchReceiptOf'].includes(workKey) && uuid.test(message[workKey]);
      const direct = workKey === 'jobId' && idPattern.test(message[workKey]);
      if ((!dispatch && !direct) || keys.some(k => k !== workKey && k !== 'recoveryUntil')) return;
      if (Object.hasOwn(message, 'recoveryUntil') &&
          (!Number.isSafeInteger(message.recoveryUntil) || message.recoveryUntil <= clock())) return;
      try {
        if (dispatch) {
          const ids = await store.transaction(state => {
            const id = workKey === 'dispatchMessageId' ? message[workKey] : state.receipts[message[workKey]]?.ackMessageId;
            const saved = state.messages[id];
            return dailyMessage(saved?.envelope) ? saved.jobIds : null;
          });
          if (!ids) throw new RetryJob(5, false); // An absent commit must not spawn continuations.
          // Missing commits get 20 x 5-second retries. Preparation keys rotate
          // each minute so a later sender retry cannot reuse an exhausted item.
          for (const id of ids) await worker.run(id);
          const pending = await store.transaction(state => ids.map(id => state.jobs[id]).filter(job => job && !['accepted', 'dead'].includes(job.state)));
          if (pending.length) throw new RetryJob(Math.max(1, Math.min(300,
            Math.ceil((Math.min(...pending.map(job => Math.max(job.dueAt, job.leaseUntil || 0))) - clock()) / 1000))));
          return;
        }
        // Only an identifier and optional deadline come through the queue.
        // Credentials/destinations are loaded from durable state by the worker.
        await worker.run(message.jobId);
        const job = await store.transaction(s => s.jobs[message.jobId]);
        if (job && !['accepted', 'dead'].includes(job.state)) {
          const due = Math.max(job.dueAt, job.leaseUntil || 0);
          throw new RetryJob(Math.max(1, Math.min(300, Math.ceil((due - clock()) / 1000))));
        }
      } catch (error) {
        if (metadata.deliveryCount >= handoffAt && !(error instanceof RetryJob && !error.recoverable) &&
            await handoff(message, workKey, metadata)) return;
        throw error;
      }
    },
    retry(error, metadata) {
      // The async consumer hands off eligible work before this hard cap. An
      // outage that also prevents all handoff publishes can still exhaust it.
      if (metadata.deliveryCount >= 20) return { acknowledge: true };
      return { afterSeconds: error instanceof RetryJob ? error.afterSeconds : 60 };
    },
  };
}
