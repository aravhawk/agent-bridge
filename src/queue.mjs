import { dailyMessage, retainMessages, CONTENT_RETENTION_MS } from './messages.mjs';
import { BridgeError } from './policy.mjs';

export const TOPIC = 'rn-jarvis-friday-synthetic-20261018';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const idPattern = /^job_[a-f0-9]{64}$/;
class RetryJob extends Error {
  constructor(afterSeconds) { super('bridge_job_pending'); this.afterSeconds = afterSeconds; }
}
export function createQueueAdapter({ client, store, worker, enabled = false, maintenanceEnabled = false, clock = Date.now }) {
  const gate = () => { if (!enabled) throw new BridgeError('queue_not_enabled', 503); };
  async function publish(payload, key, delaySeconds = 1) {
    await client.send(TOPIC, payload, { region: 'iad1', delaySeconds,
      retentionSeconds: Math.min(604800, Math.max(3600, delaySeconds + 3600)), idempotencyKey: key });
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
      if (['dispatchMessageId', 'dispatchReceiptOf'].includes(key) && uuid.test(message[key])) {
        const ids = await store.transaction(state => {
          const id = key === 'dispatchMessageId' ? message[key] : state.receipts[message[key]]?.ackMessageId;
          const saved = state.messages[id];
          return dailyMessage(saved?.envelope) ? saved.jobIds : null;
        });
        if (!ids) throw new RetryJob(5); // Prearmed work may precede DB commit.
        // Missing commits get 20 x 5-second retries. Preparation keys rotate
        // each minute so a later sender retry cannot reuse an exhausted item.
        for (const id of ids) await worker.run(id);
        const pending = await store.transaction(state => ids.map(id => state.jobs[id]).filter(job => job && !['accepted', 'dead'].includes(job.state)));
        if (pending.length) throw new RetryJob(Math.max(1, Math.min(300,
          Math.ceil((Math.min(...pending.map(job => Math.max(job.dueAt, job.leaseUntil || 0))) - clock()) / 1000))));
        return;
      }
      // Only a job identifier comes through the queue. Credentials and callback
      // destinations are loaded from the scoped durable store by the worker.
      if (!message || Object.keys(message).length !== 1 || !idPattern.test(message.jobId || '') ||
          metadata.topicName !== TOPIC || metadata.region !== 'iad1') return;
      await worker.run(message.jobId);
      const job = await store.transaction(s => s.jobs[message.jobId]);
      if (job && !['accepted', 'dead'].includes(job.state)) {
        const due = Math.max(job.dueAt, job.leaseUntil || 0);
        throw new RetryJob(Math.max(1, Math.min(300, Math.ceil((due - clock()) / 1000))));
      }
    },
    retry(error, metadata) {
      // A bounded SDK retry budget complements the durable worker's five actual
      // delivery attempts. Unfinished state stays available for reconciliation.
      if (metadata.deliveryCount >= 20) return { acknowledge: true };
      return { afterSeconds: error instanceof RetryJob ? error.afterSeconds : 60 };
    },
  };
}
