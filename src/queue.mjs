import { BridgeError } from './policy.mjs';

export const TOPIC = 'rn-jarvis-friday-synthetic-20261018';
const idPattern = /^job_[a-f0-9]{64}$/;
class RetryJob extends Error {
  constructor(afterSeconds) { super('bridge_job_pending'); this.afterSeconds = afterSeconds; }
}
export function createQueueAdapter({ client, store, worker, enabled = false, clock = Date.now }) {
  const gate = () => { if (!enabled) throw new BridgeError('queue_not_enabled', 503); };
  return {
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
      gate();
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
