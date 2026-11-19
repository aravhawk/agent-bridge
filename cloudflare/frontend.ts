import { BridgeError } from '../src/policy.ts';
import type { Fetcher } from './protocol.ts';
import type { QueueMetadata, QueuePayload } from '../src/queue.ts';
/** Constructor-only prototype. api/* remain on Postgres until an approved cutover. */
export function createCloudflareFrontend({ endpoint, key, fetcher = request => fetch(request) }: { endpoint: string; key: string; fetcher?: Fetcher }) {
  const base = new URL(endpoint);
  if (base.protocol !== 'https:' || base.origin !== endpoint || !/^[a-f0-9]{64}$/.test(key)) throw new BridgeError('backend_configuration_required', 503);
  const headers = () => new Headers({ authorization: 'Bearer ' + key });
  return {
    async fetch(request: Request): Promise<Response> {
      const h = headers(); h.set('x-bridge-url', request.url); h.set('x-bridge-method', request.method);
      for (const name of ['authorization', 'content-type', 'origin', 'upstash-signature']) {
        const value = request.headers.get(name); if (value !== null) h.set('x-bridge-original-' + name, value);
      }
      return fetcher(new Request(endpoint + '/invoke', { method: 'POST', headers: h, redirect: 'manual',
        body: request.body, ...(request.body ? { duplex: 'half' } : {}), signal: AbortSignal.timeout(55000) }));
    },
    // Wire ONLY behind the existing official queue SDK's handleCallback. Never mount as a public queue route.
    async consume(payload: QueuePayload, metadata: QueueMetadata): Promise<void> {
      const h = headers(); h.set('content-type', 'application/json');
      const r = await fetcher(new Request(endpoint + '/queue', { method: 'POST', headers: h, redirect: 'manual', signal: AbortSignal.timeout(55000),
        body: JSON.stringify({ payload, metadata: { ...metadata,
          createdAt: metadata.createdAt?.getTime?.(), expiresAt: metadata.expiresAt?.getTime?.() } }) }));
      if (!r.ok) {
        const header = r.headers.get('retry-after');
        const seconds = header && /^\d{1,3}$/.test(header) ? Number(header) : 60;
        throw new BridgeError('backend_queue_retry', 503, {
          retryAfterSeconds: seconds >= 1 && seconds <= 300 ? seconds : 60,
        });
      }
    },
  };
}
