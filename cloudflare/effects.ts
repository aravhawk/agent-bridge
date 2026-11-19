import { BridgeError } from '../src/policy.ts';
import { createPublicWebhookTransport } from '../src/webhook.ts';
import { attachmentConfig, createBlobProvider, ATTACHMENT_KEY, HARD_MAX_BYTES } from '../src/blob.ts';
import { QUEUE_TOPIC, QUEUE_REGION } from '../src/release.ts';
import { authorized, bounded, errorResponse } from './protocol.ts';
import type { RuntimeQueueClient } from '../src/runtime.ts';
import type { BlobProvider, ValidAttachmentConfig } from '../src/blob.ts';
import type { Env } from '../src/config.ts';
import type { WebhookTransport } from '../src/webhook.ts';
import type { Fetcher } from './protocol.ts';
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BridgeError('invalid_params', 400);
  return value as Record<string, unknown>;
}
function integer(value: unknown, min: number, max: number): value is number { return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max; }
// Existing Vercel SDKs remain in their original deployment identity. No Blob bytes or state documents cross this interface.
export function createEffectHandler({ key, queue, env, transport = createPublicWebhookTransport({ enabled: true }), blob = config => createBlobProvider({ config }) }:
  { key: string; queue: RuntimeQueueClient; env: Env; transport?: WebhookTransport; blob?: (config: ValidAttachmentConfig) => BlobProvider }) {
  return async (request: Request): Promise<Response> => {
    if (request.method !== 'POST' || !authorized(request, key)) return Response.json({ error: 'unauthorized' }, { status: 401 });
    try {
      const input: unknown = JSON.parse(await bounded(request));
      if (!input || typeof input !== 'object' || Array.isArray(input)) throw new BridgeError('invalid_params', 400);
      const { operation, args } = input as { operation?: unknown; args?: unknown };
      if (!Array.isArray(args) || Object.keys(input).sort().join(',') !== 'args,operation') throw new BridgeError('invalid_params', 400);
      const values: unknown[] = args;
      if (operation === 'queue.send') {
        const [topic, rawPayload, rawOptions] = values; const payload = record(rawPayload), options = record(rawOptions);
        if (values.length !== 3 || topic !== QUEUE_TOPIC || options.region !== QUEUE_REGION ||
          !integer(options.delaySeconds, 0, 604800) || !integer(options.retentionSeconds, 1, 604800) ||
          typeof options.idempotencyKey !== 'string' || !/^[\x21-\x7e]{1,512}$/.test(options.idempotencyKey)) throw new BridgeError('invalid_params', 400);
        const keys = Object.keys(payload); const work = keys.filter(k => k !== 'recoveryUntil');
        if (work.length !== 1 || !['jobId', 'dispatchMessageId', 'dispatchReceiptOf', 'cleanupMessageId'].includes(work[0]!) ||
          typeof payload[work[0]!] !== 'string' ||
          !(work[0] === 'jobId' ? /^job_[a-f0-9]{64}$/ : /^[a-f0-9-]{36}$/).test(payload[work[0]!] as string) ||
          (keys.includes('recoveryUntil') && !integer(payload.recoveryUntil, 1, Number.MAX_SAFE_INTEGER))) throw new BridgeError('invalid_params', 400);
        await queue.send(QUEUE_TOPIC, payload, { region: QUEUE_REGION, delaySeconds: options.delaySeconds,
          retentionSeconds: options.retentionSeconds, idempotencyKey: options.idempotencyKey }); return Response.json({ ok: true });
      }
      if (operation === 'webhook.post') {
        const request = record(values[1]), h = record(request.headers);
        const names = ['content-type', 'webhook-id', 'webhook-timestamp', 'webhook-signature', 'x-mcp-subscription-id', 'authorization'];
        if (values.length !== 2 || typeof values[0] !== 'string' || typeof request.body !== 'string' || Buffer.byteLength(request.body) > 256 * 1024 ||
          Object.entries(h).some(([k,v]) => !names.includes(k.toLowerCase()) || typeof v !== 'string' || v.length > 8192 || /[\r\n]/.test(v))) throw new BridgeError('invalid_params', 400);
        const headers = Object.fromEntries(Object.entries(h).map(([k,v])=>[k, v as string]));
        return Response.json(await transport(values[0], { body: request.body, headers }));
      }
      const config = attachmentConfig(env); if (!config.valid) throw new BridgeError('attachments_not_configured', 503);
      const provider = blob(config);
      if (values.length !== 1) throw new BridgeError('invalid_params', 400);
      const presign = () => { const v = record(values[0]);
        if (typeof v.key !== 'string' || !ATTACHMENT_KEY.test(v.key) || !integer(v.validUntil, Date.now()+1000, Date.now()+15*60000)) throw new BridgeError('invalid_params',400);
        return {key:v.key,validUntil:v.validUntil}; };
      switch (operation) {
        case 'blob.presignUpload': { const v=presign(), raw=record(values[0]);if(!integer(raw.size,1,HARD_MAX_BYTES))throw new BridgeError('invalid_params',400);return Response.json(await provider.presignUpload({...v,size:raw.size})); }
        case 'blob.presignGet': return Response.json(await provider.presignGet(presign()));
        case 'blob.head': if(typeof values[0]!=='string'||!ATTACHMENT_KEY.test(values[0]))throw new BridgeError('invalid_params',400);return Response.json(await provider.head(values[0]));
        // Physical deletion is deliberately absent (no retention-policy adoption).
        default: throw new BridgeError('invalid_params', 400);
      }
    } catch (error) { return errorResponse(error); }
  };
}
export function remoteEffects(endpoint: string, key: string, fetcher: Fetcher = request => fetch(request)) {
  const url = new URL(endpoint);
  if (url.protocol !== 'https:' || url.pathname !== '/api/bridge-effects' || url.search || url.hash || url.username || url.password ||
      !/^[a-f0-9]{64}$/.test(key)) throw new BridgeError('backend_effect_configuration_required', 503);
  async function call<T>(operation: string, args: unknown[]): Promise<T> {
    const req = new Request(url.href, { method: 'POST', headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
      body: JSON.stringify({ operation, args }), signal: AbortSignal.timeout(15000), redirect: 'manual' });
    const response = await fetcher(req);
    if (!response.ok) throw new BridgeError('backend_effect_unavailable', 503);
    const text = await bounded(response);
    return JSON.parse(text) as T; // Authenticated closed adapter; core validates provider results again.

  }
  return {
    queue: { send: (...args: Parameters<RuntimeQueueClient['send']>) => call('queue.send', args) } satisfies RuntimeQueueClient,
    transport: ((...args) => call('webhook.post', args)) satisfies WebhookTransport,
    blob: (config: ValidAttachmentConfig): BlobProvider => ({ namespace: config.namespace, kind: 'vercel-blob',
      presignUpload: input => call('blob.presignUpload', [input]), presignGet: input => call('blob.presignGet', [input]),
      head: input => call('blob.head', [input]), delete: async () => { throw new BridgeError('attachment_retention_not_approved', 503); } }),
  };
}
