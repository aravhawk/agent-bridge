import { QueueClient } from '@vercel/queue';
import { BridgeError } from '../src/policy.ts';
import { PUBLIC_ORIGIN, QUEUE_REGION } from '../src/release.ts';
import { createCloudflareFrontend } from './frontend.ts';
import { errorResponse } from './protocol.ts';
import type { Env } from '../src/config.ts';
import type { QueuePayload } from '../src/queue.ts';
import type { Fetcher } from './protocol.ts';

export function selectStateBackend(env: Env, fetcher?: Fetcher) {
  switch (env.BRIDGE_STATE_BACKEND) {
    case undefined:
    case 'postgres':
      return null;
    case 'paused':
      throw new BridgeError('bridge_migration_paused', 503);
    case 'cloudflare':
      return createCloudflareFrontend({ endpoint: env.BRIDGE_CLOUDFLARE_ORIGIN ?? '',
        key: env.BRIDGE_CLOUDFLARE_GATEWAY_KEY ?? '', ...(fetcher ? { fetcher } : {}) });
    default:
      throw new BridgeError('backend_configuration_required', 503);
  }
}

export function createVercelQueueClient() {
  return new QueueClient({ region: QUEUE_REGION, telemetry: { isEnabled: false } });
}

export function cloudflareQueueHandler(frontend: NonNullable<ReturnType<typeof selectStateBackend>>, client = createVercelQueueClient()) {
  return client.handleCallback<QueuePayload>((payload, metadata) => frontend.consume(payload, metadata),
    { visibilityTimeoutSeconds: 60, retry: (error, metadata) => {
      if (metadata.deliveryCount >= 20) return { acknowledge: true };
      const afterSeconds = error instanceof BridgeError ? error.details?.retryAfterSeconds : undefined;
      return { afterSeconds: typeof afterSeconds === 'number' ? afterSeconds : 60 };
    } });
}

export async function routeStateRequest(request: Request, postgres: (request: Request) => Response | Promise<Response>,
  env: Env = process.env, fetcher?: Fetcher) {
  try {
    const frontend = selectStateBackend(env, fetcher);
    const url = new URL(request.url);
    if (frontend && request.method === 'GET' && ['/', '/health'].includes(url.pathname) && url.origin !== PUBLIC_ORIGIN) {
      return await frontend.fetch(new Request(PUBLIC_ORIGIN + url.pathname + url.search, request));
    }
    return await (frontend ? frontend.fetch(request) : postgres(request));
  } catch (error) { return errorResponse(error); }
}
