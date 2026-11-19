import type { DurableObjectNamespace } from '@cloudflare/workers-types';
import { authorized } from './protocol.ts';
interface Bindings { BRIDGE: DurableObjectNamespace; GATEWAY_KEY: string; MIGRATION_KEY: string }
/** Thin gateway: authenticate fixed-size secret, validate route, stream to ONE named object. No state or JSON parsing here. */
export default {
  async fetch(request: Request, env: Bindings): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (!['/invoke', '/queue', '/migration'].includes(path) || request.method !== 'POST') return Response.json({ error: 'not_found' }, { status: 404 });
    if (!authorized(request, path === '/migration' ? env.MIGRATION_KEY : env.GATEWAY_KEY)) return Response.json({ error: 'unauthorized' }, { status: 401 });
    const id = env.BRIDGE.idFromName('bridge-runtime-v1');
    // Native Worker and Node use structurally identical Fetch HTTP objects here.
    return env.BRIDGE.get(id).fetch(request as unknown as Parameters<ReturnType<DurableObjectNamespace['get']>['fetch']>[0]) as unknown as Promise<Response>;
  },
};
