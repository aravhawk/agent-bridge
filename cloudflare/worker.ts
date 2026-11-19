import { DurableObject } from 'cloudflare:workers';
import type { Request as CFRequest, Response as CFResponse, DurableObjectNamespace, DurableObjectState } from '@cloudflare/workers-types';
import { createRuntime } from '../src/runtime.ts';
import { BridgeError } from '../src/policy.ts';
import { createResourceRouter } from '../src/resource.ts';
import { CONFIG } from '../src/config.ts';
import { decodeStorageKey } from '../src/webhook.ts';
import { SQLiteStore, keyIdentity } from './sqlite-store.ts';
import { authorized, bounded, errorResponse, MAX_TRANSFER_BYTES } from './protocol.ts';
import { remoteEffects } from './effects.ts';
import type { QueueMetadata, QueuePayload } from '../src/queue.ts';

interface Bindings { BRIDGE: DurableObjectNamespace; GATEWAY_KEY: string; MIGRATION_KEY: string;
  EFFECT_KEY: string; EFFECT_ENDPOINT: string; STORE_IDENTITY: string; RUNTIME_ENV: string }
export { default } from './gateway.ts';
export class BridgeObject extends DurableObject<Bindings> {
  readonly store: SQLiteStore;
  readonly runtime: ReturnType<typeof createRuntime>;
  readonly route: ReturnType<typeof createResourceRouter>;
  readonly environment: Readonly<Record<string, string | undefined>>;
  constructor(ctx: DurableObjectState, env: Bindings) {
    super(ctx, env);
    this.store = new SQLiteStore(ctx.storage, env.STORE_IDENTITY);
    const settings: unknown = JSON.parse(env.RUNTIME_ENV);
    if (!settings || typeof settings !== 'object' || Array.isArray(settings) || Object.values(settings).some(v => typeof v !== 'string')) throw Error('backend_configuration_required');
    this.environment = settings as Record<string, string>;
    if (this.environment.BRIDGE_PUBLIC_ORIGIN && this.environment.BRIDGE_PUBLIC_ORIGIN !== CONFIG.origin) throw Error('backend_identity_mismatch');
    if ([env.GATEWAY_KEY, env.MIGRATION_KEY, env.EFFECT_KEY].some(k => !/^[a-f0-9]{64}$/.test(k)) ||
        new Set([env.GATEWAY_KEY, env.MIGRATION_KEY, env.EFFECT_KEY]).size !== 3) throw Error('backend_key_separation_required');
    const effects = remoteEffects(env.EFFECT_ENDPOINT, env.EFFECT_KEY);
    const options = { env: this.environment, durableStore: this.store, queueClient: effects.queue,
      transportFactory: () => effects.transport, attachmentProviderFactory: effects.blob };
    try {
      this.runtime = createRuntime({ ...options,
        taskData: { enabled: true, leaseMs: 60000, linkRetentionMs: 172800000, purgeEnabled: false } });
    } catch (error) {
      if (!(error instanceof BridgeError) || !error.code.startsWith('task_')) throw error;
      // Match api/index.ts: optional task policy cannot disable v1 or migration.
      this.runtime = createRuntime(options);
    }
    this.route = createResourceRouter({ getHandler: role => this.runtime.handler(role), getProvider: () => {
      // Default resourceRouter provider resolution must use the same trusted environment.
      return this.provider();
    } });
  }
  private provider() { return providerConfiguration(this.environment.BRIDGE_OAUTH_ISSUER); }
  override async fetch(request: CFRequest): Promise<CFResponse> {
    return this.handle(request as unknown as Request) as unknown as Promise<CFResponse>;
  }
  private async handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (!authorized(request, path === '/migration' ? this.env.MIGRATION_KEY : this.env.GATEWAY_KEY)) return Response.json({ error: 'unauthorized' }, { status: 401 });
    try {
      if (path === '/migration') {
        const command: unknown = JSON.parse(await bounded(request, MAX_TRANSFER_BYTES));
        if (!command || typeof command !== 'object' || Array.isArray(command)) throw Error();
        const c = command as Record<string, unknown>;
        const key = decodeStorageKey(this.environment.BRIDGE_SUBSCRIPTION_STORAGE_KEY); if (!key) throw Error();
        switch (c.operation) {
          case 'status': return Response.json(this.store.status());
          case 'inspect': if(typeof c.revision!=='number')throw Error();return Response.json(this.store.inspect(c.revision));
          case 'import': return Response.json(this.store.importFrozen(c.transfer, keyIdentity(key)));
          case 'activate':
            if (typeof c.handoff !== 'string' || typeof c.revision !== 'number') throw Error();
            return Response.json(this.store.activate(c.handoff, c.revision));
          case 'freeze':
            if (typeof c.revision !== 'number' || typeof c.target !== 'string') throw Error();
            return Response.json(this.store.freeze(c.revision, c.target));
          default: throw Error();
        }
      }
      if (path === '/queue') {
        const c = JSON.parse(await bounded(request)) as { payload: QueuePayload; metadata: QueueMetadata & { createdAt?: number; expiresAt?: number } };
        const m = c.metadata;
        const { createdAt, expiresAt, ...rest } = m;
        const metadata = { ...rest, ...(typeof createdAt === 'number' ? { createdAt: new Date(createdAt) } : {}),
          ...(typeof expiresAt === 'number' ? { expiresAt: new Date(expiresAt) } : {}) };
        try {
          await this.runtime.consumeQueue(c.payload, metadata);
        } catch (error) {
          const directive = this.runtime.queueRetry(error, metadata);
          if (!directive.acknowledge) {
            return Response.json({ error: 'backend_queue_retry' }, {
              status: 503, headers: { 'retry-after': String(directive.afterSeconds) },
            });
          }
        }
        return Response.json({ ok: true });
      }
      if (path !== '/invoke') return Response.json({ error: 'not_found' }, { status: 404 });
      const url = new URL(request.headers.get('x-bridge-url') || '');
      const method = request.headers.get('x-bridge-method') || '';
      if (url.origin !== CONFIG.origin || !['GET', 'POST', 'DELETE'].includes(method)) return Response.json({ error: 'invalid_params' }, { status: 400 });
      const headers = new Headers();
      for (const name of ['authorization', 'content-type', 'origin', 'upstash-signature']) {
        const value = request.headers.get('x-bridge-original-' + name); if (value !== null) headers.set(name, value);
      }
      const body = await bounded(request);
      const original = new Request(url, { method, headers, ...(method === 'GET' ? {} : { body }) });
      if (url.pathname === '/api/cron') return this.runtime.cronHandler()(original);
      return this.route(original);
    } catch (error) { return errorResponse(error); }
  }
}
import { providerConfiguration } from '../src/resource.ts';
