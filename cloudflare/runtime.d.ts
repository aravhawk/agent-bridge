// Narrow declaration for the native workerd base class; HTTP conversion is explicit at its boundary.
declare module 'cloudflare:workers' {
  import type { DurableObjectState, Request, Response } from '@cloudflare/workers-types';
  export abstract class DurableObject<Env> {
    protected env: Env;
    constructor(ctx: DurableObjectState, env: Env);
    fetch?(request: Request): Promise<Response>;
  }
}
