import { createEffectHandler } from '../cloudflare/effects.ts';
import { createVercelQueueClient } from '../cloudflare/vercel.ts';

let handler: ReturnType<typeof createEffectHandler> | undefined;
export default { fetch(request: Request) {
  if (process.env.BRIDGE_STATE_BACKEND !== 'cloudflare' || !/^[a-f0-9]{64}$/.test(process.env.BRIDGE_CLOUDFLARE_EFFECT_KEY ?? '')) {
    return Response.json({ error: 'not_found' }, { status: 404 });
  }
  handler ||= createEffectHandler({ key: process.env.BRIDGE_CLOUDFLARE_EFFECT_KEY!, queue: createVercelQueueClient(), env: process.env });
  return handler(request);
} };
