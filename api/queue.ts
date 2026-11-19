import { runtime } from '../src/runtime.ts';
import { cloudflareQueueHandler, selectStateBackend } from '../cloudflare/vercel.ts';
let consumer: ((request: Request) => Promise<Response>) | undefined;
export default { async fetch(request: Request) {
  // queue/v2beta consumers have no public URL. Preserve the trusted internal
  // callback's receipt/payload so the official SDK can finish its leased item.
  try {
    if (!consumer) {
      const frontend = selectStateBackend(process.env);
      if (!frontend && !process.env.DATABASE_URL) return Response.json({ error: 'storage_configuration_required' }, { status: 503 });
      consumer = frontend ? cloudflareQueueHandler(frontend) : runtime.queueHandler();
    }
    return await consumer(request);
  }
  catch { return Response.json({ error: 'queue_unavailable' }, { status: 503 }); }
} };
