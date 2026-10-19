import { runtime } from '../src/runtime.mjs';
let consumer;
export default { async fetch(request) {
  if (process.env.BRIDGE_DELIVERY_ENABLED !== 'true' && process.env.BRIDGE_DAILY_ENABLED !== 'true') {
    return Response.json({ error: 'delivery_not_enabled' }, { status: 503 });
  }
  // queue/v2beta consumers have no public URL. Preserve the trusted internal
  // callback's receipt/payload so the official SDK can finish its leased item.
  try { consumer ||= runtime.queueHandler(); return await consumer(request); }
  catch { return Response.json({ error: 'queue_unavailable' }, { status: 503 }); }
} };
