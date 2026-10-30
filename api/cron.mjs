import { runtime } from '../src/runtime.mjs';
let handler;
// Vercel cron target for the SYNC batch flush. Authentication (CRON_SECRET),
// readiness and the Chicago even-hour check all live in runtime.cronHandler.
export default { async fetch(request) {
  try { handler ||= runtime.cronHandler(); return await handler(request); }
  catch { return Response.json({ error: 'cron_unavailable' }, { status: 503 }); }
} };
