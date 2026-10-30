import { runtime } from '../src/runtime.mjs';
let handler;
// Hourly trigger target (GitHub Actions POST) for the SYNC batch flush.
// Authentication (CRON_SECRET), readiness and the Chicago even-hour window
// all live in runtime.cronHandler.
export default { async fetch(request) {
  try { handler ||= runtime.cronHandler(); return await handler(request); }
  catch { return Response.json({ error: 'cron_unavailable' }, { status: 503 }); }
} };
