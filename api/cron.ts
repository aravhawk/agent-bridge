import { runtime } from '../src/runtime.ts';
let handler: ((request: Request) => Promise<Response>) | undefined;
// Scheduled trigger target (QStash-signed, or any scheduler with the bearer) for the SYNC flush.
// Authentication (CRON_SECRET), readiness and the Chicago even-hour window
// all live in runtime.cronHandler.
export default { async fetch(request: Request) {
  try { handler ||= runtime.cronHandler(); return await handler(request); }
  catch { return Response.json({ error: 'cron_unavailable' }, { status: 503 }); }
} };
