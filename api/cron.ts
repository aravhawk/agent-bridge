import { runtime } from '../src/runtime.ts';
import { routeStateRequest } from '../cloudflare/vercel.ts';
let handler: ((request: Request) => Promise<Response>) | undefined;
// Scheduled trigger target (QStash-signed, or any scheduler with the bearer) for the SYNC flush.
// Authentication (CRON_SECRET), readiness and the Chicago even-hour window
// all live in runtime.cronHandler.
export default { async fetch(request: Request) {
  return routeStateRequest(request, async original => {
    try { handler ||= runtime.cronHandler(); return await handler(original); }
    catch { return Response.json({ error: 'cron_unavailable' }, { status: 503 }); }
  });
} };
