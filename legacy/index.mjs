import { handleDiagnostic } from './diagnostic.mjs';
// Synthetic discovery probe only. No storage, credentials, outbound requests,
// subscriptions, message delivery, agent work, or OAuth token issuance.
const VERSION = '0.1.0';
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26'];
const HEALTH = Object.freeze({
  status: 'ok', probe: 'RN-20261018-VERCEL-DISCOVERY', version: VERSION,
  messageDelivery: false, events: false, oauthConfigured: false,
});
const HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};
const json = (body, status = 200, headers = {}) =>
  Response.json(body, { status, headers: { ...HEADERS, ...headers } });
const error = (id, code, message, status = 200) =>
  json({ jsonrpc: '2.0', id, error: { code, message } }, status);

export async function handle(request) {
  const diagnostic = await handleDiagnostic(request);
  if (diagnostic) return diagnostic;
  const url = new URL(request.url);
  // Reject browser cross-origin requests. Non-browser MCP clients omit Origin.
  const origin = request.headers.get('origin');
  if (origin && origin !== url.origin) return json({ error: 'Forbidden origin' }, 403);
  if (request.method === 'GET' && ['/', '/health', '/probe-info'].includes(url.pathname)) {
    return json(HEALTH);
  }
  // Intentionally fail closed until an approved real OAuth provider is configured.
  // Never advertise invented authorization endpoints or accept bearer credentials.
  if (url.pathname === '/protected/mcp' || url.pathname.startsWith('/.well-known/')) {
    return json({ error: 'oauth_not_configured', message: 'No authorization server or grants exist for this probe.' }, 503);
  }
  if (url.pathname !== '/mcp') return json({ error: 'Not found' }, 404);
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  const type = request.headers.get('content-type') || '';
  if (!/^application\/json(?:\s*;|$)/i.test(type)) return json({ error: 'JSON required' }, 415);
  const accept = request.headers.get('accept') || '';
  if (!accept.includes('application/json') || !accept.includes('text/event-stream')) {
    return json({ error: 'Accept must include application/json and text/event-stream' }, 406);
  }
  const length = Number(request.headers.get('content-length'));
  if (length > 8192) return json({ error: 'Request too large' }, 413);
  let raw = '';
  let total = 0;
  const reader = request.body?.getReader();
  const decoder = new TextDecoder();
  if (reader) {
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > 8192) { await reader.cancel(); return json({ error: 'Request too large' }, 413); }
        raw += decoder.decode(value, { stream: true });
      }
      raw += decoder.decode();
    } catch { return json({ error: 'Request unreadable' }, 400); }
  }
  let rpc;
  try { rpc = JSON.parse(raw); } catch { return error(null, -32700, 'Parse error', 400); }
  if (!rpc || Array.isArray(rpc) || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
    return error(null, -32600, 'Invalid request', 400);
  }
  const hasId = Object.hasOwn(rpc, 'id');
  if (hasId && !(typeof rpc.id === 'string' || Number.isSafeInteger(rpc.id))) {
    return error(null, -32600, 'Invalid request id', 400);
  }
  if (!hasId) {
    if (rpc.method === 'notifications/initialized') return new Response(null, { status: 202, headers: HEADERS });
    return new Response(null, { status: 202, headers: HEADERS });
  }
  const id = rpc.id;
  if (rpc.method === 'initialize') {
    const requested = rpc.params?.protocolVersion;
    return json({ jsonrpc: '2.0', id, result: {
      protocolVersion: PROTOCOLS.includes(requested) ? requested : PROTOCOLS[0],
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'rn-jarvis-friday-discovery-probe', version: VERSION },
      instructions: 'Synthetic health-only probe. Message delivery, events and OAuth are unavailable.',
    } });
  }
  const protocol = request.headers.get('mcp-protocol-version');
  if (protocol && !PROTOCOLS.includes(protocol)) return json({ error: 'Unsupported MCP protocol version' }, 400);
  if (rpc.method === 'ping') return json({ jsonrpc: '2.0', id, result: {} });
  if (rpc.method === 'tools/list') return json({ jsonrpc: '2.0', id, result: { tools: [{
    name: 'probe_health', description: 'Return fixed synthetic probe readiness; no side effects.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }] } });
  if (rpc.method === 'tools/call') {
    const args = rpc.params?.arguments;
    if (rpc.params?.name !== 'probe_health' || (args !== undefined &&
      (!args || Array.isArray(args) || typeof args !== 'object' || Object.keys(args).length))) {
      return error(id, -32602, 'Only probe_health with empty arguments is available');
    }
    return json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(HEALTH) }], isError: false } });
  }
  return error(id, -32601, 'Method not available in this discovery-only probe');
}

export default { fetch: handle };
