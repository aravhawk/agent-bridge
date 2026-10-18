import { BridgeError } from './policy.mjs';

// The exact platform header/prefix is REQUIRED from the real native webhook
// setup. No guessed xAI, Cursor or private platform endpoint is built in.
export function createFixedEventSender({ enabled = false, endpoint, approvedOrigin,
  authHeader, authPrefix = '', secret, fetchImpl = fetch }) {
  if (!enabled) throw new BridgeError('delivery_not_enabled', 503);
  let u;
  try { u = new URL(endpoint); } catch { throw new BridgeError('delivery_configuration_required', 503); }
  if (u.protocol !== 'https:' || u.origin !== approvedOrigin || u.username || u.password ||
      u.search || u.hash || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(authHeader || '') ||
      /^(host|cookie|content-type|content-length|connection)$/i.test(authHeader) ||
      /[\r\n]/.test(authPrefix) || typeof secret !== 'string' || !secret || /[\r\n]/.test(secret)) {
    throw new BridgeError('delivery_configuration_required', 503);
  }
  return async envelope => {
    // Destination is closed over; message input can never choose a URL/header.
    let response;
    try {
      response = await fetchImpl(u.href, { method: 'POST', redirect: 'error',
        signal: AbortSignal.timeout(10000),
        headers: { 'content-type': 'application/json', [authHeader]: authPrefix + secret },
        body: JSON.stringify(envelope) });
    } catch { throw new BridgeError('delivery_transport_failed', 503); }
    // Do not read an arbitrary response body; it could echo credentials or URLs.
    await response.body?.cancel().catch(() => {});
    if (!response.ok) throw new BridgeError('delivery_rejected', response.status === 429 ? 429 : 503);
    return { messageId: envelope.id, transportAccepted: true, status: response.status };
  };
}
