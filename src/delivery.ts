import { BridgeError } from './policy.ts';
import type { Envelope } from './types.ts';

// The exact platform header/prefix is REQUIRED from the real native webhook
// setup. No guessed xAI, Cursor or private platform endpoint is built in.
export interface FixedEventSenderOptions {
  enabled?: boolean; endpoint?: string | undefined; approvedOrigin?: string | undefined; authHeader?: string | undefined;
  authPrefix?: string; secret?: string | undefined; fetchImpl?: typeof fetch;
}
export interface FixedSendResult { messageId: string; transportAccepted: true; status: number }
export function createFixedEventSender({ enabled = false, endpoint, approvedOrigin,
  authHeader, authPrefix = '', secret, fetchImpl = fetch }: FixedEventSenderOptions): (envelope: Envelope) => Promise<FixedSendResult> {
  if (!enabled) throw new BridgeError('delivery_not_enabled', 503);
  let u!: URL;
  try { u = new URL(endpoint as string); } catch { throw new BridgeError('delivery_configuration_required', 503); }
  if (u.protocol !== 'https:' || u.origin !== approvedOrigin || u.username || u.password ||
      u.search || u.hash || !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(authHeader || '') ||
      /^(host|cookie|content-type|content-length|connection)$/i.test(authHeader as string) ||
      /[\r\n]/.test(authPrefix) || typeof secret !== 'string' || !secret || /[\r\n]/.test(secret)) {
    throw new BridgeError('delivery_configuration_required', 503);
  }
  return async (envelope: Envelope): Promise<FixedSendResult> => {
    // Destination is closed over; message input can never choose a URL/header.
    let response!: Response;
    try {
      response = await fetchImpl(u.href, { method: 'POST', redirect: 'error',
        signal: AbortSignal.timeout(10000),
        // authHeader was validated above.
        headers: { 'content-type': 'application/json', [authHeader as string]: authPrefix + secret },
        body: JSON.stringify(envelope) });
    } catch { throw new BridgeError('delivery_transport_failed', 503); }
    // Do not read an arbitrary response body; it could echo credentials or URLs.
    await response.body?.cancel().catch(() => {});
    if (!response.ok) throw new BridgeError('delivery_rejected', response.status === 429 ? 429 : 503);
    return { messageId: envelope.id, transportAccepted: true, status: response.status };
  };
}
