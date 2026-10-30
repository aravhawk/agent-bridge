import { randomUUID } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.mjs';
import { EVENT_NAME, digest } from './events.mjs';
import { createWebhookSender, webhookSenderConfigured } from './webhook-sender.mjs';
import { RECEIVER_ID } from './release.mjs';
import { EVENTS_PEER, WEBHOOK_PEER, NAMES, peerCode } from './config.mjs';

const fail = (code, status = 503) => { throw new BridgeError(code, status); };
export const DIAGNOSTIC_MAX_WINDOW_MS = 2 * 3600000;

// Fixed operator interval, shared across instances/restarts. Validate its full
// duration, not its remaining lifetime: an overlong arm must never open later.
export function diagnosticWindowOpen(from, until, now, maxWindowMs = DIAGNOSTIC_MAX_WINDOW_MS) {
  const start = typeof from === 'string' ? Date.parse(from) : NaN;
  const end = typeof until === 'string' ? Date.parse(until) : NaN;
  return Number.isSafeInteger(start) && Number.isSafeInteger(end) && Number.isSafeInteger(now) &&
    end > start && end - start <= maxWindowMs && start <= now && now < end;
}
const view = (record, duplicate) => ({ messageId: record.messageId, receiverId: record.receiverId,
  attemptedAt: new Date(record.attemptedAt).toISOString(), duplicate,
  transport: record.outcome ? { status: record.outcome.status, error: record.outcome.error }
    : { status: null, error: 'outcome_not_recorded' },
  wakeVerified: false, evidenceRequired: `native_${NAMES.prefix}_run_with_exact_messageId` });

// One synthetic webhook-peer event for the whole deployment lifetime, transport
// evidence only. No stored message exists, so a native read of this UUID
// reports message_not_found. The spend marker commits under the state row lock
// BEFORE the request starts: concurrent calls, restarts, timeouts and lost
// outcomes can only return the recorded attempt, never send another. Caller
// input chooses nothing; destination, key and body are server configuration.
export function createWebhookDiagnostic({ store, endpoint, secret, auth = 'bearer', transport, from, until, clock = Date.now }) {
  const key = NAMES.diagnosticState;
  return async principal => {
    if (principal?.role !== EVENTS_PEER || !principal.scopes?.includes(SCOPES[EVENTS_PEER].probe)) fail('insufficient_scope', 403);
    // Repairable configuration must fail before the single attempt is spent.
    if (!webhookSenderConfigured({ endpoint, secret, auth })) fail(peerCode('sender_configuration_required'));
    const claimed = await store.transaction(state => {
      const now = clock();
      if (state[key]) return { record: state[key], duplicate: true };
      if (!diagnosticWindowOpen(from, until, now)) fail(peerCode('diagnostic_not_armed'));
      state[key] = { messageId: randomUUID(), receiverId: RECEIVER_ID,
        owner: principal.principalKey,
        attemptedAt: now, armedFrom: Date.parse(from), armedUntil: Date.parse(until), outcome: null };
      return { record: state[key], duplicate: false };
    });
    if (claimed.duplicate) return view(claimed.record, true);
    const { messageId } = claimed.record;
    const eventId = 'evt_' + digest(JSON.stringify([messageId, WEBHOOK_PEER]));
    let outcome;
    try {
      // The durable COMMIT can finish after the window closes. Keep that spend
      // even when transport is suppressed; re-arming must not permit a resend.
      if (!diagnosticWindowOpen(from, until, clock())) fail(peerCode('diagnostic_expired'));
      const send = createWebhookSender({ enabled: true, probeMessageId: messageId, endpoint, secret, auth, transport, clock });
      const response = await send({ id: 'job_' + eventId.slice(4), eventId, messageId, recipient: WEBHOOK_PEER,
        attempts: 1, body: JSON.stringify({ event: EVENT_NAME, data: { messageId } }) });
      outcome = { status: response.status, error: null };
    } catch (error) {
      // Sender errors are already sanitized codes; anything else is collapsed.
      outcome = { status: null, error: error instanceof BridgeError ? error.code : peerCode('transport_failed') };
    }
    const record = { ...claimed.record, outcome: { ...outcome, completedAt: clock() } };
    let recorded = false;
    try {
      recorded = await store.transaction(state => {
        const saved = state[key];
        if (saved?.messageId !== messageId || saved.outcome) return false;
        saved.outcome = record.outcome; return true;
      });
    } catch { /* The spent marker already blocks resends; report unrecorded. */ }
    return { ...view(record, false), recorded };
  };
}
