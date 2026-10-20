import { randomUUID } from 'node:crypto';
import { BridgeError, SCOPES } from './policy.mjs';
import { EVENT_NAME, digest } from './events.mjs';
import { createFridaySender, fridaySenderConfigured } from './friday-sender.mjs';
import { RECEIVER_ID } from './release.mjs';

const fail = (code, status = 503) => { throw new BridgeError(code, status); };
export const DIAGNOSTIC_MAX_WINDOW_MS = 2 * 3600000;

// Operator arming is a finite env deadline no more than two hours ahead.
// A missing, malformed, past or longer window keeps the diagnostic closed.
export function diagnosticWindowOpen(until, now) {
  const end = typeof until === 'string' ? Date.parse(until) : NaN;
  return Number.isSafeInteger(end) && end > now && end - now <= DIAGNOSTIC_MAX_WINDOW_MS;
}
const view = (record, duplicate) => ({ messageId: record.messageId, receiverId: record.receiverId,
  attemptedAt: new Date(record.attemptedAt).toISOString(), duplicate,
  transport: record.outcome ? { status: record.outcome.status, error: record.outcome.error }
    : { status: null, error: 'outcome_not_recorded' },
  wakeVerified: false, evidenceRequired: 'native_friday_run_with_exact_messageId' });

// One synthetic Friday webhook for the whole deployment lifetime, transport
// evidence only. No stored message exists, so a native read of this UUID
// reports message_not_found. The spend marker commits under the state row lock
// BEFORE the request starts: concurrent calls, restarts, timeouts and lost
// outcomes can only return the recorded attempt, never send another. Caller
// input chooses nothing; destination, key and body are server configuration.
export function createFridayDiagnostic({ store, endpoint, secret, transport, until, clock = Date.now }) {
  return async principal => {
    if (principal?.role !== 'jarvis' || !principal.scopes?.includes(SCOPES.jarvis.probe)) fail('insufficient_scope', 403);
    // Repairable configuration must fail before the single attempt is spent.
    if (!fridaySenderConfigured({ endpoint, secret })) fail('friday_sender_configuration_required');
    const claimed = await store.transaction(state => {
      const now = clock();
      if (state.fridayWebhookDiagnostic) return { record: state.fridayWebhookDiagnostic, duplicate: true };
      if (!diagnosticWindowOpen(until, now)) fail('friday_diagnostic_not_armed');
      state.fridayWebhookDiagnostic = { messageId: randomUUID(), receiverId: RECEIVER_ID,
        attemptedAt: now, armedUntil: Date.parse(until), outcome: null };
      return { record: state.fridayWebhookDiagnostic, duplicate: false };
    });
    if (claimed.duplicate) return view(claimed.record, true);
    const { messageId } = claimed.record;
    const eventId = 'evt_' + digest(JSON.stringify([messageId, 'friday']));
    let outcome;
    try {
      const send = createFridaySender({ enabled: true, probeMessageId: messageId, endpoint, secret, transport });
      const response = await send({ id: 'job_' + eventId.slice(4), eventId, messageId, recipient: 'friday',
        attempts: 1, body: JSON.stringify({ event: EVENT_NAME, data: { messageId } }) });
      outcome = { status: response.status, error: null };
    } catch (error) {
      // Sender errors are already sanitized codes; anything else is collapsed.
      outcome = { status: null, error: error instanceof BridgeError ? error.code : 'friday_transport_failed' };
    }
    const record = { ...claimed.record, outcome: { ...outcome, completedAt: clock() } };
    let recorded = false;
    try {
      recorded = await store.transaction(state => {
        const saved = state.fridayWebhookDiagnostic;
        if (saved?.messageId !== messageId || saved.outcome) return false;
        saved.outcome = record.outcome; return true;
      });
    } catch { /* The spent marker already blocks resends; report unrecorded. */ }
    return { ...view(record, false), recorded };
  };
}
