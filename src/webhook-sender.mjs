import { BridgeError, DELIVERY_TRANSPORT_OUTCOME } from './policy.mjs';
import { EVENT_NAME, digest, ownKeys } from './events.mjs';
import { callbackUrl, createPublicWebhookTransport, signedHeaders, validSecret } from './webhook.mjs';
import { WEBHOOK_AUTH_MODES, WEBHOOK_PEER, peerCode } from './config.mjs';

const fail = (code, status = 503) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
// standard-webhooks: whsec_ key, webhook-id/timestamp/signature headers.
// bearer: legacy shared key sent as `Authorization: Bearer <key>`.
function destinationFor({ endpoint, secret, auth = 'bearer' }) {
  try {
    if (typeof endpoint !== 'string' || typeof secret !== 'string' || !WEBHOOK_AUTH_MODES.includes(auth) ||
        (auth === 'bearer' ? !/^[\x21-\x7e]{1,4096}$/.test(secret) : !validSecret(secret))) throw Error();
    return callbackUrl(endpoint);
  } catch { fail(peerCode('sender_configuration_required')); }
}
export function webhookSenderConfigured(options) {
  try { destinationFor(options); return true; } catch { return false; }
}

// The body names only the event and stored message ID. The receiver reads the
// message through its own authenticated MCP session; the webhook carries no
// content, credential or instruction.
function candidateBody(job) {
  try {
    if (job?.recipient !== WEBHOOK_PEER || !uuid.test(job.messageId || '') ||
        job.eventId !== 'evt_' + digest(JSON.stringify([job.messageId, WEBHOOK_PEER])) ||
        job.id !== 'job_' + job.eventId.slice(4) || typeof job.body !== 'string' ||
        Buffer.byteLength(job.body) > 1024) throw Error();
    const body = JSON.parse(job.body);
    ownKeys(body, ['event', 'data']); ownKeys(body.data, ['messageId']);
    if (body.event !== EVENT_NAME || body.data.messageId !== job.messageId) throw Error();
    return JSON.stringify({ event: EVENT_NAME, data: { messageId: job.messageId } });
  } catch { fail(`invalid_${peerCode('job')}`, 400); }
}

// All options are trusted server configuration, never request/MCP parameters.
// contractVerified must follow native evidence, not existence of a saved key.
// While unverified, probeMessageId permits only one fixed first-attempt job;
// durable worker attempts prevent retries from sending again after a restart.
// This helper alone does not supply the worker's required accessAllowed binding.
// `auth` defaults to the legacy bearer mode; the runtime always passes the
// configured mode explicitly.
export function createWebhookSender({ enabled = false, contractVerified = false,
  probeMessageId, endpoint, secret, auth = 'bearer', transport, clock = Date.now } = {}) {
  if (!enabled) fail('delivery_not_enabled');
  const probeOnly = contractVerified !== true;
  if (probeOnly && !uuid.test(probeMessageId || '')) fail(peerCode('native_contract_unverified'));
  const destination = destinationFor({ endpoint, secret, auth });
  const post = transport || createPublicWebhookTransport({ enabled: true });
  const observed = (result, error = null) => Object.defineProperty(result, DELIVERY_TRANSPORT_OUTCOME,
    { value: Object.freeze({ terminal: probeOnly, error }) });
  let probeAttempted = false;
  return async job => {
    const body = candidateBody(job);
    if (probeOnly && (job.messageId !== probeMessageId || job.attempts !== 1 || probeAttempted)) {
      fail(peerCode('contract_probe_exhausted'));
    }
    // Spend the probe before awaiting; timeouts/ambiguous HTTP results are not
    // grounds for another exploratory request. Never inspect the response body.
    if (probeOnly) probeAttempted = true;
    // The event ID is stable across retries, as Standard Webhooks requires.
    const headers = auth === 'bearer'
      ? { 'content-type': 'application/json', authorization: 'Bearer ' + secret }
      : signedHeaders({ id: job.eventId, body, secrets: [secret], now: clock() });
    let response;
    try {
      response = await post(destination, { body, headers });
    } catch (error) {
      const transient = ['callback_timeout', 'callback_transport_failed', 'callback_dns_failed'].includes(error?.code);
      const code = transient ? error.code : peerCode('transport_failed');
      throw observed(new BridgeError(code, 503), code);
    }
    if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599) {
      throw observed(new BridgeError(peerCode('transport_invalid'), 503), peerCode('transport_invalid'));
    }
    return observed({ status: response.status }); // Transport evidence only, never wake proof.
  };
}
