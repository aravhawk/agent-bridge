import { BridgeError, DELIVERY_TRANSPORT_OUTCOME } from './policy.mjs';
import { EVENT_NAME, digest, ownKeys } from './events.mjs';
import { callbackUrl, createPublicWebhookTransport } from './webhook.mjs';

const fail = (code, status = 503) => { throw new BridgeError(code, status); };
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

// Candidate mirrors the existing Friday outbox body and saved receiver prompt.
// Native docs have NOT established its acceptance/context mapping. No runtime
// imports this adapter until the authorized one-job probe verifies that fact.
function candidateBody(job) {
  try {
    if (job?.recipient !== 'friday' || !uuid.test(job.messageId || '') ||
        job.eventId !== 'evt_' + digest(JSON.stringify([job.messageId, 'friday'])) ||
        job.id !== 'job_' + job.eventId.slice(4) || typeof job.body !== 'string' ||
        Buffer.byteLength(job.body) > 1024) throw Error();
    const body = JSON.parse(job.body);
    ownKeys(body, ['event', 'data']); ownKeys(body.data, ['messageId']);
    if (body.event !== EVENT_NAME || body.data.messageId !== job.messageId) throw Error();
    return JSON.stringify({ event: EVENT_NAME, data: { messageId: job.messageId } });
  } catch { fail('invalid_friday_job', 400); }
}

// All options are trusted server configuration, never request/MCP parameters.
// contractVerified must follow native evidence, not existence of a saved key.
// While unverified, probeMessageId permits only one fixed first-attempt job;
// durable worker attempts prevent retries from sending again after a restart.
// This helper alone does not supply the worker's required accessAllowed binding.
export function createFridaySender({ enabled = false, contractVerified = false,
  probeMessageId, endpoint, secret, transport } = {}) {
  if (!enabled) fail('delivery_not_enabled');
  const probeOnly = contractVerified !== true;
  if (probeOnly && !uuid.test(probeMessageId || '')) fail('friday_native_contract_unverified');
  let destination;
  try {
    if (typeof endpoint !== 'string' || typeof secret !== 'string' ||
        !/^[\x21-\x7e]{1,4096}$/.test(secret)) throw Error();
    destination = callbackUrl(endpoint);
  } catch { fail('friday_sender_configuration_required'); }
  const post = transport || createPublicWebhookTransport({ enabled: true });
  const observed = (result, error = null) => Object.defineProperty(result, DELIVERY_TRANSPORT_OUTCOME,
    { value: Object.freeze({ terminal: probeOnly, error }) });
  let probeAttempted = false;
  return async job => {
    const body = candidateBody(job);
    if (probeOnly && (job.messageId !== probeMessageId || job.attempts !== 1 || probeAttempted)) {
      fail('friday_contract_probe_exhausted');
    }
    // Spend the probe before awaiting; timeouts/ambiguous HTTP results are not
    // grounds for another exploratory request. Never inspect the response body.
    if (probeOnly) probeAttempted = true;
    let response;
    try {
      response = await post(destination, { body,
        headers: { 'content-type': 'application/json', authorization: 'Bearer ' + secret } });
    } catch (error) {
      const transient = ['callback_timeout', 'callback_transport_failed', 'callback_dns_failed'].includes(error?.code);
      const code = transient ? error.code : 'friday_transport_failed';
      throw observed(new BridgeError(code, 503), code);
    }
    if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599) {
      throw observed(new BridgeError('friday_transport_invalid', 503), 'friday_transport_invalid');
    }
    return observed({ status: response.status }); // Transport evidence only, never wake proof.
  };
}
