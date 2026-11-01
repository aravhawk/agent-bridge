import test from 'node:test';
import assert from 'node:assert/strict';
import { createWebhookSender } from '../src/webhook-sender.ts';
import { BridgeError } from '../src/policy.ts';
import { digest } from '../src/events.ts';
import type { WebhookSenderOptions } from '../src/webhook-sender.ts';
import type { TransportRequest } from '../src/webhook.ts';

// Nonsecret offline fixtures. No native endpoint, credential or request is used.
const messageId = '00000000-0000-4000-8000-000000000001';
const eventId = 'evt_' + digest(JSON.stringify([messageId, 'friday']));
const body = { event: 'bridge.message.received', data: { messageId } };
const job = { id: 'job_' + eventId.slice(4), eventId, messageId, recipient: 'friday', attempts: 1,
  body: JSON.stringify(body) };
const config = { enabled: true, endpoint: 'https://receiver.example.test/hook?opaque=fixture',
  secret: 'FIXTURE_NOT_A_REAL_KEY', contractVerified: true };
const code = (name: string) => (e: unknown) => e instanceof BridgeError && e.code === name;

test('Friday sender stays closed without activation and independently verified contract or exact probe ID', () => {
  assert.throws(() => createWebhookSender(), code('delivery_not_enabled'));
  assert.throws(() => createWebhookSender({ ...config, contractVerified: false }), code('friday_native_contract_unverified'));
  // A string is not the boolean opt-in.
  assert.throws(() => createWebhookSender({ ...config, contractVerified: 'true' } as unknown as WebhookSenderOptions), code('friday_native_contract_unverified'));
  for (const probeMessageId of ['', 'caller-selected', messageId.toUpperCase() + 'x']) {
    assert.throws(() => createWebhookSender({ ...config, contractVerified: false, probeMessageId }),
      code('friday_native_contract_unverified'));
  }
});

test('fixed destination and observed Bearer format carry only a canonical candidate event/message ID', async () => {
  const calls: ({ url: string } & TransportRequest)[] = [];
  const send = createWebhookSender({ ...config, transport: async (url, request) => {
    calls.push({ url, ...request });
    return { status: 202, get body(): never { return assert.fail('must not inspect response body'); } };
  } });
  const result = await send({ ...job, body: JSON.stringify({ data: { messageId }, event: body.event }, null, 2) });
  assert.deepEqual(result, { status: 202 });
  assert.equal(calls[0]!.url, config.endpoint);
  assert.equal(calls[0]!.headers.authorization, 'Bearer ' + config.secret);
  assert.equal(calls[0]!.headers['content-type'], 'application/json');
  assert.equal(calls[0]!.body, JSON.stringify(body));
  assert.deepEqual(Object.keys(calls[0]!.headers).sort(), ['authorization', 'content-type']);
  assert.equal('wakeVerified' in result, false);
});

test('forged recipient/body/identity and extra payload fields fail before transport', async () => {
  let calls = 0;
  const send = createWebhookSender({ ...config, transport: async () => { calls++; return { status: 200 }; } });
  const invalid = [{ ...job, recipient: 'jarvis' }, { ...job, eventId: 'evt_' + 'a'.repeat(64) },
    { ...job, id: 'job_' + 'a'.repeat(64) }, { ...job, body: '{' },
    { ...job, body: JSON.stringify({ ...body, instruction: 'untrusted extra data' }) },
    { ...job, body: JSON.stringify({ ...body, data: { messageId, url: 'https://unrelated.example' } }) },
    { ...job, body: JSON.stringify({ event: 'other.event', data: { messageId } }) },
    { ...job, body: JSON.stringify({ ...body, data: { messageId: '00000000-0000-4000-8000-000000000002' } }) },
    { ...job, body: ' '.repeat(1025) }];
  for (const item of invalid) await assert.rejects(send(item), code('invalid_friday_job'));
  assert.equal(calls, 0);
});

test('one-shot contract probe is fixed to one known message and cannot retry or reset through a restarted worker attempt', async () => {
  let calls = 0;
  const options = { ...config, contractVerified: false, probeMessageId: messageId,
    transport: async () => { calls++; return { status: 503 }; } };
  const send = createWebhookSender(options);
  assert.deepEqual(await send(job), { status: 503 });
  await assert.rejects(send(job), code('friday_contract_probe_exhausted'));
  await assert.rejects(createWebhookSender(options)({ ...job, attempts: 2 }), code('friday_contract_probe_exhausted'));
  const otherId = '00000000-0000-4000-8000-000000000002';
  const otherEvent = 'evt_' + digest(JSON.stringify([otherId, 'friday']));
  await assert.rejects(createWebhookSender(options)({ ...job, messageId: otherId, eventId: otherEvent,
    id: 'job_' + otherEvent.slice(4), body: JSON.stringify({ ...body, data: { messageId: otherId } }) }),
    code('friday_contract_probe_exhausted'));
  assert.equal(calls, 1);
});

test('probe transport failure consumes its single attempt and raw secret-bearing exceptions stay sanitized', async () => {
  const send = createWebhookSender({ ...config, contractVerified: false, probeMessageId: messageId,
    transport: async () => { throw new Error(config.secret); } });
  await assert.rejects(send(job), e => code('friday_transport_failed')(e) && !String(e).includes(config.secret));
  await assert.rejects(send(job), code('friday_contract_probe_exhausted'));
  const timeout = createWebhookSender({ ...config, transport: async () => { throw new BridgeError('callback_timeout', 503); } });
  await assert.rejects(timeout(job), code('callback_timeout'));
});

test('invalid destination or header material cannot construct a sender and invalid transport status is sanitized', async () => {
  for (const endpoint of ['http://receiver.example.test/hook', 'https://user:pass@receiver.example.test/hook',
    'https://127.0.0.1/hook', 'https://receiver.example.test:444/hook', 'https://receiver.example.test/hook#fragment']) {
    assert.throws(() => createWebhookSender({ ...config, endpoint }), code('friday_sender_configuration_required'));
  }
  for (const secret of ['', 'key\r\nInjected: header', 'key with spaces', 'x'.repeat(4097)]) {
    assert.throws(() => createWebhookSender({ ...config, secret }), code('friday_sender_configuration_required'));
  }
  const send = createWebhookSender({ ...config, transport: async () => ({ status: '202' }) });
  await assert.rejects(send(job), code('friday_transport_invalid'));
});
