import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import ipaddr from 'ipaddr.js';
import { Webhook } from 'standardwebhooks';
import { BridgeError } from './policy.mjs';

const fail = (code, status = 400) => { throw new BridgeError(code, status); };
export function callbackUrl(value) {
  let u;
  try { u = new URL(value); } catch { fail('invalid_callback'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.hash ||
      (u.port && u.port !== '443') || !u.hostname || u.href.length > 4096 ||
      isIP(u.hostname.replace(/^\[|\]$/g, '')) || u.hostname.endsWith('.')) fail('invalid_callback');
  return u.href;
}
export function validSecret(secret) {
  if (typeof secret !== 'string' || !/^whsec_(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(secret)) {
    fail('invalid_signing_secret');
  }
  const bytes = Buffer.from(secret.slice(6), 'base64');
  if (bytes.length < 24 || bytes.length > 64 || bytes.toString('base64') !== secret.slice(6)) fail('invalid_signing_secret');
  return secret;
}
export function publicAddress(address) {
  try {
    // IPv4-mapped IPv6 is normalized before classification. Reject transition,
    // documentation, multicast, reserved and all private/local ranges as well.
    const parsed = ipaddr.process(address);
    return parsed.range() === 'unicast';
  } catch { return false; }
}
export function signedHeaders({ id, body, secrets, subscriptionId, now = Date.now() }) {
  if (typeof body !== 'string' || Buffer.byteLength(body) > 256 * 1024) fail('payload_too_large', 413);
  if (!Array.isArray(secrets) || !secrets.length || secrets.length > 2) fail('invalid_signing_secret');
  const when = new Date(now);
  return { 'content-type': 'application/json', 'webhook-id': id,
    'webhook-timestamp': String(Math.floor(now / 1000)),
    'webhook-signature': [...new Set(secrets)].map(s => new Webhook(validSecret(s)).sign(id, when, body)).join(' '),
    ...(subscriptionId ? { 'X-MCP-Subscription-Id': subscriptionId } : {}) };
}

// Connection-time DNS validation; the socket connects only to a checked IP,
// while Host/SNI and TLS certificate verification retain the original hostname.
// No generic fetch redirect behavior or proxy environment is involved.
export function createPublicWebhookTransport({ enabled = false, resolve = lookup, request = httpsRequest,
  timeoutMs = 10000, responseLimit = 4096 } = {}) {
  if (!enabled) fail('delivery_not_enabled', 503);
  return async (url, { body, headers }) => {
    const u = new URL(callbackUrl(url));
    if (typeof body !== 'string' || Buffer.byteLength(body) > 256 * 1024) fail('payload_too_large', 413);
    let addresses; let dnsTimer;
    try {
      addresses = await Promise.race([resolve(u.hostname, { all: true, verbatim: true }),
        new Promise((_, reject) => { dnsTimer = setTimeout(() => reject(new BridgeError('callback_timeout', 503)), timeoutMs); })]);
    } catch (error) {
      if (error instanceof BridgeError) throw error;
      fail('callback_dns_failed', 503);
    } finally { clearTimeout(dnsTimer); }
    if (!addresses?.length || !addresses.every(x => publicAddress(x.address))) fail('callback_address_blocked', 400);
    const pinned = addresses[0];
    return new Promise((resolveResult, rejectResult) => {
      let settled = false;
      let req;
      const timer = setTimeout(() => {
        req?.destroy(); finish(new BridgeError('callback_timeout', 503));
      }, timeoutMs);
      const finish = (error, result) => {
        if (settled) return;
        settled = true; clearTimeout(timer);
        if (error) rejectResult(error); else resolveResult(result);
      };
      try {
        req = request(u, { method: 'POST', agent: false, servername: u.hostname,
          rejectUnauthorized: true, headers: { ...headers, 'content-length': Buffer.byteLength(body) },
          lookup: (_hostname, options, callback) => {
            // Support Node's all-address lookup form without a second DNS call.
            if (options?.all) callback(null, [pinned]); else callback(null, pinned.address, pinned.family);
          } }, res => {
          const chunks = []; let size = 0;
          res.on('data', chunk => {
            size += chunk.length;
            if (size > responseLimit) { res.destroy(); finish(new BridgeError('callback_response_too_large', 503)); }
            else chunks.push(chunk);
          });
          res.on('error', () => finish(new BridgeError('callback_transport_failed', 503)));
          res.on('end', () => finish(null, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('error', () => finish(new BridgeError('callback_transport_failed', 503)));
        req.end(body);
      } catch { finish(new BridgeError('callback_transport_failed', 503)); }
    });
  };
}

// No key is generated for deployment here. A provided 32-byte key must arrive
// through approved project Secret storage. Fixture tests use ephemeral keys.
export function createProtector(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) fail('storage_key_required', 503);
  const storageKey = Buffer.from(key);
  return {
    seal(value, context) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', storageKey, iv);
      cipher.setAAD(Buffer.from(context));
      const data = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
    },
    open(value, context) {
      try {
        const data = Buffer.from(value, 'base64');
        const cipher = createDecipheriv('aes-256-gcm', storageKey, data.subarray(0, 12));
        cipher.setAAD(Buffer.from(context)); cipher.setAuthTag(data.subarray(12, 28));
        return JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString('utf8'));
      } catch { fail('storage_decryption_failed', 503); }
    },
  };
}
