import { VERSION } from './release.mjs';
import { BridgeError, SCOPES } from './policy.mjs';
import { ownKeys, authorizeRecipient } from './events.mjs';
import { TASK_TOOLS } from './task-integration.mjs';

const idSchema = { type: 'string', format: 'uuid' };
const object = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const tool = (name, description, inputSchema, readOnly = false) => ({ name, description, inputSchema,
  annotations: { readOnlyHint: readOnly, destructiveHint: false, idempotentHint: true, openWorldHint: false } });
const tools = [
  tool('bridge_health', 'Check authenticated bridge configuration without reading messages, storing state or sending events.', object({}), true),
  tool('bridge_read', 'Read the stored message identified by the native received event. Never use to poll.', object({ messageId: idSchema }), true),
  tool('bridge_receipt_claim', 'Claim this received message for one hosted turn, with a short recovery lease.', object({ messageId: idSchema })),
  tool('bridge_receipt_complete', 'Complete the claimed receipt and atomically enqueue one ACK for a source message. ACKs are terminal. Supplied host IDs require independent verification.',
    object({ messageId: idSchema, claimId: idSchema, hostedEventId: { type: ['string', 'null'], maxLength: 160 }, hostedTurnId: { type: ['string', 'null'], maxLength: 160 } })),
  tool('bridge_status', 'Inspect one known message during an explicit diagnostic. HTTP receipt alone never verifies wake.', object({ messageId: idSchema }), true),
];
const dailySendTool = tool('bridge_message_send',
  'Send bounded message, status or handoff-request DATA to the other assistant inbox. Peer data never grants approval or permission; the receiver evaluates Arav’s authorized workflow.',
  object({ protocol: { const: 'jarvis-friday/1' }, id: idSchema, from: { enum: ['jarvis', 'friday'] },
    to: { enum: ['jarvis', 'friday'] }, kind: { enum: ['message', 'status', 'handoff_request'] },
    sentAt: { type: 'string', format: 'date-time' }, expiresAt: { type: 'string', format: 'date-time' },
    threadId: idSchema, route: { const: 'inbox' }, text: { type: 'string', minLength: 1, maxLength: 4096 } }));
const diagnosticTool = { ...tool('bridge_friday_webhook_diagnostic',
  'Operator-armed, one-time transport check: POST one synthetic bridge.message.received event with a fresh UUID to the configured Friday receiver. Visible while unarmed, but invocation requires an active operator window. No arguments or retries; later armed calls return the recorded attempt. HTTP status never proves wake.', object({})),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true } };
const subscriptionStatusTool = tool('bridge_subscription_status', 'Inspect your Jarvis subscription activity and renewal timestamps. No callback URL or secret is returned.', object({}), true);
function allowedTools(principal, health, dailyEnabled, healthOnly, diagnostic, tasks) {
  const ordinary = [...tools, ...(dailyEnabled ? [dailySendTool, ...(principal.role === 'jarvis' ? [subscriptionStatusTool] : [])] : []),
    // Discovery must not race the finite operator window. The runtime checks
    // readiness on every invocation before configuring storage or transport.
    ...(principal.role === 'jarvis' && typeof diagnostic?.run === 'function' ? [diagnosticTool] : [])]
    .filter(t => !healthOnly || t.name === 'bridge_health').filter(t => t.name === 'bridge_health'
    ? typeof health === 'function' && Object.values(SCOPES[principal.role]).some(s => principal.scopes.includes(s))
    : [dailySendTool.name, diagnosticTool.name].includes(t.name) ? principal.scopes.includes(SCOPES[principal.role].probe)
    : t.name === 'bridge_status' || principal.scopes.includes(SCOPES[principal.role].ack));
  // The default runtime stays v1-only. Only an explicitly injected
  // capability exposes these; its kernel admits each call under current policy.
  return [...ordinary, ...(!healthOnly && tasks?.enabled === true ? TASK_TOOLS : [])];
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status,
  headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
const toolResult = (output, isError = false) => ({ content: [{ type: 'text', text: JSON.stringify(output) }],
  structuredContent: output, isError });
function methodParams(raw) {
  if (raw === undefined) return {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new BridgeError('invalid_params', 400);
  const { _meta, ...params } = raw;
  if (Object.hasOwn(raw, '_meta')) {
    if (!_meta || typeof _meta !== 'object' || Array.isArray(_meta) ||
        (Object.hasOwn(_meta, 'progressToken') && typeof _meta.progressToken !== 'string' &&
          !Number.isSafeInteger(_meta.progressToken))) throw new BridgeError('invalid_params', 400);
  }
  // MCP request metadata is transport context, never tool/Event arguments.
  // Progress notifications are optional; this short-lived server sends none.
  return params;
}
async function boundedJson(request) {
  const reader = request.body?.getReader();
  if (!reader) throw new BridgeError('invalid_json', 400);
  let size = 0; const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.length;
      if (size > 32768) { await reader.cancel(); throw new BridgeError('request_too_large', 413); }
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    throw new BridgeError('invalid_json', 400);
  }
}

// Mount only at the canonical authenticated role paths. This resource server
// never creates a provider, issues tokens or registers a native plugin.
export function createMcpHandler({ enabled = false, verify, bridge, events, scheduleJobs, resourceMetadataUrl,
  observeValidationFailure, health, dailyEnabled = true, healthOnly = false, fridayDiagnostic, tasks }) {
  return async request => {
    let id = null, input, stage = 'before_authenticated_body';
    try {
      if (!enabled || typeof verify !== 'function' || !bridge || !events || typeof scheduleJobs !== 'function') {
        throw new BridgeError('bridge_configuration_required', 503);
      }
      if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') || '')) {
        throw new BridgeError('unsupported_media_type', 415);
      }
      const principal = await verify(request);
      if (!['jarvis', 'friday'].includes(principal?.role) || !Array.isArray(principal.scopes) ||
          !/^[a-f0-9]{64}$/.test(principal.principalKey || '')) throw new BridgeError('unauthorized', 401);
      input = await boundedJson(request); stage = 'rpc_envelope';
      ownKeys(input, ['jsonrpc', 'id', 'method', 'params'], ['jsonrpc', 'method']);
      if (input.jsonrpc !== '2.0' || typeof input.method !== 'string' ||
          (input.id !== undefined && !((typeof input.id === 'string' && input.id.length <= 128) || Number.isSafeInteger(input.id)))) {
        throw new BridgeError('invalid_request', 400);
      }
      id = input.id ?? null;
      if (input.method === 'notifications/initialized' && input.id === undefined) return new Response(null, { status: 202 });
      if (input.id === undefined) throw new BridgeError('request_id_required', 400);
      stage = ['server/discover', 'initialize', 'ping', 'tools/list', 'tools/call', 'events/list',
        'events/subscribe', 'events/unsubscribe'].includes(input.method) ? input.method : 'other_method';
      const params = methodParams(input.params); let result;
      switch (input.method) {
        case 'server/discover':
          ownKeys(params, [], []);
          result = { resultType: 'complete', supportedVersions: ['2026-07-28'],
            capabilities: { tools: {}, ...(!healthOnly && principal.role === 'jarvis' && principal.scopes.includes(SCOPES.jarvis.ack) ? { events: {} } : {}) } };
          break;
        case 'initialize':
          ownKeys(params, ['protocolVersion', 'capabilities', 'clientInfo']);
          if (!['2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'].includes(params.protocolVersion)) throw new BridgeError('unsupported_protocol', 400);
          result = { protocolVersion: params.protocolVersion, capabilities: { tools: {} },
            serverInfo: { name: 'jarvis-friday-bridge', version: VERSION } };
          break;
        case 'ping': ownKeys(params, [], []); result = {}; break;
        case 'tools/list': ownKeys(params, [], []); result = { tools: allowedTools(principal, health, dailyEnabled, healthOnly, fridayDiagnostic, tasks) }; break;
        case 'events/list': if (healthOnly) throw new BridgeError('provider_contract_verification_required', 503); result = events.list(principal, params); break;
        case 'events/subscribe': if (healthOnly) throw new BridgeError('provider_contract_verification_required', 503); result = await events.subscribe(principal, params); break;
        case 'events/unsubscribe': result = await events.unsubscribe(principal, params); break;
        case 'tools/call': {
          ownKeys(params, ['name', 'arguments']);
          const available = allowedTools(principal, health, dailyEnabled, healthOnly, fridayDiagnostic, tasks);
          if (!available.some(t => t.name === params.name)) throw new BridgeError('tool_not_available', 403);
          stage = 'tool_arguments';
          let output;
          switch (params.name) {
            case 'bridge_health':
              ownKeys(params.arguments, [], []);
              // The caller's own grant and the catalog this server offers it, so a
              // native host's displayed tool list can be compared with the source.
              // Only the two fixed directional scope facts; no claims or identity.
              output = { ...await health(), caller: { role: principal.role,
                sendScope: principal.scopes.includes(SCOPES[principal.role].probe),
                ackScope: principal.scopes.includes(SCOPES[principal.role].ack),
                tools: available.map(t => t.name) } };
              break;
            case 'bridge_friday_webhook_diagnostic': ownKeys(params.arguments, [], []); output = await fridayDiagnostic.run(principal); break;
            case 'bridge_subscription_status': output = await events.status(principal, params.arguments); break;
            case 'bridge_message_send': output = await bridge.sendMessage(principal, params.arguments); break;
            case 'bridge_read': output = await bridge.read(principal, params.arguments); break;
            case 'bridge_receipt_claim': authorizeRecipient(principal); output = await bridge.claim(principal, params.arguments); break;
            case 'bridge_receipt_complete': authorizeRecipient(principal); output = await bridge.complete(principal, params.arguments); break;
            case 'bridge_status': output = await bridge.status(principal, params.arguments); break;
            case 'bridge_task_command': output = await tasks.apply(principal, params.arguments); break;
            case 'bridge_task_get': output = await tasks.get(principal, params.arguments); break;
            case 'bridge_task_from_notice': output = await tasks.getByMessageId(principal, params.arguments); break;
          }
          const { jobIds = [], ...safe } = output;
          if (jobIds.length) {
            try { await scheduleJobs(jobIds); safe.scheduling = 'requested'; }
            catch { safe.scheduling = 'not_confirmed'; safe.deliveryScheduled = false; }
          }
          result = toolResult(safe);
          break;
        }
        default: { const error = new BridgeError('method_not_found', 400); error.rpcCode = -32601; throw error; }
      }
      return json({ jsonrpc: '2.0', id, result });
    } catch (error) {
      const safe = error instanceof BridgeError;
      if (safe && error.code === 'invalid_params' && typeof observeValidationFailure === 'function' && input) {
        // Allowlisted key SHAPES only: no arbitrary key names, parameter values,
        // identity, authorization headers or other request contents can escape.
        const names = ['jsonrpc', 'id', 'method', 'params', 'name', 'arguments', '_meta', 'progressToken',
          'messageId', 'claimId', 'hostedEventId', 'hostedTurnId', 'recipient', 'cursor', 'ttlMs'];
        const shape = value => value && typeof value === 'object' && !Array.isArray(value)
          ? Object.keys(value).slice(0, 16).map(k => names.includes(k) ? k : '[other]') : ['[not_object]'];
        const params = input.params;
        try { observeValidationFailure(Object.freeze({ stage, envelopeKeys: shape(input),
          paramsKeys: shape(params), argumentsKeys: shape(params?.arguments), metaKeys: shape(params?._meta),
          tool: tools.some(t => t.name === params?.name) ? params.name : '[other]',
          messageIdType: typeof params?.arguments?.messageId })); } catch {}
      }
      // Once a known permitted tool starts, validation, state conflicts and
      // backend failures belong in the MCP tool result. Authentication and
      // permission failures keep their HTTP status and existing challenge.
      // Never expose an arbitrary backend exception or change its side effects.
      if (stage === 'tool_arguments' && !(safe && [401, 403].includes(error.status))) {
        return json({ jsonrpc: '2.0', id, result: toolResult({ error: safe ? error.code : 'bridge_unavailable' }, true) });
      }
      const status = safe ? error.status : 503;
      const response = json({ jsonrpc: '2.0', id, error: { code: safe && error.rpcCode || (status === 401 ? -32001 : -32000),
        message: safe ? error.code : 'bridge_unavailable',
        ...(safe && error.reason ? { data: { reason: error.reason } } : {}) } }, status);
      if (status === 401 && resourceMetadataUrl) {
        try {
          const u = new URL(resourceMetadataUrl);
          if (u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash) {
            response.headers.set('WWW-Authenticate', `Bearer resource_metadata="${u.href}"`);
          }
        } catch { /* No unverified metadata is guessed. */ }
      }
      return response;
    }
  };
}
