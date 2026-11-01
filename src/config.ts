// Deployment identity, resolved once from the process environment at startup.
// Request values never reach this module. Secrets and readiness flags are read
// per runtime (src/runtime.mjs); only public identity and naming live here.
//
// Compatibility mode: when BRIDGE_PUBLIC_ORIGIN is unset, every default below
// reproduces the original two-assistant deployment exactly (origin, peer IDs,
// OAuth scope strings, protocol ID, tool/readiness/error names, queue topic,
// issuer and database host constraints). New deployments set
// BRIDGE_PUBLIC_ORIGIN and BRIDGE_PEERS and get the generic defaults instead.
// Any individual setting may still be overridden explicitly in either mode.

export const GENERIC_PROTOCOL = 'agent-inbox/1';
export const LEGACY_PROTOCOL = 'jarvis-friday/1';
export const PROTOCOLS = Object.freeze([GENERIC_PROTOCOL, LEGACY_PROTOCOL]);
export const DELIVERY_MODES = Object.freeze(['events', 'webhook']);
export const WEBHOOK_AUTH_MODES = Object.freeze(['standard-webhooks', 'bearer']);

const COMPAT = Object.freeze({
  origin: 'https://jarvis-friday-bridge.aravhawk.com',
  peers: 'jarvis:events,friday:webhook',
  serviceName: 'Jarvis Friday Bridge',
  serverName: 'jarvis-friday-bridge',
  protocol: LEGACY_PROTOCOL,
  receiverId: 'jarvis-friday-bridge-inbox',
  requireIssuerUnderOrigin: true,
  databaseHostSuffix: '.neon.tech',
});
const GENERIC = Object.freeze({
  serviceName: 'Agent Bridge',
  serverName: 'agent-inbox-bridge',
  protocol: GENERIC_PROTOCOL,
  receiverId: 'agent-inbox-bridge',
  requireIssuerUnderOrigin: false,
  databaseHostSuffix: '',
});
// Shared by both modes: these must match vercel.json, which cannot read env.
const DEFAULT_QUEUE_TOPIC = 'jarvis-friday-bridge-v1';
const DEFAULT_QUEUE_REGION = 'iad1';

// Externally visible names that mention the webhook peer. Compatibility mode
// keeps the original identifiers so existing clients, stored state and
// operator tooling observe no change; generic mode uses neutral equivalents.
const LEGACY_NAMES = Object.freeze({ prefix: 'friday', diagnosticTool: 'bridge_friday_webhook_diagnostic',
  senderConfigured: 'fridaySenderConfigured', contractVerified: 'fridayContractVerified',
  diagnosticArmed: 'fridayWebhookDiagnosticArmed', diagnosticState: 'fridayWebhookDiagnostic', canaryState: 'fridayCanary' });
const GENERIC_NAMES = Object.freeze({ prefix: 'webhook', diagnosticTool: 'bridge_webhook_diagnostic',
  senderConfigured: 'webhookSenderConfigured', contractVerified: 'webhookContractVerified',
  diagnosticArmed: 'webhookDiagnosticArmed', diagnosticState: 'webhookDiagnostic', canaryState: 'webhookCanary' });

// Per-peer webhook settings and the original variable each one falls back to.
const WEBHOOK_SETTINGS = Object.freeze({
  url: ['WEBHOOK_URL', 'FRIDAY_WEBHOOK_URL'],
  receiverId: ['RECEIVER_ID', 'FRIDAY_RECEIVER_ID'],
  contractVerified: ['WEBHOOK_CONTRACT_VERIFIED', 'FRIDAY_WEBHOOK_CONTRACT_VERIFIED'],
  diagnosticFrom: ['DIAGNOSTIC_FROM', 'FRIDAY_WEBHOOK_DIAGNOSTIC_FROM'],
  diagnosticUntil: ['DIAGNOSTIC_UNTIL', 'FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL'],
  canaryMessageId: ['CANARY_MESSAGE_ID', 'FRIDAY_CANARY_MESSAGE_ID'],
  canaryReturnSubscriptionId: ['CANARY_RETURN_SUBSCRIPTION_ID', 'FRIDAY_CANARY_RETURN_SUBSCRIPTION_ID'],
  canaryFrom: ['CANARY_FROM', 'FRIDAY_CANARY_FROM'],
  canaryUntil: ['CANARY_UNTIL', 'FRIDAY_CANARY_UNTIL'],
} as const);

export type DeliveryMode = 'events' | 'webhook';
export interface PeerSpec { readonly id: string; readonly delivery: DeliveryMode }
export type Env = Readonly<Record<string, string | undefined>>;
export class ConfigurationError extends Error {
  constructor(message: string) { super(message); this.name = 'ConfigurationError'; }
}
// Explicitly typed so a bare invalid(...) statement narrows control flow.
const invalid: (message: string) => never = message => { throw new ConfigurationError(message); };
const PEER_ID = /^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

function publicOrigin(value: string): string {
  let u!: URL;
  try { u = new URL(value); } catch { invalid('BRIDGE_PUBLIC_ORIGIN must be an https:// origin'); }
  if (u.protocol !== 'https:' || value !== u.origin || u.port) {
    invalid('BRIDGE_PUBLIC_ORIGIN must be an https:// origin without path, port or trailing slash');
  }
  return u.origin;
}
export function parsePeers(value: unknown): readonly [PeerSpec, PeerSpec] {
  const entries = typeof value === 'string' ? value.split(',').map(x => x.trim()) : [];
  const peers = entries.map((entry): PeerSpec => {
    const [id, delivery, extra] = entry.split(':') as [string, DeliveryMode, string | undefined];
    if (extra !== undefined || !PEER_ID.test(id || '') || !DELIVERY_MODES.includes(delivery)) {
      invalid('BRIDGE_PEERS entries must be <id>:<events|webhook> with lowercase IDs');
    }
    return Object.freeze({ id, delivery });
  });
  // The delivery model is a two-party inbox: one peer receives signed MCP
  // event callbacks it subscribed to, the other receives server-configured
  // webhooks. Each sends to the other; there is no fan-out or relay.
  // peers[0] and peers[1] exist whenever length is 2 (checked first).
  if (peers.length !== 2 || peers[0]!.id === peers[1]!.id ||
      peers.filter(p => p.delivery === 'events').length !== 1) {
    invalid('BRIDGE_PEERS must name exactly two distinct peers: one events peer and one webhook peer');
  }
  // Exactly one events and one webhook peer were checked above.
  return Object.freeze([peers.find(p => p.delivery === 'events'), peers.find(p => p.delivery === 'webhook')] as [PeerSpec, PeerSpec]);
}
const envKey = (id: string) => id.toUpperCase().replace(/-/g, '_');
function flag(env: Env, name: string, fallback: boolean): boolean {
  const value = env[name];
  if (value === undefined) return fallback;
  if (!['true', 'false'].includes(value)) invalid(`${name} must be true or false`);
  return value === 'true';
}
function choice(env: Env, name: string, fallback: string, test: (value: string) => boolean, message: string): string {
  const value = env[name];
  if (value === undefined) return fallback;
  if (!test(value)) invalid(`${name} ${message}`);
  return value;
}

export interface NameSet {
  readonly prefix: string; readonly diagnosticTool: string; readonly senderConfigured: string; readonly contractVerified: string;
  readonly diagnosticArmed: string; readonly diagnosticState: string; readonly canaryState: string;
}
// A type alias (not an interface) so Object.values() yields string[].
export type PeerScopes = { readonly probe: string; readonly ack: string };
export interface BridgeConfig {
  readonly compat: boolean; readonly origin: string; readonly peerIds: readonly string[];
  readonly eventsPeer: string; readonly webhookPeer: string; readonly scopes: Readonly<Record<string, PeerScopes>>;
  readonly webhookEnvPrefix: string; readonly serviceName: string; readonly serverName: string;
  readonly protocol: string; readonly acceptedProtocols: readonly string[]; readonly receiverId: string;
  readonly queueTopic: string; readonly queueRegion: string; readonly requireIssuerUnderOrigin: boolean;
  readonly databaseHostSuffix: string; readonly names: NameSet;
}
export function loadConfig(env: Env = process.env): BridgeConfig {
  const compat = env.BRIDGE_PUBLIC_ORIGIN === undefined;
  if (!compat && env.BRIDGE_PEERS === undefined) invalid('BRIDGE_PEERS is required when BRIDGE_PUBLIC_ORIGIN is set');
  const defaults = compat ? COMPAT : GENERIC;
  // Not compat mode means BRIDGE_PUBLIC_ORIGIN is set.
  const origin = compat ? COMPAT.origin : publicOrigin(env.BRIDGE_PUBLIC_ORIGIN as string);
  const [eventsPeer, webhookPeer] = parsePeers(env.BRIDGE_PEERS ?? COMPAT.peers).map(p => p.id) as [string, string]; // two peers, by parsePeers
  const peerIds = Object.freeze([eventsPeer, webhookPeer]);
  const counterpart = (id: string) => id === eventsPeer ? webhookPeer : id === webhookPeer ? eventsPeer : undefined;
  // Directional scopes: send names the recipient, ack names the holder.
  const scopes = Object.freeze(Object.fromEntries(peerIds.map(id => [id,
    Object.freeze({ probe: `bridge:send:${counterpart(id)}`, ack: `bridge:ack:${id}` })])));
  const protocol = choice(env, 'BRIDGE_MESSAGE_PROTOCOL', defaults.protocol, v => PROTOCOLS.includes(v as typeof PROTOCOLS[number]),
    `must be one of ${PROTOCOLS.join(', ')}`);
  const text = (name: string, fallback: string, pattern: RegExp, message: string) => choice(env, name, fallback, v => pattern.test(v), message);
  return Object.freeze({
    compat, origin, peerIds, eventsPeer, webhookPeer, scopes,
    webhookEnvPrefix: `BRIDGE_PEER_${envKey(webhookPeer)}_`,
    serviceName: text('BRIDGE_SERVICE_NAME', defaults.serviceName, /^[\x20-\x7e]{1,64}$/, 'must be 1-64 printable ASCII characters'),
    serverName: defaults.serverName,
    protocol, acceptedProtocols: Object.freeze([protocol, ...PROTOCOLS.filter(p => p !== protocol)]),
    receiverId: text('BRIDGE_RECEIVER_ID', defaults.receiverId, /^[a-z0-9][a-z0-9._-]{0,63}$/, 'must be a lowercase identifier'),
    queueTopic: text('BRIDGE_QUEUE_TOPIC', DEFAULT_QUEUE_TOPIC, /^[A-Za-z0-9_-]{1,128}$/, 'must be a queue topic name'),
    queueRegion: text('BRIDGE_QUEUE_REGION', DEFAULT_QUEUE_REGION, /^[a-z]{3}[0-9]$/, 'must be a Vercel region ID such as iad1'),
    requireIssuerUnderOrigin: flag(env, 'BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN', defaults.requireIssuerUnderOrigin),
    databaseHostSuffix: text('BRIDGE_DATABASE_HOST_SUFFIX', defaults.databaseHostSuffix,
      /^(?:\.[a-z0-9-]+(?:\.[a-z0-9-]+)*)?$/, 'must be empty or a hostname suffix starting with "."'),
    names: compat ? LEGACY_NAMES : GENERIC_NAMES,
  });
}

export const CONFIG = loadConfig();
export const { eventsPeer: EVENTS_PEER, webhookPeer: WEBHOOK_PEER, peerIds: PEER_IDS, names: NAMES } = CONFIG;
export const counterpart = (id: string | undefined): string | undefined =>
  id === EVENTS_PEER ? WEBHOOK_PEER : id === WEBHOOK_PEER ? EVENTS_PEER : undefined;
// Error codes that concern the webhook peer, e.g. friday_* or webhook_*.
export const peerCode = (suffix: string) => `${NAMES.prefix}_${suffix}`;

// Webhook peer settings from the runtime environment. BRIDGE_PEER_<ID>_* wins;
// the original FRIDAY_* variables remain accepted. Bearer authentication is
// the legacy default only when the secret comes from FRIDAY_WEBHOOK_KEY.
export type WebhookPeerSettings = Readonly<Record<keyof typeof WEBHOOK_SETTINGS | 'secret' | 'auth', string | undefined>>;
export function webhookPeerSettings(env: Env, prefix = CONFIG.webhookEnvPrefix): WebhookPeerSettings {
  const settings: Record<string, string | undefined> = Object.fromEntries(Object.entries(WEBHOOK_SETTINGS).map(([field, [suffix, legacy]]) =>
    [field, env[prefix + suffix] !== undefined ? env[prefix + suffix] : env[legacy]]));
  const signed = env[prefix + 'WEBHOOK_SECRET'] !== undefined;
  settings.secret = signed ? env[prefix + 'WEBHOOK_SECRET'] : env.FRIDAY_WEBHOOK_KEY;
  settings.auth = env[prefix + 'WEBHOOK_AUTH'] ?? (signed ? 'standard-webhooks' : 'bearer');
  // Exactly the WEBHOOK_SETTINGS fields plus secret and auth.
  return Object.freeze(settings) as WebhookPeerSettings;
}
