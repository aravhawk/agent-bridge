import { BridgeError, SCOPES } from './policy.mjs';

// Only creates local file contents after ACTUAL authenticated discovery is
// supplied. It never contacts a service, zips/uploads or installs a plugin.
// No placeholder mcp.json or secret belongs in an account-save operation.
export function preparePrivatePlugin({ endpoint, clientId, discovery, events, liveDiscoveryVerified = false } = {}) {
  if (!liveDiscoveryVerified || !discovery?.supportedVersions?.includes('2026-07-28') ||
      !discovery.capabilities?.events || !events?.some(e => e.name === 'bridge.message.received') ||
      typeof clientId !== 'string' || !clientId.trim() || clientId.length > 512) {
    throw new BridgeError('live_plugin_discovery_and_client_required', 503);
  }
  let u;
  try { u = new URL(endpoint); } catch { throw new BridgeError('verified_mcp_endpoint_required', 503); }
  if (u.origin !== 'https://rn-jarvis-friday-discovery-20261018.vercel.app' ||
      u.pathname !== '/bridge/jarvis/mcp' || u.username || u.password || u.hash || u.search) {
    throw new BridgeError('verified_mcp_endpoint_required', 503);
  }
  const manifest = { $schema: 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',
    name: 'rn-jarvis-friday-synthetic-bridge-20261018', version: '0.1.0',
    description: 'Private synthetic Jarvis–Friday connectivity test, hosted on the isolated Vercel bridge.',
    author: { name: 'Arav Jain' }, extensions: { 'com.openai': { interface: {
      displayName: 'RN Jarvis Friday Bridge', shortDescription: 'Synthetic bridge test',
      longDescription: 'Receive native Events for stored synthetic test messages, read by ID, and record a durable receipt and ACK.',
      developerName: 'Arav Jain', category: 'Productivity', capabilities: [],
      defaultPrompt: 'Receive synthetic bridge events in this hosted chat and acknowledge each message once.' } } } };
  const mcp = { $schema: 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json', mcpServers: {
    'rn-synthetic-bridge': { type: 'streamable-http', url: u.href, extensions: { 'com.openai': {
      auth: { type: 'oauth', client: { mode: 'provided', clientId, tokenEndpointAuthMethod: 'none' } },
      baseScopes: [SCOPES.jarvis.probe, SCOPES.jarvis.ack, 'offline_access'] } } } } };
  return { 'plugin.json': JSON.stringify(manifest, null, 2), 'mcp.json': JSON.stringify(mcp, null, 2) };
}
