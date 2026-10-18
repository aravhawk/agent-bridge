import { SCOPES } from './policy.mjs';

export const ORIGIN = 'https://rn-jarvis-friday-discovery-20261018.vercel.app';
export const ISSUER = 'https://musical-bee-9978.clerk.accounts.dev';
export const JWKS = ISSUER + '/.well-known/jwks.json';
export const resourceFor = role => `${ORIGIN}/bridge/${role}/mcp`;
export const metadataFor = role => `${ORIGIN}/.well-known/oauth-protected-resource/bridge/${role}/mcp`;
const roles = ['friday', 'jarvis'];
const json = (body, status = 200, headers = {}) => Response.json(body, { status, headers: {
  'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers,
} });
const challenge = role => json({ error: 'unauthorized' }, 401, {
  'www-authenticate': `Bearer resource_metadata="${metadataFor(role)}"`,
});

// Public discovery describes only the real, pre-registered provider. This
// server cannot register clients, authorize grants, issue or refresh tokens.
export function createResourceRouter({ legacy, getHandler }) {
  return async request => {
    const url = new URL(request.url);
    const role = roles.find(r => url.pathname === `/bridge/${r}/mcp`);
    const metadataRole = roles.find(r => url.pathname === `/.well-known/oauth-protected-resource/bridge/${r}/mcp`);
    if (!role && !metadataRole) return legacy(request);
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) return json({ error: 'forbidden_origin' }, 403);
    if (metadataRole) {
      if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET' });
      return json({ resource: resourceFor(metadataRole), authorization_servers: [ISSUER],
        bearer_methods_supported: ['header'], scopes_supported: Object.values(SCOPES[metadataRole]),
        resource_name: `RN Jarvis Friday Synthetic Bridge — ${metadataRole}` });
    }
    // Authentication discovery must work before secrets/subject configuration.
    // The presence of a header alone never authorizes a request.
    if (!request.headers.get('authorization')) return challenge(role);
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'POST' });
    try { return await (await getHandler(role))(request); }
    catch { return json({ error: 'bridge_configuration_required' }, 503); }
  };
}
