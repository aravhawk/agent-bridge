import { isIP } from 'node:net';
import { SCOPES } from './policy.ts';
import { PUBLIC_ORIGIN, SERVICE_NAME, VERSION } from './release.ts';
import { CONFIG, PEER_IDS } from './config.ts';
import type { PeerScopes } from './config.ts';
import type { Role } from './types.ts';

export const ORIGIN = PUBLIC_ORIGIN;
export const resourceFor = (role: Role) => `${ORIGIN}/bridge/${role}/mcp`;
export const metadataFor = (role: Role) => `${ORIGIN}/.well-known/oauth-protected-resource/bridge/${role}/mcp`;
const roles = PEER_IDS;
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => Response.json(body, { status, headers: {
  'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers,
} });
// Required operator configuration obtained from the actual approved provider.
// No guessed issuer, development fallback, request-selected key URL or issuer.
// The issuer must be a bare HTTPS origin serving /.well-known/jwks.json. With
// BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN it must also be a subdomain of the origin.
export interface ProviderConfiguration { readonly issuer: string; readonly jwks: string }
export function providerConfiguration(value: unknown, { requireUnderOrigin = CONFIG.requireIssuerUnderOrigin } = {}): ProviderConfiguration | null {
  try {
    if (typeof value !== 'string' || value.trim() !== value) return null;
    const u = new URL(value);
    if (value !== u.origin || u.protocol !== 'https:' || u.username || u.password || u.search || u.hash ||
        u.pathname !== '/' || u.port || (requireUnderOrigin && !u.hostname.endsWith('.' + new URL(ORIGIN).hostname)) || isIP(u.hostname) ||
        /(?:^|\.)(?:localhost|local|internal)$/.test(u.hostname)) return null;
    return Object.freeze({ issuer: u.origin, jwks: u.origin + '/.well-known/jwks.json' });
  } catch { return null; }
}
export type RequestHandler = (request: Request) => Response | Promise<Response>;
export interface ResourceRouterOptions {
  getHandler: (role: Role) => RequestHandler | Promise<RequestHandler>;
  getProvider?: () => ProviderConfiguration | null;
}
export function createResourceRouter({ getHandler, getProvider = () => providerConfiguration(process.env.BRIDGE_OAUTH_ISSUER) }: ResourceRouterOptions): RequestHandler {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (['/', '/health'].includes(url.pathname) && request.method === 'GET') return json({ status: 'ok', service: SERVICE_NAME,
      version: VERSION, authenticationRequired: true });
    const role = roles.find(r => url.pathname === `/bridge/${r}/mcp`);
    const metadataRole = roles.find(r => url.pathname === `/.well-known/oauth-protected-resource/bridge/${r}/mcp`);
    if ((!role && !metadataRole) || url.origin !== ORIGIN) return json({ error: 'not_found' }, 404);
    const origin = request.headers.get('origin');
    if (origin && origin !== ORIGIN) return json({ error: 'forbidden_origin' }, 403);
    if (metadataRole) {
      if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405, { allow: 'GET' });
      const provider = getProvider();
      if (!provider) return json({ error: 'identity_provider_not_configured' }, 503);
      return json({ resource: resourceFor(metadataRole), authorization_servers: [provider.issuer],
        bearer_methods_supported: ['header'], scopes_supported: Object.values(SCOPES[metadataRole] as PeerScopes),
        resource_name: `${SERVICE_NAME} — ${metadataRole}` });
    }
    if (!request.headers.get('authorization')) return json({ error: 'unauthorized' }, 401, {
      // Not a metadata path, so `role` matched the MCP path.
      'www-authenticate': `Bearer resource_metadata="${metadataFor(role as Role)}"`,
    });
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { allow: 'POST' });
    try { return await (await getHandler(role as Role))(request); }
    catch { return json({ error: 'bridge_configuration_required' }, 503); }
  };
}
