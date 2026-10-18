// Reject-only discovery/registration diagnostic. No clients, grants, tokens,
// sessions, credentials, outbound calls, or durable state are ever created.
// Authorization requests are rejected; log only allowlisted nonsecret metadata.
const ORIGIN = 'https://rn-jarvis-friday-discovery-20261018.vercel.app';
const HEADERS = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};
const json = (body, status = 200, extra = {}) =>
  Response.json(body, { status, headers: { ...HEADERS, ...extra } });
const emit = (event) => console.log('RN_OAUTH_DIAG ' + JSON.stringify(event));
const choice = (value, allowed) => allowed.includes(value) ? value : 'other-or-absent';
const enumArray = (value, allowed) => Array.isArray(value)
  ? [...new Set(value.map(x => choice(x, allowed)))].slice(0, 8) : [];

// Only callback origin/path are emitted; no userinfo, query, fragment or URL.
export function callbackMetadata(value) {
  try {
    const u = new URL(value);
    if (!['https:', 'http:', 'grokbot:', 'sand:'].includes(u.protocol) ||
        u.username || u.password || u.origin.length > 160 ||
        u.pathname.length > 256 || !/^\/[a-zA-Z0-9_./~%-]*$/.test(u.pathname)) {
      return { classification: 'unrecognized' };
    }
    return { origin: u.origin === 'null' ? u.protocol + '//' + u.host : u.origin,
      path: u.pathname };
  } catch { return { classification: 'invalid' }; }
}

async function registrationMetadata(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') || '')) {
    return { bodyClassification: 'not-json' };
  }
  let bytes = 0, raw = '';
  const reader = request.body?.getReader();
  if (!reader) return { bodyClassification: 'absent' };
  const decoder = new TextDecoder();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 8192) { await reader.cancel(); return { bodyClassification: 'too-large' }; }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
    const b = JSON.parse(raw);
    raw = '';
    if (!b || Array.isArray(b) || typeof b !== 'object') return { bodyClassification: 'invalid' };
    return {
      bodyClassification: 'json',
      callbacks: Array.isArray(b.redirect_uris) ? b.redirect_uris.slice(0, 8).map(callbackMetadata) : [],
      tokenEndpointAuthMethod: choice(b.token_endpoint_auth_method,
        ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt']),
      grantTypes: enumArray(b.grant_types, ['authorization_code', 'refresh_token']),
      responseTypes: enumArray(b.response_types, ['code']),
    };
  } catch { return { bodyClassification: 'unreadable-or-invalid' }; }
}

export async function handleDiagnostic(request) {
  const u = new URL(request.url);
  // Match exact known route shapes; never emit arbitrary paths or queries.
  const resource = u.pathname.match(/^\/oauth-diag\/(dcr|cimd|public)\/mcp$/);
  const prm = u.pathname.match(/^\/\.well-known\/oauth-protected-resource\/oauth-diag\/(dcr|cimd|public)\/mcp$/);
  const as = u.pathname.match(/^\/\.well-known\/oauth-authorization-server\/oauth-diag\/(dcr|cimd|public)$/) ||
    u.pathname.match(/^\/oauth-diag\/(dcr|cimd|public)\/\.well-known\/(?:oauth-authorization-server|openid-configuration)$/) ||
    u.pathname.match(/^\/\.well-known\/openid-configuration\/oauth-diag\/(dcr|cimd|public)$/);
  const action = u.pathname.match(/^\/oauth-diag\/(dcr|cimd|public)\/(register|authorize|token)$/);
  if (!resource && !prm && !as && !action) return null;
  const mode = (resource || prm || as || action)[1];
  const issuer = ORIGIN + '/oauth-diag/' + mode;
  if (request.headers.get('origin') && request.headers.get('origin') !== ORIGIN) {
    return json({ error: 'forbidden_origin' }, 403);
  }
  if (resource) {
    emit({ mode, kind: 'resource-401', method: choice(request.method, ['GET', 'POST']) });
    return json({ error: 'diagnostic_authorization_required', noGrantsOrTokens: true }, 401,
      { 'WWW-Authenticate': 'Bearer resource_metadata="' + ORIGIN +
        '/.well-known/oauth-protected-resource/oauth-diag/' + mode + '/mcp"' });
  }
  if (prm || as) {
    if (request.method !== 'GET') return json({ error: 'method_not_allowed' }, 405);
    emit({ mode, kind: prm ? 'protected-resource-metadata' : 'authorization-server-metadata' });
    if (prm) return json({ resource: issuer + '/mcp', authorization_servers: [issuer],
      bearer_methods_supported: ['header'], scopes_supported: ['probe:health'],
      resource_name: 'Reject-only OAuth diagnostic; no grants or tokens' });
    return json({ issuer, authorization_endpoint: issuer + '/authorize',
      token_endpoint: issuer + '/token',
      ...(mode === 'public' ? {} : { registration_endpoint: issuer + '/register' }),
      response_types_supported: ['code'], grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
      scopes_supported: ['probe:health'], client_id_metadata_document_supported: mode === 'cimd' });
  }
  if (action[2] === 'register') {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
    emit({ mode, kind: 'registration-rejected', method: 'POST',
      ...(await registrationMetadata(request)) });
    return json({ error: 'invalid_client_metadata',
      error_description: 'Diagnostic intentionally rejects registration; no client or credential created.' }, 400);
  }
  // Never inspect headers or token bodies. For authorization, extract only the
  // fields needed for compatibility; never log raw URLs, state or challenges.
  const authorization = action[2] === 'authorize';
  const params = u.searchParams;
  emit({ mode, kind: authorization ? 'authorization-rejected' : 'token-rejected',
    ...(authorization ? {
      callback: callbackMetadata(params.get('redirect_uri')),
      responseType: choice(params.get('response_type'), ['code']),
      clientIdClassification: /^https:\/\/[^/]+\/.+/.test(params.get('client_id') || '')
        ? 'https-metadata-url' : params.has('client_id') ? 'opaque' : 'absent',
      pkceMethod: choice(params.get('code_challenge_method'), ['S256', 'plain']),
      statePresent: params.has('state'), challengePresent: params.has('code_challenge'),
      sensitiveParameterPresent: ['client_secret', 'code', 'access_token', 'refresh_token',
        'code_verifier', 'id_token', 'password'].some(key => params.has(key)),
    } : {}) });
  return json({ error: 'access_denied',
    error_description: 'Reject-only diagnostic. No consent, code, grant, client or token can be issued.' }, 400);
}
