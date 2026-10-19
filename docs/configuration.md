# Jarvis Friday Bridge v1.0.0 configuration

## Fixed service identity

Origin: `https://jarvis-friday-bridge.aravhawk.com`.
Only this origin accepts authenticated MCP and resource metadata. Default Vercel
aliases may expose public liveness but do not accept MCP credentials. Request
headers cannot select the issuer, JWKS, role, callback, destination or audience.

| Client | Resource audience | Directional scopes | Existing native callback to confirm in actual final form |
|---|---|---|---|
| Jarvis | Origin + `/bridge/jarvis/mcp` | bridge:send:friday, bridge:ack:jarvis, offline_access | https://chatgpt.com/connector_platform_oauth_redirect |
| Friday | Origin + `/bridge/friday/mcp` | bridge:send:jarvis, bridge:ack:friday, offline_access | https://www.cursor.com/agents/mcp/oauth/callback |

Both clients are public, provided registrations, token authentication none,
required S256 PKCE and provider-hosted consent. JWT access tokens must include
the exact resource audience. No client Secret, DCR/CIMD, device grant, OIDC
identity scopes or provider-admin API key is required by this resource server.
Callbacks above are the previously observed native values; recheck the actual
new client flow before saving an allowlist. Do not guess replacements.

## Provider identity and bootstrap

BRIDGE_OAUTH_ISSUER is required and blank by default. Obtain the exact HTTPS
origin from the new approved Clerk production instance's live metadata; verify
issuer/JWKS endpoints after DNS/TLS. It must be beneath the service's namespace
(`*.jarvis-friday-bridge.aravhawk.com`), without credentials, path, query, port or
fragment. A development issuer or unrelated domain is rejected. There is no
assumed production issuer/client ID in source. The fixture identity used by
unit tests is not a deployed or proposed provider configuration.

During Clerk setup, select the subdomain-scoped Secondary application when
offered. A Primary application may use clerk.aravhawk.com, which is outside this
issuer constraint. Confirm the actual issuer from production metadata before
native grants; stop if a compatible setup is unavailable instead of weakening
the constraint or guessing DNS records.

Pin the real new production user's subject using BRIDGE_ALLOWED_SUBJECT_SHA256
as a Production Secret; do not reuse the development instance's subject pin.
Never put raw tokens, user IDs, login flows or Secret values in source/reports.
The displayed provider subject can be hashed locally without printing it and
only the digest saved to the approved new Secret target. Actual sign-in or
credential entry remains a native/human flow. No fabricated allow-all pin.

Once provider + pin are configured, the resource can expose authenticated
bridge_health alone even while BRIDGE_OAUTH_CONTRACT_VERIFIED=false. It still
checks real JWT signature, issuer, role audience, subject and scopes. Bootstrap
cannot list/subscribe to events or read/write message data; authenticated
unsubscribe remains available to honor withdrawal. It never issues/echoes tokens
or logs claims. Require successful native health under BOTH actual clients
before attesting the OAuth contract and refreshing the same app's tools. Health
accepts at least one appropriate directional scope; it does not prove both send
AND ACK scopes. Independently verify both required scopes for each actual
grant/token without exposing tokens/claims before attestation. If that proof is
unavailable in the supported native flow, keep the OAuth contract unattested.

Normal v1 catalog: seven Jarvis tools, six Friday tools. There is no synthetic
bridge_send. bridge_message_send handles bounded data; read/receipt/status tools
are scoped; Jarvis additionally has safe bridge_subscription_status metadata.
An authenticated health result proves neither DB connectivity nor native wake.

## New project Secret/config bindings

Only Production on project prj_rTBPrIoODxpC1A6sS2OQtlvc7cqE, Arav's Projects.
Do not pull environment files or copy/decrypt old project secrets.

- DATABASE_URL: native Neon integration Secret for a NEW isolated database;
  verified TLS (`verify-full`), Neon hostname, poolmax2. Apply schema.sql only
  after approval to the new empty database. No auto-migration or memory fallback.
- BRIDGE_SUBSCRIPTION_STORAGE_KEY: fresh32-byte key, stored as a sensitive
  Production Secret. Protects native callback data with AES-GCM and ID-bound AAD.
- FRIDAY_WEBHOOK_URL / FRIDAY_WEBHOOK_KEY: dedicated new receiver binding, saved
  through approved private transfer. Never ask for either in chat or reveal it.
- BRIDGE_ALLOWED_SUBJECT_SHA256: new production identity pin, Secret.
- BRIDGE_OAUTH_ISSUER / BRIDGE_OAUTH_SCOPE_CLAIM=scope: verified public provider
  contract. No Clerk backend Secret key is needed or copied into the backend.

Closed defaults:

```text
BRIDGE_OAUTH_CONTRACT_VERIFIED=false
BRIDGE_SUBSCRIPTIONS_ENABLED=false
BRIDGE_DELIVERY_ENABLED=false
BRIDGE_RECEIVER_POLICY=
FRIDAY_RECEIVER_ID=jarvis-friday-bridge-inbox
FRIDAY_WEBHOOK_CONTRACT_VERIFIED=false
```

After native health/contract proof, subscription setup can be enabled separately
from delivery. Native ChatGPT creates exactly one new v1 subscription with its
own callback/secret. Its lease is capped by verified JWT expiry. Same-token
renewal cannot extend expiry; later verified token expiry can. Denial and
unsubscribe tombstones survive renewal/restart. No provider introspection or
immortal lease is claimed. Verify actual native renewal and exact subscription
identity before transport activation; metadata count alone does not prove it.

Delivery additionally requires verified Friday binding/contract and attested
inbox-v1 policies on BOTH receivers, then global delivery true. New grants and
these activations require the specifically reviewed action-time bundle. A flag
is an operator attestation, not independent evidence. Do not reuse old test
windows, IDs, grants, callbacks or activation approvals for the changed realm.

## Public metadata/package checks

`npm run check:remote` expects an unconfigured, closed v1 deployment. After
actual verified issuer setup, use `python3 scripts/check_v1.py --issuer <actual>`;
after JWT policy is configured add `--auth-configured`. These compare public
metadata and send only an invalid nonsecret fixture, never a real token/event.

Portable plugin source is v1.0.0 with an explicitly non-live MCP template. Render
only after obtaining actual approved public client metadata:

```sh
python3 scripts/package_plugin.py --issuer <actual-issuer-origin> --jarvis-client-id <actual-public-id>
```

Output stays in ignored .reports/. Rendering does not install a plugin, create
a grant or replace the actual native custom MCP registration. Do not install
unresolved templates or create duplicate registrations to refresh discovery.
