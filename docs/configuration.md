# Configuration and preserved boundaries

## Public OAuth settings

Issuer: `https://musical-bee-9978.clerk.accounts.dev`.
Authorization: issuer plus `/oauth/authorize`; token: issuer plus `/oauth/token`.
Both clients are public, token endpoint authentication `none`, required S256,
provider-hosted consent, JWT access tokens and Include Audience enabled.
No client secret belongs in this repository. DCR/CIMD and device grants are off.

| Native side | Public client ID | Requested scopes | Exact resource audience |
|---|---|---|---|
| Friday | `jtwi71bhdmkGqilW` | `bridge:send:jarvis bridge:ack:friday offline_access` | Production origin + `/bridge/friday/mcp` |
| Jarvis | `f58dfaNi1qX2vtdx` | `bridge:ack:jarvis bridge:send:friday offline_access` | Production origin + `/bridge/jarvis/mcp` |

Friday's callback is `https://www.cursor.com/agents/mcp/oauth/callback`.
The native ChatGPT form displayed
`https://chatgpt.com/connector_platform_oauth_redirect`, matching Jarvis's saved
callback. Always compare the actual native management value before changing an
allowlist. Public client IDs and resource URLs are not credentials.

Jarvis uses OIDC disabled and no identity/metadata scopes. Custom directional
scopes are intentionally not advertised globally, but assigned to each client.
Actual native Friday authentication and bridge-tool discovery were verified.
Jarvis's managed custom MCP grant, original five tools and event discovery are
also verified. Persistent native Events subscription remains pending.

Managed Jarvis plugin: `plugin_asdk_app_6ad53911909481919c20dfb6f8d3fb51`;
connector: `asdk_app_6ad53911909481919c20dfb6f8d3fb51`. This is the connected
custom MCP registration; the portable plugin in `plugin/` is a separate source
package. Do not create a duplicate registration to refresh tools.

## Authenticated health and current access

`bridge_health` accepts `{}` and requires the existing verified resource
identity plus at least one role-specific bridge scope. It returns successful
MCP content containing only authenticated status, server version and nonsecret
configuration/readiness booleans. It does not initialize the database, mutate
state, access messages, check the grant provider, enqueue jobs or send a
callback. Normal JWT verification retains the existing provider JWKS resolver;
the health operation adds no outbound call. `storageConfigured` reports binding
presence, not a database connectivity check. `subscriptionSetupEnabled` and
`deliveryEnabled` report effective gates, not successful subscription or wake.

After a deployment adding the tool, refresh the existing custom app's action
list in its management UI (if offered), or start a new host turn and rediscover
the existing connector. Verify `bridge_health` is exposed, then invoke it once
with `{}` through that same connector. Do not replace this with the public
health endpoint or count `message_not_found` as successful tool execution.
No OAuth reconnection or expanded grant is required by this backend change.

`src/access.mjs` implements a Jarvis-only current-access adapter. Every check
requires a trusted `readCurrentGrant` integration and matches the pinned
subject, issuer, client `f58dfaNi1qX2vtdx`, exact Jarvis resource, acknowledgment
scope, active/unrevoked state, future expiry and freshly checked facts. The
owner must match the verified principal digest. Wrong or absent facts and
provider errors return false. Facts are never accepted from tool arguments or
saved JWT assertions, and no raw identity, token or provider error is logged.

The reader contract returns `{active, revoked, issuer, clientId, resource,
subject, scopes, checkedAt, expiresAt}` internally; timestamps are epoch
milliseconds. It must query an authoritative current grant/revocation source on
each call. The adapter does not establish that source or create a credential.
Production currently has no reader bound and reports
`currentAccessCheckConfigured:false`; therefore subscriptions and delivery
remain closed. Do not bind a placeholder reader or treat signature validity
as current OAuth revocation evidence. A supported provider read source and any
required least-privilege credential must be reviewed before provisioning it.

The adapter is checked before native subscription callback/storage work and
again by the worker before Jarvis delivery. It deliberately denies Friday
delivery; that requires a separately verified sender/access binding.

## Runtime storage and gates

Vercel injects `DATABASE_URL` from the existing isolated Neon integration in
Production only. Never pull it into a local `.env`, copy it from the dashboard,
or commit it. TLS must be verified and the hostname must be a Neon host.

The real allowed subject is pinned through sensitive Production configuration.
Do not copy the subject or its configured digest into the repository. Configure
one of `BRIDGE_ALLOWED_SUBJECT` or `BRIDGE_ALLOWED_SUBJECT_SHA256`, never both.
`BRIDGE_OAUTH_SCOPE_CLAIM=scope` matches the verified provider contract.

`BRIDGE_OAUTH_CONTRACT_VERIFIED` is true in the existing Production runtime.
The example file remains closed by default. These flags must remain false until
the corresponding acceptance work is complete:

```text
BRIDGE_DELIVERY_ENABLED=false
BRIDGE_SUBSCRIPTIONS_ENABLED=false
BRIDGE_AUTH_DIAGNOSTIC=false
BRIDGE_AUTH_TIMING_DIAGNOSTIC=false
BRIDGE_RPC_SHAPE_DIAGNOSTIC=false
```

Flags alone cannot enable delivery. The default runtime still requires an
authoritative current-grant reader for the access adapter and a supported Friday sender binding.
Native callback configuration requires a securely supplied32-byte AES-GCM
protector key. No placeholder allow-all adapter, relay or polling listener is
acceptable. Do not generate a new credential merely to inspect a setup flow.

## Native receivers

Jarvis must discover MCP2026-07-28 Events, list `bridge.message.received`, and
establish a native persistent subscription with arguments `recipient:"jarvis"`
and `ttlMs:null`. The host supplies its callback URL and signing secret in the
authenticated handshake. Never ask for that secret in chat.

The current Friday UI exposes a Routines list and the existing email routine's
pause toggle, but no usable pre-creation webhook form. Its guide documents POST
and a persistent URL/sender-key capability, but not the exact body/auth/replay
contract or a safe direct credential handoff to Vercel. No incoming webhook
routine/key has been created for this bridge. Do not assume a generic xAI
webhook format applies to the Bot app or repeat the unusable panel-copy path.

Keep existing routines/subscriptions enabled unless explicitly instructed
otherwise. No schedule or random test should be armed before both native
receivers and the subscription are verified. Test credential refresh only
after the actual native access token expires, without extracting a token or
changing its lifetime.

## Publishing and deployment

Only project source and nonsecret configuration belong here. Do not add message
histories, session dumps, browser state, screenshots, environment pulls, real
callback secrets, auth URLs containing flow parameters, or unrelated artifacts.
The history audit prints rule names and paths, never matching secret values.

CI uses no deployment secret and runs no remote/native test. The existing
Vercel project is connected to `aravhawk/jarvis-friday-bridge` through its
already-authorized GitHub installation. The saved dashboard connection was
verified after navigating away and back; no new grant or sign-in was needed.
Production tracks `main`; Root Directory is blank (repository root), Framework
Other, Node.js 24.x, with no build/output/install command overrides. The root's
`api/`, `package.json` and `vercel.json` match those settings. Do not create
another Vercel project or expand installation permissions for this setup.

Linking did not start a deployment. The initial repository commit passed 59
local/CI tests and staged/history secret scans. All 34 credential-free remote
checks passed after linking: 11 bridge authentication/metadata/boundary checks,
12 original health-only MCP checks and 11 rejecting OAuth diagnostic checks.
These checks verify public behavior, tool discovery and `probe_health`, and
that invalid or unauthenticated bridge requests fail closed. They do not prove
native OAuth refresh, authenticated Events subscription, durable delivery or a
hosted wake. Those remain gated by the acceptance requirements above.

For a Git-triggered release, match the deployment's Git SHA to the pushed
`main` commit and require Ready status on the same existing project. Confirm
the canonical URL still points to that deployment, run `npm run check:remote`,
and verify delivery/subscriptions and temporary diagnostics remain false.
Remote reports belong in ignored `.reports/remote/`, not in Git. Investigate
build failures only within this project's deployment configuration; never
alter OAuth URLs, read secrets or enable delivery to make a build pass.
