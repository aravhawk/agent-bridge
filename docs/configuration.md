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
also verified. Jarvis's signed native Events callback and persisted active
subscription were verified on October 19; live renewal remains untested.

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

`src/access.mjs` implements bounded Jarvis authorization leases and durable
resource denial. The existing verifier checks signature, issuer, audience,
pinned subject and scopes; it passes only verified token expiry and a policy
fingerprint internally. Tokens and raw claims are never stored in subscriptions.
No Clerk backend credential or custom grant-reader API is required.

Every subscription is finite. The deadline is the earliest of the requested
TTL (one day when omitted, seven-day server cap when null), the seven-day
maximum, and the verified JWT expiration. There is no minimum-TTL extension or
clock-tolerance extension. A refresh with the same verified expiration cannot
extend the saved deadline; a later verified expiration can. Older tokens,
legacy subscriptions without authorization metadata and changed policy/owner
bindings fail closed. The callback challenge and final save recheck expiry and
durable denial. The worker checks owner, recipient, resource, scope, status,
pinned policy, hard expiry and denial before sending and at final commit.

Resource denial is server-owned state in the existing aggregate's optional
`resourceDenials` map. The operator-only `denyResourceAccess` application helper
persists the denial and deactivates that owner's Jarvis subscriptions. It is
not exposed as a new MCP/admin endpoint. Renewals never erase denial, and
unsubscribe writes a durable inactive tombstone even if callback verification
is in flight. No database schema migration or separate store is needed.

This is the signed-JWT expiry model, not instant provider introspection: Clerk
revocation alone cannot instantly invalidate an already issued JWT. Local
resource denial and unsubscribe stop this bridge immediately; otherwise the
finite lease ends no later than token expiry. See [Clerk token formats](https://clerk.com/docs/guides/development/machine-auth/token-formats).
A network request already in flight cannot be recalled; the final worker fence
prevents late completion from recording revoked/expired authority as accepted.

[Native subscription renewal](https://developers.openai.com/plugins/build/mcp-events#refresh-a-subscription)
uses `events/subscribe` again before the finite `refreshBefore`, even when the
client requested `ttlMs:null`. Live native OAuth refresh and native subscription
renewal remain separate unverified tests. Neither discovery nor local tests
prove that the host renewed the live subscription.

## Runtime storage and gates

Vercel injects `DATABASE_URL` from the existing isolated Neon integration in
Production only. Never pull it into a local `.env`, copy it from the dashboard,
or commit it. TLS must be verified and the hostname must be a Neon host.

The real allowed subject is pinned through sensitive Production configuration.
Do not copy the subject or its configured digest into the repository. Configure
one of `BRIDGE_ALLOWED_SUBJECT` or `BRIDGE_ALLOWED_SUBJECT_SHA256`, never both.
`BRIDGE_OAUTH_SCOPE_CLAIM=scope` matches the verified provider contract.

`BRIDGE_OAUTH_CONTRACT_VERIFIED` is true in the existing Production runtime.
The example file remains closed by default. The current approved gates are:

```text
BRIDGE_DELIVERY_ENABLED=false
BRIDGE_SUBSCRIPTIONS_ENABLED=true
BRIDGE_AUTH_DIAGNOSTIC=false
BRIDGE_AUTH_TIMING_DIAGNOSTIC=false
BRIDGE_RPC_SHAPE_DIAGNOSTIC=false
```

Flags alone cannot enable delivery. The default runtime still requires an
valid JWT-bound lease metadata, callback protection and a supported Friday sender/access binding.
Native callback configuration requires a securely supplied 32-byte AES-GCM
protector key. No placeholder allow-all adapter, relay or polling listener is
acceptable. Do not generate a new credential merely to inspect a setup flow.

Subscription setup enables only the signed callback verification handshake;
it does not enable message writes or application delivery. Preserve the current
subscription gate while completing Friday receiver acceptance.

## Probe admission and idempotence

New probe IDs are limited to 10 per rolling 60 seconds for each authenticated
sender role. The JWT verifier binds each of the two fixed role slots to the
configured pinned subject and exact resource audience. Admission timestamps
are stored in the existing durable aggregate under the same row lock as message
and job creation: at most two arrays of 10 timestamps, no new service, schema,
credential or platform rule. Concurrent function instances and restarts share
the budget; failed insertions roll back their admission.

Exact canonical retransmissions remain idempotent, including at a full budget
or after the five-minute freshness window. Changed content for a saved ID still
conflicts. New stale/future envelopes, unknown fields and invalid directional
scopes fail before admission. An admitted probe may generate only its existing
atomic single receipt ACK; ACK completion does not spend fresh-probe admission
and cannot generate an ACK-of-ACK. A fresh-ID overflow returns HTTP 429 with
`probe_rate_limited`, creates no message/job and makes no scheduling request.

This caps accepted fresh probes, not all authenticated HTTP/duplicate traffic.
The 32 KiB body limit, aggregate capacity limit, five actual delivery attempts
and 20 queue-callback budget remain separate bounds. No random test is armed;
its `sentAt` must be generated when it fires to satisfy five-minute freshness.

## Native receivers

Jarvis must discover MCP2026-07-28 Events, list `bridge.message.received`, and
establish a native subscription with arguments `recipient:"jarvis"` and
`ttlMs:null`. The server grants a finite token-bounded `refreshBefore`; the host
must renew using fresh verified authority. The host supplies its callback URL and signing secret in the
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
and verify delivery and temporary diagnostics remain false while the approved
Jarvis subscription setup gate remains true.
Remote reports belong in ignored `.reports/remote/`, not in Git. Investigate
build failures only within this project's deployment configuration; never
alter OAuth URLs, read secrets or enable delivery to make a build pass.
