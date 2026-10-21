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
After OAuth attestation, Jarvis callers with the send scope also discover the
one-time diagnostic schema regardless of arming (eight tools with both scopes).
An authenticated health result proves neither DB connectivity nor native wake.

Delivery flags never change the catalog. After attestation every token with a
directional scope is offered bridge_status, so a host showing only bridge_health
is displaying a cached or filtered list, not this server's output. Health
reports `caller`: the role, whether the token carries the send and ACK scopes,
and the exact tool names this server offers that caller. Compare it with the
host's displayed list before changing grants or reconnecting.

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

## Bounded queue failure recovery

An eligible private queue callback that still fails on delivery 18 or later
attempts to publish one successor on the existing topic before acknowledging
the old item. This happens in the asynchronous consumer, not the SDK's
synchronous retry hook. The successor preserves its work identifier, uses a
stable idempotency key for ambiguous publication/ACK outcomes, waits 60 seconds,
and carries an absolute recovery deadline. Descendants cannot extend that
deadline beyond the original queue item's expiry or one hour from its creation.
Workers retain all original source/recipient expiry, authorization and attempt
limits. Known-absent source/ACK commits do not spawn continuations.

This requires no new environment variable, grant, endpoint, schedule or service.
Healthy work adds no recovery publication. Prolonged handler/database failures
add queue publishes and callbacks within the fixed window; the five-attempt
transport cap stays unchanged. If the consumer cannot start, or every successor
publish also fails through the remaining SDK attempts, work can still exhaust
the platform budget. Cleanup remains best effort. This is bounded recovery of
known backend work, not assistant inbox polling or a guarantee of delivery.

HTTP acceptance does not schedule another hosted turn after a receiver fails.
These continuations do not retry accepted transports or the one-shot diagnostic,
and receipt leases alone do not recover hosted processing. Exactly-once durable
receipt/ACK creation does not guarantee exactly-once external agent actions.

## One-time Friday webhook diagnostic

Transport-only check of the saved Friday receiver binding while delivery stays
off. It is armed only when the OAuth contract is attested, storage and the
Friday URL/key are configured, FRIDAY_RECEIVER_ID is `jarvis-friday-bridge-inbox`
and FRIDAY_WEBHOOK_DIAGNOSTIC_FROM / FRIDAY_WEBHOOK_DIAGNOSTIC_UNTIL are fixed ISO
start/end timestamps for an interval of at most two hours total. Both values
are required: FROM must be at or before now, and UNTIL must be after now. Missing,
invalid, reversed or overlong intervals stay closed, including after a restart;
an overlong interval cannot become valid as time passes. This replaces the old
deadline-only configuration. Prepare both timestamps together for the approved
test window; no new credential or service is needed. Health reports
`fridayWebhookDiagnosticArmed`. After OAuth attestation, Jarvis with its send
scope alone sees `bridge_friday_webhook_diagnostic`, which takes no arguments,
even while unarmed. Friday never sees it; pre-attestation bootstrap stays health
only. Discovery grants no execution: every invocation checks readiness before
storage or transport setup, and an unarmed/expired call fails with
`friday_diagnostic_not_armed` without spending an attempt. This stable schema
allows the native catalog to refresh while delivery and the diagnostic are off.
Native caching or host filtering can still require a supported refresh.

The first call commits a durable spend marker with a fresh server UUID before
any request starts, then makes ONE POST: the saved URL, `Authorization: Bearer`
with the saved key, `Content-Type: application/json` and exactly
`{"event":"bridge.message.received","data":{"messageId":"<uuid>"}}`. There are
no retries. Concurrent calls, restarts, re-arming, timeouts and lost outcomes
only return the recorded attempt (`duplicate: true`); a second send needs a
code change. The window is checked again after the spend commits and before
starting transport. If it has closed, no request starts, the spend remains
permanent and the recorded result is `friday_diagnostic_expired`. Results carry
the UUID, numeric status or sanitized error, never
the URL, key or response body. No message is stored, so Friday's read of the
UUID returns message_not_found by design.

HTTP 2xx proves neither wake nor mapping. Evidence is the native Friday run
showing this exact event and data.messageId. Only then may an operator consider
FRIDAY_WEBHOOK_CONTRACT_VERIFIED; the diagnostic never sets it. Afterwards,
clear both diagnostic timestamps (the window also lapses on its own).

## Bounded operation evidence

Subscription requests accept an optional non-negative safe-integer `maxAgeMs`
as in the [MCP Events draft's cursor lifecycle](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md#cursor-lifecycle).
It has no effect on this event: replay is
unsupported and the cursor remains null. It never alters subscription identity,
lease expiry, callback verification or delivery admission. Non-null cursors and
unknown fields remain rejected. This compatibility allowance is not evidence
that the native host has sent this field or that it caused a renewal failure.

The existing store retains at most eight renewal-result observations per saved
subscription and eight read-result observations for the single diagnostic UUID.
Only records less than 24 hours old are visible. Retention is lazy: relevant
successful transactions prune stale records; idle storage does not have a timed
deletion guarantee. No new table, binding, schedule, service or credential is
needed. Each qualifying operation adds one best-effort store transaction and
its associated database latency. Recording failures are ignored without retry,
preserving the original result or error.

The existing subscription-status tool returns `inactiveReason` and
`renewalObservations` only for the caller's own subscriptions. Records contain
time, success/error, an allowlisted result code, an optional sanitized callback
failure reason, the granted refresh deadline, and whether the presented
authority expiry was new, same, later, earlier or unknown. They never retain
tokens, callback URLs, callback secrets, error messages or message content.
Failed initial setup without a saved identity, pre-authentication rejection,
runtime preflight failure and unavailable storage can leave no observation.
These records are not a complete request log. Recording never extends a lease,
reopens denied/unsubscribed access or changes subscription identity.

Rejected subscription parameter shapes can also record `invalid_params` when
the caller has current verified Jarvis/ACK authority and the known event,
exact filter and validated callback identify an existing caller-owned binding.
Only the usual fixed result metadata is saved, never parameter names/values or
callback URLs. Validation still rejects the request with its original error.
Unknown or malformed bindings are not invented from a supplied ID. A recognizable
binding requires one store lookup transaction; an unmatched owner/ID rolls it
back without a durable UPDATE. Unauthenticated, wrong-scope, expired-authority
or unrecognizable requests make no observation-store call. Recording is best
effort and cannot turn a malformed request into a subscription or retry.

After the diagnostic spend, an authorized Friday `bridge_read` of its exact
UUID can record its original success/error without storing the source payload.
Capture closes at the earlier of the original arm deadline and 30 minutes after
the spend, even if settings are subsequently changed. `bridge_status` exposes
these sanitized results when no source message exists: the original Jarvis
operator with ACK scope may inspect all records; Friday with ACK scope may see
only its own records. New first-spend markers save the operator's existing
hashed principal identity solely for this isolation. Legacy ownerless markers
are never backfilled and grant no new Jarvis status access. The permanent spend
marker is never cleared by evidence expiry. Existing stored-message status
responses stay unchanged.

`evidenceStatus: server_read_result_only_not_native_wake` and `wakeVerified:
false` are deliberate: a recorded read result proves a server call by that
authenticated principal, not the original native event context, routine wake,
claim, completion or ACK. No observation retries a request or enables delivery.
Deploying this change cannot recover the earlier diagnostic's missing trace.

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
