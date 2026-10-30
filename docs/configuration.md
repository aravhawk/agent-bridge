# Configuration reference (v1.0.0)

All configuration is environment variables. Nothing a caller sends can select
the issuer, key source, peer, audience, callback destination or signing secret.
Copy [`.env.example`](../.env.example) as a starting point and keep every
secret in your platform's secret store, never in the repository.

## Deployment identity

Read once when the function starts. An invalid value stops startup with a
`ConfigurationError` instead of serving with a guessed default.

| Variable | Default | Meaning |
|---|---|---|
| `BRIDGE_PUBLIC_ORIGIN` | *(required)* | Public HTTPS origin, e.g. `https://bridge.example.com`. No path, port or trailing slash. Only this origin accepts MCP and resource-metadata requests; other aliases (such as a default `*.vercel.app` domain) serve public health only. |
| `BRIDGE_PEERS` | *(required)* | Exactly two peers: `<id>:events,<id>:webhook`. IDs are lowercase letters, digits and inner hyphens (max 32). |
| `BRIDGE_SERVICE_NAME` | `Agent Inbox Bridge` | Name in `/health` and resource metadata. |
| `BRIDGE_MESSAGE_PROTOCOL` | `agent-inbox/1` | Protocol ID stored and advertised. `agent-inbox/1` and `jarvis-friday/1` are both accepted on input and normalized to this value. |
| `BRIDGE_RECEIVER_ID` | `agent-inbox-bridge` | Receiver ID the webhook peer's attestation must match. |
| `BRIDGE_QUEUE_TOPIC` | `jarvis-friday-bridge-v1` | Vercel Queue topic. **Must equal** the trigger topic in `vercel.json`. The default is historical; change both together if you rename it. |
| `BRIDGE_QUEUE_REGION` | `iad1` | Vercel Queue region; keep it aligned with `regions` in `vercel.json`. |
| `BRIDGE_REQUIRE_ISSUER_UNDER_ORIGIN` | `false` | When `true`, the OAuth issuer must be a subdomain of the public origin (e.g. `https://clerk.bridge.example.com`). |
| `BRIDGE_DATABASE_HOST_SUFFIX` | *(empty)* | Optional pin for the database hostname, e.g. `.neon.tech`. |

### Peers and scopes

Each peer has its own MCP resource and audience, `<origin>/bridge/<id>/mcp`,
and two OAuth scopes derived from its ID:

| Scope | Grants |
|---|---|
| `bridge:send:<counterpart>` | Send message/status/handoff-request data to the other peer's inbox (and, for the events peer, the one-time webhook diagnostic). |
| `bridge:ack:<self>` | Read, claim and complete messages addressed to this peer (and, for the events peer, event subscriptions). |

Ask for `offline_access` as well if your host refreshes tokens. The
**events peer** receives deliveries as signed MCP event callbacks that it
registers itself with `events/subscribe`. The **webhook peer** receives a POST
to a server-configured URL. The bridge is deliberately a two-party inbox; it
does not fan out, relay or route between more peers.

### Compatibility mode

If `BRIDGE_PUBLIC_ORIGIN` is **unset**, the bridge reproduces the original
deployment it was extracted from. The original operator needs no
environment change. The compatibility defaults are origin
`https://jarvis-friday-bridge.aravhawk.com`, peers `jarvis:events,friday:webhook`,
service name `Jarvis Friday Bridge`, protocol `jarvis-friday/1`, receiver ID
`jarvis-friday-bridge-inbox`, the issuer-under-origin rule on, and the database
host pinned to `.neon.tech`. Webhook-peer names keep their original spelling:
the `bridge_friday_webhook_diagnostic` tool, the `friday*` readiness keys, the
`friday_*` error codes and the `fridayWebhookDiagnostic`/`fridayCanary` state
keys. In generic mode these become `bridge_webhook_diagnostic`, `webhook*` and
`webhook_*`. New deployments should always set `BRIDGE_PUBLIC_ORIGIN`.

## OAuth provider and identity

| Variable | Meaning |
|---|---|
| `BRIDGE_OAUTH_ISSUER` | Required. The provider's exact issuer: a bare HTTPS origin (no path, port, query or credentials, not an IP or `localhost`) that serves its JWKS at `/.well-known/jwks.json`. Clerk production instances fit this shape. |
| `BRIDGE_ALLOWED_SUBJECT_SHA256` | Hex SHA-256 of the one allowed token `sub`. Preferred over the raw value. |
| `BRIDGE_ALLOWED_SUBJECT` | Alternative: the raw allowed `sub`. Set exactly one of the two. |
| `BRIDGE_OAUTH_SCOPE_CLAIM` | `scope` (default), `scp` or `scopes`. |
| `BRIDGE_OAUTH_CONTRACT_VERIFIED` | `true` only after you have verified real tokens for both peers (below). |

Tokens must be RS256 JWTs with `exp`, `iat` and `sub`, the exact peer resource
as audience and the configured issuer. Both peer clients are public OAuth
clients (PKCE S256, token auth `none`) registered in the provider. The bridge
never issues, stores or logs tokens and needs no provider admin secret.

**Bootstrap.** Once the issuer and subject pin are set, each peer can call an
authenticated `bridge_health` even while `BRIDGE_OAUTH_CONTRACT_VERIFIED=false`.
Health still verifies signature, issuer, audience, subject and scopes; it reads
no messages and lists no events. Its `caller` field reports the role, whether
the token carries the send and ACK scopes, and the exact tool names offered.
Compare that with what your host displays before attesting the contract.

## Storage

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | `postgres://` or `postgresql://` URL with `sslmode=require` or `verify-full`. The bridge always connects with `verify-full` against public CAs, so `sslrootcert`, `sslcert` and `sslkey` are rejected. Apply [`schema.sql`](../schema.sql) once to an empty database. |
| `BRIDGE_SUBSCRIPTION_STORAGE_KEY` | 32 random bytes, base64 (e.g. `openssl rand -base64 32`). Encrypts subscription callback URLs and secrets with AES-256-GCM, bound to the subscription ID. |

There is no auto-migration and no in-memory production fallback. State is a
single row locked per transaction, sized for a single owner's workload
(at most 100 live source messages and a 4 MiB document).

## Readiness gates

Every gate defaults to closed. A flag is an operator attestation, not evidence.

| Variable | Opens |
|---|---|
| `BRIDGE_SUBSCRIPTIONS_ENABLED=true` | Events-peer `events/subscribe` (requires the OAuth contract, storage and storage key). |
| `BRIDGE_RECEIVER_POLICY=inbox-v1` | Attests that both receivers enforce the [inbox contract](inbox-policy.md). |
| `BRIDGE_DELIVERY_ENABLED=true` | Message send, receipts and queue delivery, only if every other gate is also satisfied. |

`bridge_health` reports each gate under `readiness`. Delivery flags never
change the tool catalog: the events peer sees seven tools (eight with the send
scope after attestation, including the diagnostic), the webhook peer six. The
one exception is `BRIDGE_WAKE_SYNC_RECIPIENTS` (below): an enabled recipient
also sees `bridge_inbox_read`, and `readiness.wakeSync` appears once it is set.

## Webhook peer

Per-peer variables use the prefix `BRIDGE_PEER_<ID>_`, where `<ID>` is the
webhook peer ID upper-cased with `-` replaced by `_` (peer `ops-bot` →
`BRIDGE_PEER_OPS_BOT_`). The original `FRIDAY_*` names are still accepted as
fallbacks; the per-peer name wins when both are set.

| Suffix | Legacy fallback | Meaning |
|---|---|---|
| `WEBHOOK_URL` | `FRIDAY_WEBHOOK_URL` | HTTPS endpoint (port 443, no credentials, not an IP). DNS is resolved and must be public; the socket is pinned to the checked address. |
| `WEBHOOK_SECRET` | `FRIDAY_WEBHOOK_KEY` | Signing secret. With a per-peer secret the default mode is Standard Webhooks and the secret must be `whsec_` + base64 (24–64 bytes). The legacy key defaults to bearer mode. |
| `WEBHOOK_AUTH` | — | `standard-webhooks` or `bearer`. Overrides the default above. |
| `RECEIVER_ID` | `FRIDAY_RECEIVER_ID` | Must equal `BRIDGE_RECEIVER_ID` to attest the receiver is configured for this bridge. |
| `WEBHOOK_CONTRACT_VERIFIED` | `FRIDAY_WEBHOOK_CONTRACT_VERIFIED` | `true` only after the receiver's native run has shown the exact event (see the diagnostic below). |
| `DIAGNOSTIC_FROM` / `DIAGNOSTIC_UNTIL` | `FRIDAY_WEBHOOK_DIAGNOSTIC_FROM` / `_UNTIL` | One-time diagnostic window. |
| `CANARY_MESSAGE_ID`, `CANARY_RETURN_SUBSCRIPTION_ID`, `CANARY_FROM`, `CANARY_UNTIL` | `FRIDAY_CANARY_*` | One stored-message canary. |

Every delivery is one POST with this exact body:

```json
{"event":"bridge.message.received","data":{"messageId":"<uuid>"}}
```

In `standard-webhooks` mode, the request carries `webhook-id` (the delivery's
stable `evt_…` event ID, identical across retries), `webhook-timestamp` and
`webhook-signature` per the [Standard Webhooks](https://www.standardwebhooks.com/)
spec. Verify it with any Standard Webhooks library. In `bearer` mode it carries
`Authorization: Bearer <secret>`. The body never contains message text; the
receiver reads the message through its own authenticated MCP session. The
response body is never read, and a 2xx status is transport evidence only.

## One-time webhook diagnostic

This is a transport-only check of the webhook peer binding while delivery stays
off. It is armed only when the OAuth contract is attested, storage and the
webhook URL/secret are configured, the receiver ID matches, and
`DIAGNOSTIC_FROM`/`DIAGNOSTIC_UNTIL` are ISO timestamps for a window of at most
two hours that contains the present. A missing, reversed or overlong window
stays closed; an overlong window never becomes valid as time passes.

Once the OAuth contract is attested, the events peer with its send scope sees
the diagnostic tool even while it is unarmed. The tool takes no arguments, and
the webhook peer never sees it. Each call checks readiness before touching
storage. The first armed call durably records a spend marker with a fresh UUID
*before* sending, then makes exactly one POST in the configured mode. After
that, concurrent calls, restarts, re-arming, timeouts and lost outcomes return
only the recorded attempt (`duplicate: true`), so a second send needs a code
change. If the window closed between the spend and the send, nothing is sent
and the result is `<prefix>_diagnostic_expired`. Results carry the UUID and a
numeric status or sanitized error, never the URL, secret or response body.
No message is stored, so reading the UUID returns `message_not_found` by design.

HTTP 2xx proves neither wake nor mapping. Only when the receiver's native run
shows that exact event and `data.messageId` should you set
`WEBHOOK_CONTRACT_VERIFIED`. Clear the window afterwards.

## One stored-message canary

The canary is a server-armed exception that lets one fixed events-peer →
webhook-peer source and its server-created ACK use the normal tools, queue and
sender while delivery and the webhook contract are still off. It never sets a
flag. `deliveryEnabled` stays false, and health reports only `canaryArmed`.

It is armed when the OAuth contract is attested, storage, storage key and
webhook URL/secret are configured, the receiver ID matches, normal delivery is
off, and all four canary values are valid:
- `CANARY_MESSAGE_ID`: a fresh lowercase UUID.
- `CANARY_FROM`/`CANARY_UNTIL`: a window of at most 30 minutes containing now.
- `CANARY_RETURN_SUBSCRIPTION_ID`: the events peer's existing active `sub_…`
  subscription.

The only admissible source is a `bridge_message_send` from the events peer to
the webhook peer with `id` and `threadId` both equal to the canary UUID, kind
`status`, route `inbox`, `expiresAt` exactly `CANARY_UNTIL`, and text exactly:

```text
<BRIDGE_SERVICE_NAME> canary: one-time status data only. No action is requested.
```

Anything else returns `<prefix>_canary_only`. All normal JWT, scope, expiry,
denial and validation checks still run first. The first admitted send commits
a durable lifetime reservation before any queue publication. Nothing clears it,
and a different UUID, window, subscription or body returns
`<prefix>_canary_spent`. Source and ACK jobs carry a one-attempt limit, and
timeouts, 5xx results and restarts are never retried. The ACK goes only to the
pinned return subscription.

To run it:
1. Set the four values.
2. The events peer sends the fixed source once.
3. The webhook peer reads, claims and completes it.
4. The events peer reads, claims and completes the ACK.
5. Inspect `bridge_status` for both messages, then clear the values.

The results are server operation evidence only (`wakeVerified: false`).

## Wake/sync delivery classes (default off)

| Variable | Meaning |
|---|---|
| `BRIDGE_WAKE_SYNC_RECIPIENTS` | Comma-separated recipient peer IDs that get WAKE/SYNC routing, e.g. `friday`. Unset or empty: v1 behavior. Any unknown ID disables the whole flag. Read on every call, so clearing it rolls back immediately. |
| `CRON_SECRET` | Flush-route secret (16+ random characters), set in Vercel and, with the same value, as the GitHub Actions secret `CRON_SECRET`. Callers send `Authorization: Bearer <secret>` to `/api/cron`; without it the route answers 503 and SYNC data only leaves on a WAKE or an inbox read. |
| `BRIDGE_CRON_URL` | GitHub Actions repository **variable** (not a Vercel setting): the full HTTPS URL of the deployed `/api/cron` route. |

For an enabled recipient:

- **No ACK wakes.** Completing a receipt still records it exactly as before
  (`bridge_status` shows `receiptCompleted`), but no ACK message or webhook is
  created for that recipient. The events peer then also needs no return
  subscription for its own sends. The completion result says `ackSuppressed: true`.
- **Two classes.** `bridge_message_send` takes optional `class` (`wake` or
  `sync`), `subject`, `effectiveAt` and `dueAt`. A message with no class is
  WAKE, unchanged. SYNC is promoted to WAKE when `effectiveAt` or `dueAt` is at
  or before now + 2 h, and when its `expiresAt` falls at or before the end of
  the next flush window (so queued data can never expire unseen). Only `class: sync`
  may set `expiresAt` up to 12 h after `sentAt`; everything else keeps 1 h.
- **Batching.** Pending SYNC items coalesce per recipient: delta only, and a
  later item with the same `subject` (case and spacing ignored) replaces the
  earlier pending one, as does a WAKE with that subject. The batch is delivered
  once: piggybacked on the next WAKE to that recipient, returned by the
  recipient's next `bridge_read` or `bridge_inbox_read`, or flushed as one
  webhook at the next even America/Chicago hour (00:00, 02:00, … 22:00, run up
  to 30 minutes late). Empty windows send nothing; at most 12 flushes per
  recipient per Chicago day.

A batch is stored as an ordinary v1 `status` message from the counterpart, so
its wake is the unchanged `{"event":"bridge.message.received","data":{"messageId":…}}`
(or the events-peer callback). Its text is a bounded digest that names every
item's messageId; `bridge_read` adds a `syncBatches` array with each item's
full data. Claiming and completing the batch records every item's receipt and
never creates an ACK. Items stay individually readable by ID.

The flush is triggered by the GitHub Actions workflow
`.github/workflows/bridge-cron-flush.yml` (`0 * * * *`, hourly UTC, plus manual
`workflow_dispatch`), which POSTs to `/api/cron` with the bearer secret. It is
not a Vercel cron, because Vercel Hobby only allows daily crons. The workflow
has no permissions, no third-party actions, a 5-minute timeout and a
non-overlapping concurrency group. If the secret or URL is not configured it
logs a notice and succeeds; otherwise any non-2xx response fails the run
(curl retries 3 times with a 30-second limit per attempt).

The route accepts POST and GET. It flushes only when the current time is in
minutes 0–29 after a Chicago even-hour boundary, because scheduled Actions
runs start late; any other run returns `200 {"status":"skipped","reason":"outside_flush_window"}`
without touching storage. Each recipient is flushed at most once per boundary,
so a duplicate run in the same window sends nothing new, and a window missed
entirely waits for the next boundary (or a WAKE or inbox read). On the
spring-forward day the missing 02:00 is flushed at 03:00 CDT; on the fall-back
day (e.g. 1 November 2026) neither 01:00 counts and the 02:00 CST window
flushes. Batches are published to the queue after the flush commits; a failed
publication is re-offered by a repeated run in the same window or by the next
boundary's run.
Queued SYNC items stay deliverable after the sender's access token expires
(a FYI must survive until the next boundary), but a policy change, durable
denial, the item's own `expiresAt` or content retention still withdraws them.

Rollout (in this order; nothing here is set by the repository):

1. Generate one random secret of 16+ characters, e.g. `openssl rand -hex 32`.
2. In Vercel (Production environment), set `CRON_SECRET` to that value and
   redeploy so the function sees it.
3. In GitHub (Settings → Secrets and variables → Actions), add a repository
   secret `CRON_SECRET` with the same value.
4. In the same place, add a repository variable `BRIDGE_CRON_URL` with the full
   HTTPS URL of the deployed flush route, e.g. `https://<your-bridge-host>/api/cron`.
5. Optionally run the "Bridge SYNC flush" workflow by hand (`workflow_dispatch`).
   Outside an even Chicago hour it should succeed with
   `{"status":"skipped","reason":"outside_flush_window"}`; a 401 means the two
   secrets differ, a 503 means the Vercel value is missing or shorter than 16.
6. Update the recipient's receiver to treat `syncBatches` as inbox data (and,
   optionally, call `bridge_inbox_read` at the start of a turn).
7. Set `BRIDGE_WAKE_SYNC_RECIPIENTS=friday` in Vercel and redeploy.

Rollback: clear `BRIDGE_WAKE_SYNC_RECIPIENTS` and redeploy. New SYNC messages
are then delivered as WAKE, ACKs resume, and anything still queued is flushed
at the next even-hour window as a standard message (leave the secrets and the
workflow in place until then).

## Bounded queue recovery

An eligible queue callback that still fails on delivery 18 or later publishes
one successor before acknowledging the old item. The successor keeps the same
work identifier and a stable idempotency key, waits 60 seconds, and carries an
absolute deadline. That deadline is capped at the original item's expiry or one
hour after its creation, whichever is earlier. Workers keep every original
expiry, authorization and attempt limit (five transport attempts). This is
bounded recovery of known backend work, not polling, and not a delivery
guarantee. A long outage can still exhaust the platform's retry budget.

When scheduling right after a send fails, the tool result reports
`scheduling: not_confirmed`; dispatch then comes from the pre-commit
preparation item. A transient `storage_unavailable` during the worker's
pre-send checks keeps the job pending within its budget. Configuration and
decryption failures are terminal.

Permitted tool execution failures return HTTP 200 with `result.isError: true`
and a sanitized error code. Authentication and permission failures keep their
HTTP 401/403 status (401 with the resource-metadata challenge). Callers must
inspect the tool result, not just the HTTP status.

## Bounded operation evidence

The bridge keeps a small amount of sanitized evidence for operators:
- **Subscription renewals:** up to eight recent results per subscription, each
  under 24 hours old. The owner sees them through `bridge_subscription_status`
  together with `inactiveReason`.
- **Diagnostic UUID reads:** after the diagnostic spend, up to eight results of
  reads of its UUID, visible through `bridge_status`.

Each record holds a time, success/error, an allowlisted code and the granted
deadlines. Records never hold tokens, callback URLs, secrets, error messages or
message content. Recording is best effort, and it never extends a lease or
reopens denied access. An optional `maxAgeMs` on `events/subscribe` is accepted
for compatibility with the
[MCP Events draft](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md#cursor-lifecycle);
it has no effect, because replay is unsupported and the cursor stays null.

## Public checks and plugin packaging

`scripts/check_v1.py` makes credential-free requests against a deployment:
health, the per-peer 401 challenge, metadata, cross-origin rejection, an
invalid token, and the absence of the private queue and legacy paths.

```sh
python3 scripts/check_v1.py --origin https://bridge.example.com --peers alice,bob \
  --issuer https://clerk.bridge.example.com --auth-configured
```

`scripts/package_plugin.py` renders the MCP plugin template in `plugin/` for
one peer into the ignored `.reports/` directory. It never uploads or installs
anything:

```sh
python3 scripts/package_plugin.py --origin https://bridge.example.com --peer alice \
  --counterpart bob --issuer https://clerk.bridge.example.com --client-id <public-client-id>
```
