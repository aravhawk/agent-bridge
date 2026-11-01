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
| `BRIDGE_SERVICE_NAME` | `Agent Inbox Bridge` | Display label in `/`, `/health`, OAuth resource metadata and the armed canary text (1-64 printable ASCII characters). It does not rename MCP server identity, peers, routes, audiences, scopes, receiver IDs or protocol IDs. Read at startup; changing it requires a new deployment/function instance. |
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
They may set `BRIDGE_SERVICE_NAME` to their own display label. Leaving it unset
uses `Agent Inbox Bridge` in generic mode; compatibility mode deliberately keeps
`Jarvis Friday Bridge`, so the original deployment needs no new variable.

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

`bridge_health` reports each gate under `readiness`. The v1 runtime, with batching
and attachments off, retains the legacy catalog: the events peer sees seven tools
(eight with the send scope after attestation, including the diagnostic), and the
webhook peer sees six. The public API entrypoint separately attempts to add three
`bridge_task_*` tools on a fresh instance when ordinary OAuth and delivery
readiness are open; a `task_*` construction error selects a sticky v1-only
fallback. See [the task runtime contract](task-activation.md). Batching adds
`bridge_inbox_read` for each enabled recipient and reports `readiness.wakeSync`.
Setting the [private attachments](attachments.md) flag reports
`readiness.attachments`; only a valid enabled configuration adds the attachment
tools.

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
| `BRIDGE_WAKE_SYNC_RECIPIENTS` | Comma-separated recipient peer IDs that get WAKE/SYNC routing, e.g. `bob` for the generic quickstart. Unset or empty: v1 behavior. A valid configuration rolls back queued recipients omitted from the list. Any ID not present in `BRIDGE_PEERS` makes the whole value invalid: ordinary traffic stays on the v1 path, while scheduled flushes fail closed and preserve queued data. Read on every call. |
| `QSTASH_CURRENT_SIGNING_KEY` / `QSTASH_NEXT_SIGNING_KEY` | QStash signing keys (from the Upstash integration). A delivery carrying `Upstash-Signature` must verify against one of them; see [scheduler](scheduler.md). Never returned or logged. |
| `BRIDGE_QSTASH_DESTINATION_URL` | The exact public URL the QStash schedule targets, `https://<host>/api/cron` (no port, query or trailing slash). Signed deliveries must name it as their subject; it is never taken from the request. Unset: every signed delivery is refused (`503`). |
| `CRON_SECRET` | Optional bearer secret (16+ random characters) for any other scheduler: `Authorization: Bearer <secret>` to `/api/cron`. |

Without a configured scheduler, SYNC data only leaves on a WAKE or an inbox
read, and overdue outbox work is not re-offered.

With the flag unset nothing below applies: every wake names the native
message ID, ACKs are created, and no tool, field or state is added.

For an enabled recipient:

- **ACKs as in v1, per handled source.** Completing a handled direct
  message creates its correlated ACK immediately (never at send or enqueue
  time, never batched). Completing a handled non-empty batch creates exactly
  one ACK correlated to the batch, covering all its items (an item's status
  shows `batchAckMessageId`, not an ACK of its own). Completing a WAKE that
  carried batches creates the WAKE's ACK plus a separate ACK for each named
  batch the claim holds (`syncBatchAcks`); an omitted, unheld or withdrawn
  batch gets none and stays outstanding. ACKs are terminal: completing one
  creates nothing, and reading or claiming one never collects SYNC data. An
  ACK means the receiver handled the received data, not that a requested
  task is done or that a host independently verified anything. Every ACK is
  pre-armed on the native queue before the completion commits, and a retry
  after a lost response returns the recorded ACK IDs without creating more.
- **Return path.** A real message keeps the v1 rule (an events-peer sender
  needs a return subscription covering the message's authority). A batch's
  12-hour authority is synthetic, so its ACK instead needs an active return
  subscription of the batch's owner for at least 5 minutes past the claim
  lease (or until the batch expires); the batch ACK lives until the earliest
  of 1 hour, the batch's expiry, that subscription and the completing token.
  Each attached batch is also checked against its own current authority
  (policy, durable denial, expiry) at claim and again at completion.
- **Two classes.** `bridge_message_send` takes optional `class` (`wake` or
  `sync`), `subject`, `effectiveAt` and `dueAt`. A message with no class is
  WAKE, unchanged. SYNC is only for dependency-free, nonblocking routine FYI;
  any action, decision, blocker, awaited reply, workflow dependency or
  uncertainty is WAKE, and `handoff_request` always routes WAKE even if
  mislabeled SYNC. SYNC is promoted to WAKE when its `effectiveAt`, `dueAt` or
  `expiresAt` is at or before now + 2 h 30 min: the 2-hour maximum wait plus
  30 minutes of scheduler slack. That margin covers a trigger run that is
  somewhat late; it does not make on-time delivery certain if the scheduled
  trigger is delayed further or skipped (see
  [pre-rollout requirements](#pre-rollout-requirements)). This time check is a
  safety floor, not proof arbitrary text is safe to delay. Only
  `class: sync` may set `expiresAt` up to 12 h after `sentAt`; everything else
  keeps 1 h.
- **Batching.** Pending SYNC items coalesce per recipient: delta only, and a
  later item with the same `subject` (case and spacing ignored) replaces the
  earlier pending one, as does a WAKE with that subject. Pending data is cut
  into one batch when it is piggybacked on the next WAKE to that recipient,
  returned by the recipient's next `bridge_read` (of a message it has not yet
  completed) or `bridge_inbox_read`, or flushed as one webhook (below).
- **Acknowledgement and replay.** A batch stays outstanding until it is
  acknowledged, and `bridge_inbox_read` returns every outstanding batch on
  every call, so a lost response or a crash loses nothing and concurrent reads
  return the same batches (reads serialize on the store lock and never cut
  twice). Each batch has one claim record shared by both ways of handling it,
  so only one claim at a time may hold it: claiming a message also holds its
  presented, unacknowledged attached batches unless another live claim holds
  them (the claim result lists `syncBatchIds` and `syncBatchesHeldElsewhere`),
  and a direct claim of a batch held that way fails with `receipt_busy`, and
  vice versa. A batch is acknowledged either directly, by claiming and
  completing its own `messageId` (its own ID may be named in `syncBatchIds`
  and is implied if omitted), or with the message it was attached to, by
  naming it in that message's `syncBatchIds` while that message's claim holds
  it. Acknowledgement is bound to the IDs the completing receiver names from
  its own read and to its own claim, so a batch shown to a different reader,
  or held by another claim, is never acknowledged on its behalf, and no
  completion overwrites a receipt another claim holds. Completion is refused
  with `sync_batch_not_presented` for a named batch that was not presented
  with that message (or a batch whose full items were never returned by a
  read), and with `sync_batch_not_held` for a named batch the claim does not
  hold. Unnamed held batches are released at completion and stay outstanding.
  Only an acknowledged batch marks its items handled.
  A batch still unacknowledged after 12 hours is retired and its unhandled
  items are queued again.
- **Carrier fallback.** A batch piggybacked on a WAKE has no delivery of its
  own. If that carrier can no longer get it read before the batch is
  presented (the carrier's authority lapsed or was withdrawn, all its delivery
  jobs died, it was completed without the batch, or it stayed unread for the
  2-hour wait), the batch counts as due data for the flush: at the next due
  run it rides the flush batch as an attached batch, or, with nothing else
  due, is delivered on its own. It keeps its ID and its single claim record
  (the old carrier and the new one share that fence), costs the same one wake
  and one daily-cap slot as any flush, and is re-homed only once, so repeated
  or concurrent runs re-offer the same publication. A batch already read
  through its carrier, or held by that carrier's claim, is never re-homed.
  Capped or destination-less runs leave it waiting; with the flag off it is
  delivered on the next run. `bridge_status` on the batch shows `rehomedTo`.
  A carrier takes at most what one completion can acknowledge: 32
  `syncBatchIds`, its own ID included, so at most 31 attached batches; the
  rest stay stranded with unchanged IDs and go out, oldest first, at the next
  due run (another wake and cap slot). For the same reason a read stops
  collecting new pending data into a message once its open attached batches
  reach that limit, and a claim holds at most that many, reporting any older
  excess as `syncBatchesDeferred`.
- **Nothing is silently dropped.** Items whose own `expiresAt` passes while
  queued or re-queued are still delivered, flagged `expired` and `late`.
  Pending items, items in unacknowledged batches and items re-sent natively
  after a rollback but not yet completed are held past the 24-hour content
  retention (up to 6 days, within the 100-message capacity). Only a policy
  change or a durable access denial withdraws queued data (`bridge_status`
  then shows `sync.state: "withdrawn"`). When items are re-queued (an expired,
  unacknowledged batch, or a failed native re-send), the newest update per
  `subject` wins, by admission order: acceptance time, then a durable admission
  sequence stored on each message in the same transaction (so two updates
  accepted in the same millisecond, including a WAKE with that subject, still
  have a strict order). Only these stored numbers are compared, never object
  key order, which the database does not preserve. An older update is marked
  superseded and never replaces a newer one. Same-millisecond updates stored
  before the sequence existed have no recorded order, and their true order
  cannot be reconstructed: the bridge then supersedes neither and delivers
  each again with `orderUnknown: true`, rather than guessing and discarding
  what may be the newest.
- **One fence per item.** A queued or batch-carried SYNC item is handled only
  through its batch: claiming the item itself is refused with
  `sync_item_in_batch` (plus `batchMessageId`), `sync_item_not_delivered` or
  `sync_item_superseded`, so an item can never be held by a claim the batch does
  not see. A batch whose item still has a live claim from before this rule is
  refused (`sync_batch_item_busy`, with `itemIds`) for both claim and
  completion, stays outstanding, and is acknowledged only once every item is
  covered. Natively re-sent rollback items keep the v1 claim path.

A batch is stored as an ordinary v1 `status` message from the counterpart, so
its wake is the unchanged `{"event":"bridge.message.received","data":{"messageId":…}}`
(or the events-peer callback). Its text is a bounded digest that names every
item's messageId; `bridge_read` adds a `syncBatches` array with each item's
full data. The exact receiver contract is in
[inbox policy](inbox-policy.md#flagged-receiver-contract).

### Flush schedule and the 2-hour maximum

The flush is driven by an external scheduled tick to `/api/cron`. The
selected scheduler is Upstash QStash: a 5-minute schedule whose signed POST
carries only static control metadata (see [scheduler](scheduler.md) for
verification, the reviewed dry-run plan, retries and cost). Any other
scheduler may call the route with the `CRON_SECRET` bearer (GET or POST).
There is no Vercel cron and no GitHub Actions communication workflow.
Every check on a request (signature, destination, body, method, size, keys)
happens before any storage access.

Every run checks each enabled recipient with pending SYNC data and flushes
one batch when:

1. **scheduled** - an America/Chicago even hour (00:00, 02:00, … 22:00) has
   passed since its last flush and items were queued before it. A run that
   starts late, or the run after a skipped one, still delivers;
2. **max_wait** - waiting until the next top of the hour would push the oldest pending
   item past 2 hours of elapsed time since it was queued; or
3. **expiring** - an item expires before the next run (plus slack), or already
   has (re-queued data).

Otherwise the run is a `200` no-op (`flushed: 0`) and empty queues send
nothing. These rules meet the 2-hour requirement only while scheduled runs
happen; a scheduler outage delays delivery past it (see
[pre-rollout requirements](#pre-rollout-requirements)). Each recipient is flushed at most once per boundary, so duplicate
runs send nothing new. The maximum is elapsed time, not wall-clock hours: on
the fall-back day (e.g. 1 November 2026) 00:00 CDT to 02:00 CST is three real
hours, so data queued after midnight is flushed by the 01:00 CST run instead;
on the spring-forward day (e.g. 8 March 2026) the nonexistent 02:00 is flushed
at 03:00 CDT. The daily cap is `ceil(hours in the Chicago day / 2)`: 12 batch
wakes normally and on the 23-hour spring-forward day, 13 on the 25-hour
fall-back day, which can need one more to keep every item within 2 hours
when runs are on time. A
capped recipient's items stay pending (held, delivered with the next WAKE,
inbox read or the next day's first run). Batches are published to the queue
after the flush commits, and a run reports `200` only when everything due is
published and recorded as published. Otherwise it answers `503`, so the
scheduler retries (bounded) and the next tick tries again:

- `{"error":"flush_unavailable"}`: the flush commit failed or could not be
  confirmed (a commit can succeed on the server and its response still be
  lost). No publication was attempted by this call; a retry discovers any
  batches that were committed and publishes them, without re-cutting them or
  counting them again against the daily cap.
- `"status":"dispatch_pending"`: some committed batches (or native rollback
  re-sends) could not be published; `dispatched` counts those that were,
  `dispatchPending` those still waiting.
- `"status":"dispatch_unconfirmed"`: publication happened but recording it
  failed or could not be confirmed; any IDs not recorded are offered again
  (publishing again is harmless, see below).

- `"status":"outbox_pending"`: overdue outbox work could not be re-offered
  to the queue this run.

**Catch-up after missed ticks.** Nothing is collapsed to the latest tick or
silently dropped: the first run after an outage flushes every pending item
(one batch per recipient, deduplicated only by subject as designed),
re-offers every committed but unpublished batch, re-homes stranded batches
(32 per completion; the overflow waits for the next run, unchanged and
counted), and re-offers overdue outbox jobs (WAKE, ACK or batch delivery):
pending more than 10 minutes past due, or with an expired lease, at most 100
per run in durable rotation (least recently offered first; within a round
ACKs, then direct messages, then batches), so every overdue job is offered
within ceil(n / 100) runs (`outboxRescheduled`, `outboxDeferred`; a failed
publication is isolated, counted in `outboxFailed` and makes the run a
`503 outbox_pending`). This is bounded fairness, not strict priority. The
daily cap and the receiver policy are not changed by catch-up: a capped
recipient's data waits for the next day or the next WAKE or inbox read.
Immediate WAKE and ACK delivery never waits for a tick (normal dispatch uses
the native queue directly and is not ordered behind batches).

Committed batches are never lost or re-cut: a retry, or the next run,
publishes exactly the IDs still waiting, without using another daily-cap
slot. Publishing an already-published batch again is harmless, because
dispatch runs each job's idempotent worker and an accepted job is not sent
again. A persistent queue outage still delays delivery until the queue
recovers, which is part of the scheduling limitation (see
[pre-rollout requirements](#pre-rollout-requirements)).
Queued SYNC items stay deliverable after the sender's access token expires
(a FYI must survive until it is flushed), but a policy change or durable
denial still withdraws them.

### Pre-rollout requirements

The implementation does not settle the following. Resolve them before setting
`BRIDGE_WAKE_SYNC_RECIPIENTS` for a recipient:

- **Sender classification must not affect workflow.** Enable batching only
  after every sender uses SYNC solely for dependency-free, nonblocking FYI and
  treats uncertainty as WAKE. Arbitrary text cannot reliably reveal every
  dependency; the server only forces the known workflow kind
  `handoff_request` to WAKE and applies the time-field safety floor. Inbox reads
  or late-item recovery do not make workflow-dependent content safe to delay.

- **The 2-hour maximum is a requirement, not yet a proven guarantee.** The
  requested rule is delivery of SYNC data no more than 2 elapsed hours after it
  was queued. The bridge flushes on that basis at every scheduled run; with
  the selected QStash 5-minute schedule (at-least-once, bounded retries) that
  holds while QStash and the queue are available, but an outage of either
  still delays delivery, so it is not a proven guarantee. The schedule is
  a separately configured operator action (see [scheduler](scheduler.md)). The
  30-minute slack in SYNC promotion only covers modest lateness.
- **Receiver policy exceptions are required and not adopted here.** The
  [flagged receiver contract](inbox-policy.md#flagged-receiver-contract)
  needs the receiver to (1) handle SYNC batches and their items, (2) call
  `bridge_inbox_read` at the start of a turn, which departs from the current
  no-polling rule, and (3) accept and report expired or `late` items, which
  departs from the current rule to reject expired content. Each needs an
  explicit operator policy decision before rollout. This
  documentation describes the contract; it does not adopt those exceptions or
  change any receiver policy.

### Rollout and rollback

Rollout (in this order; nothing here is set by the repository; do not start
until the pre-rollout requirements above are resolved):

1. In Vercel (Production), set `BRIDGE_QSTASH_DESTINATION_URL` to the exact
   `https://<your-bridge-host>/api/cron` next to the existing QStash signing
   keys, and redeploy.
2. Review and create the 5-minute schedule from
   `node scripts/qstash-schedule-plan.mjs --dry-run --destination <url>`.
   The first ticks should answer `"status":"ok"` with `"flushed":0`;
   `503 scheduler_not_configured` means a key or the destination is missing,
   `489` means a signature, destination or body mismatch (not retried).
3. Update the recipient's receiver to follow the
   [flagged receiver contract](inbox-policy.md#flagged-receiver-contract).
4. Set `BRIDGE_WAKE_SYNC_RECIPIENTS=bob` in Vercel and redeploy.

Rollback (drain first, then switch; in this order):

1. Ask senders to stop sending `class: sync` to the recipient. Unclassified
   and `wake` messages are delivered immediately as before.
2. **Drain while the flag and the flagged receiver are still in place.** Have
   the recipient call `bridge_inbox_read` and, for every returned batch,
   claim it, handle its items and complete it, repeating until a call returns
   `"syncBatches": []`. Each call cuts any pending SYNC data into a batch and
   replays every unacknowledged one, so an empty result means nothing is
   queued or outstanding.
3. Clear `BRIDGE_WAKE_SYNC_RECIPIENTS` and redeploy. New SYNC messages are then
   delivered as WAKE (ACKs are unchanged either way).
4. Only now switch the recipient back to an old-format or legacy-only
   receiver.

Safety net for anything queued after the drain: on the next scheduled run it is
re-sent under its own message ID where its original v1 authority is still
valid (an unchanged receiver handles it like any message, ACK included); the
rest goes out once as a standard `status` batch whose text lists each item's
message ID. A natively re-sent item that is not completed before its v1
authority lapses, or whose native delivery jobs all die, is recovered on a
later run into such a batch (never re-sent natively again) instead of being
stranded. Keep the schedule and its configuration in place until that run
has happened.

## Private attachments (default off)

| Variable | Meaning |
|---|---|
| `BRIDGE_ATTACHMENTS_ENABLED` | `true` enables private temporary file transfer; anything else (or unset) keeps it off, with no tools, state, provider calls or reads of the settings below. Read on every call. |
| `BRIDGE_ATTACHMENT_MAX_BYTES` | Optional per-file maximum in decimal bytes, `500000000` (default) to `1000000000` (hard cap). Digits only; anything else disables the capability (fail closed). |
| `BLOB_STORE_ID` | Vercel Blob store connected to the project (`store_<id>` or `<id>`). It is an identifier, not a credential. The intended server-side path is the deployment's ordinary Vercel OIDC, and this bridge does not configure or pass a static token. `@vercel/blob` 2.8.2 can read `BLOB_READ_WRITE_TOKEN` as a fallback when OIDC is unavailable; do not configure or rely on that fallback here. Deployment OIDC permission is not live-qualified by local tests. Changing the store makes existing attachments fail closed. |

`bridge_health` adds `readiness.attachments` (`enabled`, `configured`
booleans) once the flag is set. Nothing is ever physically deleted by the
bridge unless a trusted, owner-approved retention policy is supplied to the
runtime constructor (no setting enables it); expired records keep their
metadata and reserved quota. Design, limits, resume, retention, private Blob
behavior and the setup checklist: [attachments](attachments.md).

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
anything. Its `jarvis`/`friday` defaults exist only for compatibility; generic
deployments must pass the actual `--peer` and `--counterpart` from
`BRIDGE_PEERS` explicitly:

```sh
python3 scripts/package_plugin.py --origin https://bridge.example.com --peer alice \
  --counterpart bob --issuer https://clerk.bridge.example.com --client-id <public-client-id>
```
