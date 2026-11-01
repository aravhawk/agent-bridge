# Scheduled tick (Upstash QStash)

The bridge needs one external, periodic trigger: `POST /api/cron`. Each run
flushes SYNC batches that are due (America/Chicago even hours, the 2-hour
maximum wait, expiry), re-offers committed but unpublished batches, re-offers
overdue outbox jobs, and reports attachment status. Every run is idempotent:
extra, late or overlapping runs are no-ops or repeat harmless work.

The owner selected **Upstash QStash**. The route stays scheduler-neutral: any
other scheduler can call it with `Authorization: Bearer $CRON_SECRET`. There
is no Vercel cron and no GitHub Actions communication workflow (repository CI
and CodeQL are unrelated and unchanged).

The repository does not create or activate a schedule. Provisioning the
schedule, configuring its destination and signing keys, and accepting its
provider cost are separate operator actions.

## How a signed delivery is verified

QStash signs each delivery with a JWT in the `Upstash-Signature` header
(HS256, keyed by your current signing key; the next key is used during
rotation). The bridge verifies it with the existing `jose` dependency,
following the official receiver (`@upstash/qstash` `Receiver.verify`: current
key, then next key; issuer `Upstash`; `sub` equal to the destination; `body`
equal to the unpadded base64url SHA-256 of the raw body), with stricter rules:

| Check | Rule |
|---|---|
| Method | `POST` only for signed deliveries (`405` otherwise) |
| Body | Raw bytes, at most 1,024 (declared and streamed); must be exactly `{"kind":"bridge.scheduled-tick","v":1}`: static control metadata, never content |
| Algorithm | `HS256` only (no `none`, no other HMAC) |
| Keys | `QSTASH_CURRENT_SIGNING_KEY`, then `QSTASH_NEXT_SIGNING_KEY`; both required; no development keys, no key chosen by any header |
| Destination | `sub` must equal `BRIDGE_QSTASH_DESTINATION_URL` exactly (trusted configuration; the request URL is never used, since a proxy can change it) |
| Claims | `iss`, `sub`, `exp`, `nbf`, `iat`, `jti`, `body` all required; 5 s clock tolerance; lifetime at most 15 minutes; `iat` not in the future; bounded `jti` and `body` formats |
| Body binding | SHA-256 of the raw bytes, compared with `body` (trailing `=` ignored) |
| Withdrawal | After the awaits, the verifying key and destination must still be configured |
| Replay | An accepted `jti` is remembered until its token expires; a replay is `200 {"status":"duplicate_tick"}` and does nothing |
| Storage | Every check above happens before any database access |

`Upstash-Message-Id`, `Upstash-Schedule-Id` and `Upstash-Retried` are
unsigned and are never used for any decision or echoed. QStash's 10-minute
publish deduplication and the `jti` record are not business identity: the
database outbox, receipt leases and source message IDs remain the durable
truth, and every flush, publication and job is idempotent on those IDs.

Responses:

| Status | Meaning | QStash |
|---|---|---|
| `200` | Ran (or nothing due, or a duplicate tick) | done |
| `489` + `Upstash-NonRetryable-Error: true` | Bad signature, destination, body or size for this delivery | not retried (not billed again) |
| `503 scheduler_not_configured` | Keys or destination missing, or withdrawn mid-request | retried (bounded) |
| `503` with `status` `dispatch_pending`, `dispatch_unconfirmed`, `outbox_pending`, `attachment_cleanup_pending`, or `error` `flush_unavailable` | Work committed but not fully published or recorded | retried (bounded); the next tick also retries |
| `408 scheduler_body_timeout` | The 1 KiB body did not arrive within 5 s (cancelled before storage) | retried (bounded) |
| `405` | Wrong method | retried as a failure; a schedule is always POST |

## Proposed schedule (dry run only)

```sh
node scripts/qstash-schedule-plan.ts --dry-run --destination https://<host>/api/cron
```

(`scripts/qstash-schedule-plan.mjs` remains as a compatibility entry point for
the same script.)

prints the exact request and a `curl` template, and never sends anything (the
script has no network code, reads no token or key, and refuses to run without
`--dry-run`). The destination must be exactly
`https://<lowercase DNS name>/api/cron` (letters, digits, `-` and `.` only);
anything else, including hosts a URL parser accepts but a shell would
interpret, is refused, and the `curl` template keeps the destination in its
own single-quoted word so only `$QSTASH_URL` and `$QSTASH_TOKEN` expand. The
plan:

| Setting | Value | Why |
|---|---|---|
| `Upstash-Cron` | `*/5 * * * *` (UTC) | Catch-up within 5 minutes; Chicago boundaries are computed by the bridge |
| `Upstash-Schedule-Id` | `bridge-tick-5m` | Re-creating updates the same schedule |
| `Upstash-Method` | `POST` | |
| Body | `{"kind":"bridge.scheduled-tick","v":1}` | Static control metadata |
| `Upstash-Retries` | `2` | At most 3 attempts per tick |
| `Upstash-Retry-Delay` | `min(60000, pow(2, retried) * 15000)` ms | 15 s, then 30 s: inside the 5-minute interval |
| `Upstash-Timeout` | `60s` | Matches the function's 60 s maximum |
| `Upstash-Label` | `bridge-tick` | Filtering in QStash logs and the DLQ |
| `Upstash-Forward-*` | none | No secret or content is forwarded |

Delivery volume (QStash bills every delivery attempt, including retries; use
the provider's current pricing when estimating cost):

| | Per day | Per 30 days |
|---|---|---|
| Ticks | 288 | 8,640 |
| Worst case, every tick retried twice | 864 | 25,920 |

A failure callback or dead-letter monitoring are not configured by the plan;
QStash's console shows each delivery's status and response.

## Delivery semantics

- **At least once, any order, possibly overlapping.** Concurrent ticks
  serialize on the database lock; each recipient is flushed at most once per
  boundary, so overlap wakes once.
- **Catch-up after missed ticks.** Nothing is collapsed to the latest tick or
  dropped: the first run after an outage flushes every pending item (one batch
  per recipient; only same-subject updates are merged, as designed),
  re-offers every unpublished batch and re-homes stranded batches (32 per
  completion; the rest wait, counted, for the next run). The daily batch-wake
  cap and the receiver policy are not changed by catch-up.
- **Outbox backstop: bounded fairness.** Each run re-offers overdue outbox
  jobs to the native queue: pending jobs more than 10 minutes past due, and
  jobs whose lease has expired (at once). At most 100 per run, least recently
  offered first (a durable per-job rotation), so a larger backlog is worked
  through and every overdue job is offered within ceil(n / 100) runs; within
  a rotation round ACKs go first, then direct messages, then batch
  deliveries. This is fairness, not strict priority: a job offered in an
  earlier round waits behind jobs not yet offered. One job's publication
  failure does not stop the others; it is counted (`outboxFailed`) and makes
  the run a `503`; jobs left for later runs are counted (`outboxDeferred`).
- **No ordering barrier.** Urgent WAKE messages and ACKs go straight to the
  native Vercel queue when sent or completed (normal dispatch); they never
  wait for a tick or queue behind a batch. The tick is only a backstop for
  them.
- **Observability.** Responses carry counts only (`flushed`, `capped`,
  `dispatched`, `dispatchPending`, `outboxRescheduled`, `outboxFailed`,
  `outboxDeferred`, attachment counts),
  plus the Chicago boundary time. No token, key, URL or message content is
  returned or logged.

## Configuration and rollout

1. `QSTASH_CURRENT_SIGNING_KEY` and `QSTASH_NEXT_SIGNING_KEY` come from the
   Upstash integration. Store them as deployment secrets.
2. Set `BRIDGE_QSTASH_DESTINATION_URL` to the exact `https://<host>/api/cron`
   and redeploy.
3. Review the dry-run plan, then create the schedule with it.
4. Check the first deliveries in the QStash console: `200` with
   `"flushed":0` while nothing is queued.

Key rotation: QStash signs with the current key and you keep both keys
configured; after rotating in Upstash, update both values. A delivery signed
with a key that is no longer configured gets `489` (not retried); the next
tick, signed with a configured key, proceeds.

To stop: pause or delete the schedule in Upstash. Clearing
`BRIDGE_QSTASH_DESTINATION_URL` makes every signed delivery `503` (retried,
then failed), so pause the schedule first.

Sources:
[schedules](https://upstash.com/docs/qstash/features/schedules),
[security](https://upstash.com/docs/qstash/features/security),
[verifying signatures](https://upstash.com/docs/qstash/howto/signature),
[receiving](https://upstash.com/docs/qstash/howto/receiving),
[retry](https://upstash.com/docs/qstash/features/retry),
[deduplication](https://upstash.com/docs/qstash/features/deduplication),
[create a schedule API](https://upstash.com/docs/qstash/api-reference/schedules/create-a-schedule),
[pricing](https://upstash.com/pricing/qstash),
official receiver source `upstash/qstash-js` `src/receiver.ts`.
