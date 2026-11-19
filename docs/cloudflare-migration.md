# Cloudflare state migration

This candidate keeps the existing Vercel public origin, OAuth provider, peer IDs,
protocol, Queue SDK and private Blob store. It moves the **runtime and its
synchronous state transitions**, not just the JSON document, into one SQLite-backed
Durable Object. Production defaults to Postgres. The Cloudflare backend is
available for explicit selection after qualification and state handoff.

## Architecture and local checks

`createCloudflareFrontend` forwards an HTTP command to an authenticated thin Worker.
The Worker streams to one `bridge-runtime-v1` object. The object verifies the original
OAuth/QStash request with the existing runtime, then executes the existing bridge,
receipt, task, attachment-metadata and outbox transitions against `SQLiteStore`.
No transaction callback or full state document is sent to Vercel. The SQLite row
holds the complete version-1 document, monotonic revision and writer fence.
`transactionSync` commits the document and revision together; thrown or asynchronous
transitions roll back. The existing 4 MiB document cap stays in force.

The object's closed effect adapter calls `createEffectHandler` in Vercel for queue
publication, validated public webhook POSTs, and Blob presign/HEAD operations. The
existing DNS/TLS transport and Blob SDK execute there under their existing platform
identity. Object bytes remain direct-to/from Blob. There is no delete/abort/lifecycle
operation in the effect protocol. Queue callbacks must go through the official
Vercel SDK first, then `frontend.consume`; never expose a public raw queue endpoint.
QStash remains the signed five-minute recovery source; no alarms or timers replace it.

```sh
npm ci --ignore-scripts
npm run typecheck
npm run typecheck:cloudflare
npm run compile:check
npm run build:cloudflare
npm test
npm run profile:cloudflare
npm audit --audit-level=moderate
```

Tests run an actual local workerd/SQLite object with synthetic identities, intercepted
network effects and no account login. They test restart persistence, current OAuth
and signed tick verification, scheduled batches, immediate WAKE, receipt claims,
terminal ACKs, duplicate callbacks/completions, attachment metadata/Range capabilities
and task-command replay. They also compare SQLite/reference-store outcomes, check
capacity/poison inputs and rehearse frozen transfer/rollback between two local SQLite
databases. A fake Blob SDK tests adapter placement; it is not real Blob qualification.

The pinned Miniflare **5 beta** is a development-only dependency because the latest
stable package's dependency graph had advisories. The build uses its supported v4
options converter. Before release, confirm a supported stable toolchain (or explicitly
accept the beta) and run the candidate CI on Linux. Node 24.22.3 is the minimum.
The Worker build substitutes a fail-closed pg stub; no Postgres TCP fallback exists.
A narrow native DurableObject/Fetch type declaration covers the workerd host boundary.

## Deployment configuration

`wrangler.jsonc` is the base Worker configuration; it does not enable a public
Worker URL by default. Three distinct 256-bit hex secrets are needed:
`GATEWAY_KEY` (Vercel to Worker), `EFFECT_KEY` (object to Vercel), `MIGRATION_KEY`
(operator-only import/freeze/activation). No production credentials were created or
placed during this prototype. Do not put these values in arguments, source or logs.

`RUNTIME_ENV` is a secret binding containing only the runtime's required trusted
configuration. Moving the existing subscription AES key, QStash verification keys and
legacy peer webhook credential into Cloudflare would be **new secret placement** and needs explicit approval.
Do not copy database URLs, provider API tokens or Blob credentials. Blob OIDC stays
in Vercel. Preserve the exact AES key: transfer checks its SHA-256 identity, and old
callback ciphertext must still decrypt with its original subscription-ID AAD.

`STORE_IDENTITY` must uniquely identify the one physical target, including the
account/namespace and object name. Never reuse it for another namespace or clone an
active store. `EFFECT_ENDPOINT` is the exact HTTPS `/api/bridge-effects` endpoint
on Vercel. The route exists only when Cloudflare is the selected backend and
requires its own effects key. Public identity settings
at Worker startup must match `RUNTIME_ENV`; custom origins fail closed on mismatch.
No OAuth audience, scope, protocol, callback, queue topic or receiver policy changes
are part of this migration.

Vercel reads these settings at deployment:

| Setting | Behavior |
| --- | --- |
| `BRIDGE_STATE_BACKEND` | Unset or `postgres` uses the existing database; `paused` stops API, cron and queue operations; `cloudflare` routes all three to the selected Worker. Unknown values fail closed. |
| `BRIDGE_CLOUDFLARE_ORIGIN` | Exact HTTPS origin of the selected Worker, without a path or trailing slash. |
| `BRIDGE_CLOUDFLARE_GATEWAY_KEY` | Same secret as Worker `GATEWAY_KEY`. |
| `BRIDGE_CLOUDFLARE_EFFECT_KEY` | Same secret as Worker `EFFECT_KEY`. The Vercel effects route returns 404 until the Cloudflare backend is selected. |

The API and cron forward the original request under the gateway key. The queue
consumer remains behind the official Vercel SDK and sends one authenticated
callback per attempt to Cloudflare. An unavailable Cloudflare backend never
causes a fallback to Postgres. Promote a paused deployment and wait out old
invocations before the database fence; promotion alone does not prove a drain.

For a fresh, isolated Worker named `agent-bridge-cf-qualification`, use only
synthetic keys and no live effects destination. With a private JSON file
containing its `GATEWAY_KEY`, `MIGRATION_KEY`, and `RUNTIME_ENV`, run:

```sh
node scripts/qualify-cloudflare-remote.ts https://agent-bridge-cf-qualification.<subdomain>.workers.dev <private-secrets-json>
```

The pilot rejects an invalid gateway or origin, exercises a checksum-validated
synthetic transfer through dormant, frozen, active, and exported states, and
checks repeat import and export. It leaves the pilot exported. It does not
exercise a real peer, signed scheduler, Vercel Queue, or Blob transfer.

## Single-writer cutover rehearsal and runbook

No production export is authorized by implementing this protocol. A transfer contains
all message/receipt/job/task/attachment/denial/tombstone data and encrypted subscriptions;
it must be kept private and never logged. `bridge-transfer/1` binds exact document
bytes, revision, source epoch, target identity, AES-key identity and handoff UUID with
a SHA-256 checksum. The checksum detects corruption; authenticated operator access
supplies authority. The control-body limit allows JSON escaping of a full 4 MiB document.

1. Check current Neon **compute and transfer quotas separately** and establish outage
   headroom. The reported 80.2/100 CU-hours is historical, not a fresh measurement.
   Do not trigger an untested migration to escape a quota warning. Keep rollback
   capacity available and rehearse with synthetic data first.
2. With separate deployment approval, apply `cloudflare/authority-schema.sql` and
   explicitly initialize its single authority row with the physical Postgres identity,
   epoch and existing key fingerprint. Stage **every** Vercel writer on
   `FencedPostgresStore` through constructor injection; the default PostgresStore does
   not consult this fence. Drain/retire all older deployments and in-flight functions.
   Do not advance if any old queue consumer, cron deployment or writer can bypass it.
3. Quiesce new requests, queue consumers and scheduler entry while preserving durable
   pending jobs. Wait for active receipt/job leases and provider requests to drain.
   Record the revision, freeze/export under the same row lock, and confirm the old
   writer is `exported` and rejects transactions. The freeze refuses active leases.
   If the response is lost, retrying the same revision/target returns the same
   persisted handoff and export; changing the target is rejected.
4. Import into the designated dormant object. Check checksum, AES fingerprint,
   revision and full per-section counts; keep it `frozen`. A byte-identical repeated
   import is safe after a lost response. No effects run during import.
5. Only after source fencing is verified, activate using that transfer's handoff and
   revision. Activation advances revision once. If its response is lost, reconcile
   status before another action. Switch the single Vercel frontend/queue target;
   restore scheduler/consumer entry and verify bounded synthetic behavior. Preserve
   existing QStash recovery and all queued IDs; never reset accepted transport evidence.
6. Reverse rollback: quiesce/drain again, freeze the object, transfer its **newest**
   complete state to the exported Postgres source, verify, activate Postgres at the
   newer revision, then redirect the one frontend/queue target. Confirm the object
   stays exported. Never reactivate a pre-cutover Postgres snapshot or independently
   replay the same queue against two active stores.

An exported source cannot simply be unfrozen. Abort after export requires the
forward/reverse handoff with the designated target. Emergency rollback while the
other backend/control plane is unavailable is **not implemented**; solve or explicitly
accept that availability constraint before cutover. Privileged manual database edits
or duplicating a namespace are outside the protocol's single-writer guarantee.

## Local PostgreSQL qualification and remaining gates

`scripts/qualify-cloudflare-postgres.ts <owned-task-root>` is an explicit local-only
qualification driver. It requires a checksum-verified PostgreSQL 17.12 build marker,
0700 socket directory and an already-started synthetic socket-only cluster. It never
reads DATABASE_URL. The driver creates a fresh synthetic database, applies the exact
schemas and uses pinned pg with two pools plus actual local workerd. It checks durable
server settings, concurrency, rollback, legacy-writer races, active claims, ambiguous
commit replies, both handoff directions, lost import/activation replies, state/key
preservation, JSONB capacity and server restart. It is separate from the ordinary
offline test glob; local pg sockets do not qualify Neon public TLS or cloud APIs.

The database UPDATE trigger now enforces the authority mode even for legacy
PostgresStore updates. Both adapters lock document then authority. Reverse import
holds both locks and changes authority temporarily inside its transaction to satisfy
the trigger, then commits frozen; no intermediate active state is visible to another
writer. This protects ordinary application writes, not a database owner who disables
the trigger or directly edits authority. Retiring old deployments and controlled
migration-operator access remain deployment gates.

`handoff` is a private, constructor-assembled operator coordinator, not a public
endpoint. It previews an active source without exporting an importable handoff,
checks destination capacity before freeze, then freezes at the exact preview revision.
A concurrent write causes a revision conflict. Frozen exports are immutable/retryable.
It replays an ambiguous import and reconciles activation by durable handoff identity,
epoch and revision; it never reactivates the old source on target failure. Status and
inspect contain private metadata/state and require the migration authorization path.
No coordinator is mounted remotely. Operator phase evidence and private transfer
transport still need remote wiring/review.

The PG destination measures its actual JSONB text size before reverse transfer;
SQLite-to-SQLite rehearsal alone does not qualify that constraint. Every module's
state and pending job evidence is copied without resetting identities or revisions.
Receipt/job lease checks are not a global in-flight barrier: the operator must drain
old functions, subscription challenges, attachment HEAD/signing operations and
reconcile task-host external executions. A rejected late storage write cannot cancel
an external request already accepted. No exactly-once external execution is claimed.

Emergency rollback while the target/control plane is unavailable remains fail-closed.
There is no safe timeout after which the old snapshot can be reactivated. A stronger
failover guarantee would need a separately designed shared authority enforced by every
writer/effect and partition tests. Production secret placement, real Queue/Blob
behavior, cloud CPU/duration, Linux CI, and a deployed frontend rehearsal
remain separately gated. Neither qualification command exports production data
or performs a cutover.

## Free-tier constraints

Cloudflare documents [8 MB SQLite rows](https://developers.cloudflare.com/durable-objects/platform/limits/)
and 10 GB per object, with [5 GB total free storage](https://developers.cloudflare.com/durable-objects/platform/pricing/).
The account-wide free allowances currently include 100,000 DO requests/day,
13,000 GB-s/day, 5 million rows read/day and 100,000 rows written/day. At five
transactions per five-minute tick, the idle baseline is about 1,440 document writes/day,
plus user activity and recovery. Full-document rewrites stay local to SQLite, but
still consume CPU and row writes. Network waits/effects can keep an object active;
measure duration usage, not just its document size.

The [thin Worker has 10 ms CPU/request on Free](https://developers.cloudflare.com/workers/platform/limits/).
`profile:cloudflare` reports a local Node CPU proxy at 84,540 B, 1 MiB and 4 MiB;
it does not certify Cloudflare billed CPU, network latency or free-plan availability.
Use a bounded cloud qualification before cutover. Existing Vercel/Blob/QStash costs
continue; no paid plan or hard billing cap is configured by this prototype.
