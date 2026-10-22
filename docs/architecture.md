# Active bridge architecture

This service is a resource server and a bounded durable outbox, not an OAuth
client or assistant runtime. Clerk issues and refreshes tokens; each native
host owns its task, connection and subscription refresh. The server must handle
valid refresh requests correctly without assuming a particular host schedule.
Normal delivery and the one-shot diagnostic remain disabled in production.

## Boundaries and state transitions

| Boundary | Owns | Must not claim |
|---|---|---|
| Canonical resource router + JWT verifier | Fixed role/audience/issuer/subject/scopes; hard request expiry | That foreground health proves background refresh |
| MCP adapter | Discovery, method/argument handling, sanitized tool results | That HTTP200 means the tool succeeded |
| Subscription state | Canonical identity, callback proof, finite TTL and authorization ceiling | That OAuth itself requires the local lease policy |
| Message/receipt transactions | Stored content, deterministic jobs, claim fencing and atomic completion/ACK | Exactly-once hosted external actions |
| Queue adapter + worker | Native dispatch, bounded retries, current admission and durable result fencing | Infinite recovery or native wake from HTTP acceptance |
| Fixed Friday adapter | Exact configured destination and wire shape | Verified receiver context from a saved credential |

The single Postgres row serializes message/outbox/receipt mutations for this
bounded personal workload. Callback secrets are encrypted with subscription-ID
AAD. There is no in-memory production fallback. A normalized multi-table schema
or new orchestration service is not needed to fix the reproduced lifecycle
defects; either would require a separate migration and validation effort.

## Three separate clocks

1. **Request token expiry.** Invalid/expired bearer tokens are rejected before a
   principal exists, with401 and the existing protected-resource challenge.
2. **Subscription TTL.** A successful subscribe grants
   `min(request_start + requested_TTL, verified_token_expiry)` (bounded defaults
   apply). Every request can re-grant a shorter TTL, even with the same valid
   token after a lapse; it cannot extend beyond that token's expiry. Existing
   denial/unsubscribe state and verification/commit races remain fenced. A token
   with an earlier expiry than stored authority remains rejected by current
   policy. A grant already at token expiry needs later verified authority.
3. **Message and claim lifetime.** Messages keep their existing immutable source
   authority ceiling, payload expiry and retention limits. A claim has a60-second
   lease; expired claims cannot complete. These are explicit local controls, not
   implied OAuth requirements. Slow hosted handling can lose the completion
   opportunity; this release does not silently relax that constraint.

The documented [host event contract](https://developers.openai.com/plugins/build/mcp-events)
uses server/discover for2.0 events, deterministic principal/callback/event/argument
identity, callback verification, signed event deliveries, finite refreshBefore
and null cursors for this non-replay source. The experimental draft is a separate
reference; unsupported streaming/control notifications are not implemented.

## Source through terminal ACK

Send validates the fixed route/scopes/lifetime and checks the return subscription
where required. It reserves native cleanup/dispatch work before content commits;
an early callback waits briefly for the commit, and an absent commit never wakes
the receiver. The final transaction rechecks authority and inserts content plus
deterministic outbox jobs atomically. Immediate job scheduling is an optimization;
if it fails the response says scheduling is unconfirmed. No reconciler daemon
is implied.

The worker leases one job, rechecks current message/subscription authority around
asynchronous admission, sends through the fixed adapter, then fences its result
against lease loss, revocation and expiry. It retries transport transients and
temporary storage failures under the existing five-attempt cap. A failed access
check never permits transport. Storage configuration, decryption and destination
rejection require repair. Native queue continuation is bounded independently;
it cannot extend message authority or replay an accepted/one-shot transport.

Recipient read/claim/complete is authenticated separately. Completion creates one
correlated ACK and marks the receipt complete in the same transaction; the ACK's
completion is terminal. Peer text remains untrusted data and never authorizes
unrelated tools/actions. The recipient's claimed external effects are not an
atomic transaction with this database. After a timeout, duplicate event delivery
or a reclaimed claim can repeat hosted handling; consumers must respect the
policy and actual current claim.

## Error and recovery semantics

The [MCP tool error contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#error-handling)
distinguishes protocol failures from tool execution failures. Known permitted
tools return sanitized validation/conflict/backend failures as isError results;
Existing401/403 errors keep their HTTP status, including current domain-expiry
errors; changing that classification is outside this repair. The adapter
does not turn an execution error into success or perform a retry. The prior
message_not_found-only exception is replaced by one execution boundary.

Turning delivery off stops non-cleanup work. Queue items and source authority
can expire during a prolonged shutdown; re-enabling alone is not a guaranteed
recovery procedure. No queue-wide scan or automation mutation is introduced.
Claims/completions blocked by a return-path outage are not automatically resumed
as hosted turns. Unsubscribe tombstones remain permanent by current policy,
stricter than generic client resubscription; removing them requires a reviewed
generation/intent design that preserves unsubscribe/verification races.

## Evidence and release limits

Offline contract tests reproduce shorter-TTL renewal/restart failure, receipt_busy
misclassification and pre-send storage failures permanently killing work. Tests
cover the fixes plus hard401→later-token→same-ID recovery through the real JWT
verifier. This simulates a client supplying fresh authority; it does not prove
the real host refreshed or repaired its registration. Existing runtime tests
exercise source→signed event→receipt→ACK, concurrency, restart and queue failure.

No local test proves native event context, hosted receipt or continuous renewal.
The spent synthetic diagnostic has no source message and cannot exercise normal
claim/ACK delivery. Its durable marker is preserved. Readiness attestations stay
false until independent native evidence exists. No support or host fault is
assumed; current host binding/refresh decisions remain unavailable to this server.
