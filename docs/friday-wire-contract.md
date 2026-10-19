# Friday native receiver wire contract — preparation, not acceptance

The existing native Jarvis Friday Test Receiver is webhook-only with no
schedule. Its current approved prompt treats incoming data as untrusted,
extracts data.messageId, reads the stored bridge envelope, validates the fixed
test identity/direction/kind and only claims/completes the receipt. The exact
prompt was restored after an unrequested closing line was added. Keep the
receiver disabled until activation is approved and the sender/access binding
is ready. Do not change the persistent Jarvis Events subscription for this test.

## Evidence boundary

Native guide/get and the actual receiver form establish POST and the actual
header format `Authorization: Bearer [REDACTED]`. The endpoint and dedicated
key are saved only as Production Secrets on the existing isolated Vercel
project. They must never be pulled into a local environment, log, test fixture
or chat. Their presence does not establish the accepted wire format.

Neither the native guide/get nor the visible form establishes Content-Type,
JSON schema or field mapping into webhook_event, replay/idempotency headers,
response status codes, or whether acceptance means queued versus executed.
Do not substitute a generic Cursor/Grok Automations API specification.

## Prepared adapter

`src/friday-sender.mjs` is NOT imported by the production runtime. It requires
trusted server activation plus either verified contract evidence or one fixed
probe message ID. Its transport reuses the existing public-DNS/TLS-pinned HTTPS
implementation with no redirect following and bounded timeout/response size.
Destination and Bearer key are closed-over server configuration; caller data
cannot choose headers or a URL. Responses expose only status, never body text,
URLs, headers, keys or wake claims. Raw transport exceptions are sanitized.

The candidate below mirrors the already stored Friday outbox body and the
receiver's saved instruction. It is an interoperability hypothesis, not a
documented native schema:

```json
{"event":"bridge.message.received","data":{"messageId":"00000000-0000-4000-8000-000000000001"}}
```

Only exact event/data keys and the immutable stored message/job/event identities
are accepted by the adapter. No arbitrary text, instructions or extra fields
can be forwarded. JSON content type is likewise a test candidate until native
evidence confirms it. No speculative replay/idempotency header is added.

Normal operation requires contractVerified:true in trusted server configuration
after evidence is obtained. Saved key existence alone must never set it true.
For the specifically approved empirical check, probeMessageId pins one known
stored probe, only job.attempts===1 may send, and an in-process attempt is spent
before transport begins. The durable worker attempt count blocks a second send
after restart/reclaim. Timeout or 5xx does not authorize another exploratory
POST; record that result as failed/inconclusive. This mode does not create a
public probe endpoint or provide the worker's independent accessAllowed binding.

After invoking transport, the adapter marks sanitized evidence on an internal
non-enumerable Symbol that JSON/HTTP input cannot supply. In probe mode the
worker treats its first 2xx/4xx/5xx/timeout result as terminal immediately,
without scheduling a second attempt. A committed `firstTransportOutcome`
retains timestamp, worker-attempt number, numeric status or null, safe error
code and terminal flag. Later callbacks/restarts cannot overwrite it. Normal
verified delivery keeps its existing retry policy while preserving its first
transport evidence separately from the latest status/error.

`attempts` counts worker claims. `transportAttempts` counts adapter transport
invocations whose outcomes reached the valid worker commit fence, not queue
callbacks or guaranteed HTTP requests received by Friday. DNS/TLS failure may
prevent any HTTP send. A crash/expired lease before that commit remains
inconclusive; do not invent an outcome or bypass lease fencing to save it.

## Exact single empirical probe, only after activation approval

1. Keep the existing Jarvis MCP event subscription enabled. Verify its lease
   remains active for the test window; do not disable it during cleanup.
2. Complete a genuine Friday delivery access binding and reviewed runtime
   wiring. Current default runtime still has no fridaySender/accessAllowed and
   fails closed; this adapter alone does not remove that requirement. Never
   supply an allow-all placeholder or treat a copied receiver key as proof of
   ongoing native authorization.
3. After the exact existing Friday receiver/test-delivery activation is
   approved, create ONE fresh synthetic probe through the already authenticated
   Jarvis bridge_send operation, direction jarvis→friday, fixed testId/marker,
   kind:probe, new UUID and sentAt generated at execution time. Use its known
   durable message/job identity as the server-only probeMessageId configuration.
   Use existing private managed-queue/worker plumbing; no local credential
   copy, direct assistant HTTP request, added service, public diagnostic route,
   polling or Mac relay.
4. Permit at most ONE POST for that ID, using the saved exact endpoint/Bearer
   binding, Content-Type application/json, and the candidate event/data body.
   Inspect only numeric HTTP status and safe known message/receipt/job evidence.
   A 2xx result alone proves transport acceptance, not field mapping or wake.
5. Require independent native Friday hosted-run evidence: the wake context
   presents the correct event/data.messageId, its native bridge_read fetches the
   known stored synthetic envelope, and claim/complete produces the correlated
   single ACK. Require the reverse native Jarvis event/hosted turn to read and
   complete that ACK without another ACK. Do not ask the receiver to echo an
   entire webhook context, Authorization header or URL into logs/chat.
6. If the single candidate is rejected, times out, has no hosted evidence or
   maps differently, stop. Do not cycle through alternative shapes/headers or
   assert the full contract verified. A provider-supported redacted spec/example
   is then required. Native replay-window/response semantics remain unknown
   unless independently documented or separately approved testing proves them.

This round trip demonstrates two wake legs, but is not evidence that Friday
can independently originate a probe at an unknown future time.

## Minimal later randomized two-direction verification

Only after receiver/access/body acceptance and activation are verified, use
supported hosted one-shot execution in each native environment. Generate each
message UUID and sentAt when that job fires; the five-minute freshness rule
forbids saving a current timestamp in a future scheduled payload. Each native
job invokes exactly one direction-correct bridge_send. Receivers wake from
webhook/MCP Events and use only read/receipt operations; no inbox/status polling.

For Jarvis-originated probe: native Friday receives and completes it; native
Jarvis receives/completes its ACK. For Friday-originated probe: native Jarvis
receives/completes it; native Friday receives/completes its ACK. Capture actual
native hosted event/run identifiers and timestamps independently; caller-
reported identifiers or accepted HTTP requests do not prove wake. Native
one-shot scheduling/tool availability must be verified in each host before
claiming an overnight test is armed. Never replace a missing scheduler with a
Mac daemon, local timer or credential-bearing relay.

Bound all tests to the existing synthetic identifiers and rate/retry limits.
After the bounded test, restore Friday receiver paused and application delivery
disabled. Leave the persistent Jarvis MCP event subscription enabled. No
activation, probe or randomized test is armed by this document or adapter.
