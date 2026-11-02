# Private file transfer (default off)

The bridge can transfer private files between its two peers without putting
file bytes in a message, an MCP response, or a model context. The sender and
recipient transfer bytes directly to and from a private Vercel Blob store
with short-lived, artifact-scoped signed URLs. The bridge stores only bounded
metadata and decides who may obtain each capability.

This is temporary transfer, not a cloud drive. Put a short summary in the
message. For code that both peers can already read from a repository, prefer
an immutable commit plus selected paths or line ranges; see
[Repository references](#repository-references).

The feature is absent unless `BRIDGE_ATTACHMENTS_ENABLED=true` and a valid
`BLOB_STORE_ID` are present. While it is off, there are no attachment tools,
no `attachmentIds` send field, no attachment state or provider call, and the
size/store settings are not read. A message containing `attachmentIds` is
rejected with `attachments_not_enabled`.

## Provider and credentials

The implementation uses a private Vercel Blob store and exact-pinned
`@vercel/blob` 2.8.2. Its intended production authentication path is the
deployment's ordinary Vercel OIDC identity paired with the connected store
ID; the bridge passes the store ID and does not configure or pass a static
read-write token. The standard SDK resolves OIDC first, but if OIDC is
unavailable it can fall back to reading `BLOB_READ_WRITE_TOKEN` from the
environment. Do not configure, copy, or rely on that fallback for this
deployment. Before enabling attachments, verify that the deployment's Vercel
OIDC identity can access the connected private store; local tests do not
qualify that provider permission or request path.

For each grant, the server asks Vercel for a delegation scoped to one
attachment pathname, operation, expiry, content type and maximum size, then
signs the URL locally. The delegation's client signing key never leaves the
provider module. The returned URL is still a bearer secret: do not put it in
messages, logs, shell history, checkpoints, telemetry, or error reports.

The core is provider-neutral. It treats ETags as opaque values and never
derives content integrity from them.

## Flow

1. The sender streams the file through `describeFile`, obtaining its exact
   decimal size and SHA-256, then calls `bridge_attachment_begin` with
   `name`, `size`, `sha256`, optional `kind` (`file`, `text`, or `code`), and
   optional `mode` (`single` by default or `multipart`). A client-chosen UUID
   v4 `id` makes an identical retry continue the same reservation.
2. The bridge durably reserves that identity and returns a private upload
   capability for exactly `att/<attachmentId>`, the declared maximum size,
   `application/octet-stream`, no overwrite and no random suffix. The grant
   metadata is bound to the attachment ID, mode, size, and SHA-256 before any
   client request is sent.
3. The sender uploads either with one PUT or with the native multipart
   protocol. The helper hashes the bytes actually consumed from an opened,
   no-follow file handle and refuses success if they differ from the declared
   SHA-256 or if the file identity changes. This check happens after the
   stream: a provider may already have accepted bytes when a mismatch is
   discovered, so the helper makes no false success claim and does not claim
   that it prevented provider writes.
4. The sender calls `bridge_attachment_finalize`, optionally with the opaque
   ETag returned by upload. The bridge performs a bounded HEAD and requires
   the exact size. HEAD proves only that an object of that size exists at the
   immutable pathname; it is not SHA-256 proof.
5. The sender includes up to four `attachmentIds` in a normal message. Both
   message transactions admit only the sender's own `available` attachments
   for that recipient under the current policy, store namespace, authority,
   expiry and configured size limit. The envelope contains IDs only.
6. The recipient calls `bridge_attachment_download` with the claimed
   `messageId` and `attachmentId`, optionally adding a byte range. The bridge
   checks the message, both peers' current authority and policy, durable
   denials, object version, attachment access window and grant budgets.
7. The recipient streams to a path it chose and verifies the full declared
   size and SHA-256 before acknowledging or using the file. The full digest
   is mandatory even when HEAD and ETag matched.

File bytes are untrusted data, including files labelled `text` or `code`.
Never automatically open, render, extract, execute, import, source, compile,
or load them into model context. Verification establishes identity, not
safety.

## Limits and honest cost bounds

All sizes are decimal bytes.

| Bound | Value |
|---|---|
| File size | 1 to 500,000,000 by default; trusted `BRIDGE_ATTACHMENT_MAX_BYTES` may set 500,000,000 through 1,000,000,000 |
| Live records | 20 per sender, 50 total |
| Reserved bytes | 20,000,000,000 total |
| All records | 400 |
| Attachments per message | 4 |
| Fixed access window | 24 h from reservation; never extended |
| Capability lifetime | At most 15 min and never past caller authorization or the reservation bounds |
| Single upload window | First hour of the fixed reservation |
| Multipart upload window | The fixed 24 h reservation; each new capability still needs fresh caller authority |
| Upload-side rate | 10 per minute and 100 per day per role |
| Download-grant rate | 20 per minute and 400 per day per role |
| Per attachment | 5 single or 40 multipart grants; 10 HEAD attempts; 80 download grants |

Each bridge issuance/HEAD attempt is charged before its provider step and is
never refunded. Multipart session creation (3), part attempts (5 per part),
completion attempts (3), concurrency (4), and checkpoint size are also
bounded by the helper.

Those are truthful helper and logical-reservation bounds, not bounds on
physical provider requests, storage, transfer, or billing. A bearer grant can
be reused by its holder until expiry; an in-flight request may finish after
the bridge times out; an unknown create may have created an abandoned native
session; and the default policy neither aborts sessions nor deletes objects.
Provider accounting applies to every physical request and stored byte.

Download authority is intentionally stricter than queued-text recovery. A
SYNC item's text may later be recovered in a batch after its original sender
token expires, while the attachment is no longer downloadable. There is no
strict two-hour attachment SLA and this document does not adopt a receiver or
deletion policy.

## Single PUT

`uploadFile(path, begun, expected)` validates the complete grant, opens the
source without following a symlink, checks the opened and named file identity,
streams exactly the expected size, hashes the bytes consumed by the HTTP
request, rechecks identity, and returns only if the response names the exact
pathname and supplies a bounded opaque ETag. A failed or unknown outcome is
not automatically retried or deleted; request another grant within the fixed
single-upload window.

A plain HTTPS client can use the returned URL and exact returned headers. The
following is illustrative; keep both URL and response private and compare the
local SHA-256 again before finalizing:

```sh
curl --fail-with-body --proto '=https' --request PUT \
  --header 'x-api-version: 13' \
  --header 'x-vercel-blob-store-id: <store-id-from-grant-header>' \
  --header 'x-vercel-blob-access: private' \
  --header 'x-content-type: application/octet-stream' \
  --header 'x-add-random-suffix: 0' \
  --header 'x-allow-overwrite: 0' \
  --header 'Content-Length: <exact-size>' \
  --data-binary '@<local-path>' \
  '<upload-url>'
sha256sum '<local-path>'
```

Prefer the helper: command lines, process listings, verbose output and shell
history can disclose a signed URL, and plain `curl` cannot bind a changing
source as tightly as the opened-handle helper.

## Multipart upload and cross-wake resume

Use `mode: multipart` for large or interruption-prone uploads. The helper:

1. `planMultipart(path)` opens the file without following a symlink and
   streams it once, recording the whole SHA-256, 16/32/64 MiB part hashes,
   exact file identity and sizes.
2. `createCheckpoint(absolutePath, { attachmentId, plan })` creates a new
   mode-0600 JSON checkpoint atomically. It contains only binding/progress
   data: no URL, signature, delegation, credential, or signing token.
3. `uploadMultipart(checkpointPath, begun)` takes an exclusive lock file for
   the whole operation. Another process or Promise using that checkpoint gets
   `checkpoint_busy`; locks are never taken over automatically while an older
   network call might still be live. `breakCheckpointLock` is an explicit
   operator action only after the earlier owner is known to have stopped.
4. Session creation intent, every part attempt, part ETags/hashes, and
   completion intent are persisted atomically before or after the relevant
   request. The part-attempt budget therefore survives process restarts and
   wakes; failure to persist sends nothing.
5. On a later wake, call `bridge_attachment_begin` again with the same ID and
   identical name/size/SHA/kind/mode to get a fresh short capability, then run
   `uploadMultipart` against the same checkpoint. Completed parts are not
   resent.

An unknown create is never blindly repeated. The checkpoint remains
`creation_unknown`; starting a replacement requires explicit
`allowNewSession: true`, counts against the three-session bound, and honestly
records the unknown session as abandoned. No automatic stale-owner takeover,
abort, or cleanup occurs.

If a COMPLETE request succeeds but its response is lost, the checkpoint is
`complete_unknown`. A bounded retry may receive `not_found` because the
provider already consumed the session; the helper returns
`session_gone_check_finalize` and still does not know the opaque ETag. Call
`bridge_attachment_finalize` without an ETag. Its immutable-path HEAD can
reconcile exact size and record the provider's opaque ETag. That flow does
not prove SHA-256: only the recipient's full streamed digest does.

## Downloads and resume

`consumeAttachment(metadata, absolutePath, acquireDownload, options)` is a
bounded Node consumer around the existing streaming helper. The host must
supply its existing recipient-authenticated MCP binding **in the same process**;
the callback receives only attachment/message IDs and range bounds, and its
grant must never be logged or serialized to model/tool history. Each call
acquires a fresh grant, binds size/SHA-256/IDs, and streams at most one chunk
(16 MiB default, 64 MiB maximum). Default file limit is 500,000,000 bytes;
an explicitly configured limit can reach the 1,000,000,000-byte hard cap.
One deadline covers acquisition and transfer (45 seconds default, 55 maximum).
Outputs contain only IDs, size/hash, received count and `partial`/`verified`;
errors use fixed codes, never callback errors/URLs/headers. No automatic retry,
receipt completion, file execution or cleanup occurs. Persisted partial state
allows a later invocation to resume; reconcile/reclaim an expired 60-second
receipt lease before further workflow handling, rather than reusing it.

This is a reusable client binding, **not** proof of a hosted assistant's file
ingestion. The current MCP download tool returns a short-lived capability in
ordinary tool content/structured output; do not invoke it through a transcript
surface when capabilities must remain private. A host must acquire/consume it
before transcript serialization. OpenAI's [plugin tool-results contract](https://developers.openai.com/plugins/reference#tool-results)
only hides component `_meta`; it does not establish automatic remote-file
delivery to native receiver disk. Resource links, giant base64 results, and
host UI downloads are not substitutes. Native host binding remains a rollout
requirement; no new proxy or access grant is supplied here.

For a Node host with an already authenticated Codex CLI and the managed Bridge
connector, `consumeCodexAttachment` in `src/codex-attachment-consumer.ts` supplies
that binding. It launches a short-lived `codex app-server --stdio` child with
an ephemeral thread and **no model turn**. It discovers and calls only the
fixed `codex_apps` / `jarvis_friday_bridge.bridge_attachment_download` tool,
keeps protocol pipes private, bounds startup/RPC/overall time and protocol
bytes, and refuses interaction requests, unexpected model/item activity,
missing tools or a persisted rollout. It never logs raw responses/errors,
reads auth files, starts login, changes configuration, or starts a daemon.
Normal existing CLI authentication/connector access are prerequisites; no
automatic consent or permission response is supported. Runtime protocol
support was checked with CLI 0.166.0; this experimental interface may change
and then fails closed. Synthetic protocol tests are not live file qualification.

The destination is on the **consumer process's filesystem**, not automatically
in a hosted Dot's file library or model context. Receipt claim ownership,
existing-run reconciliation and actual file availability to the intended host
still need explicit integration. A metadata-only health call and an owned
synthetic MCP canary showed no rollout path or result items in the ephemeral
thread's metadata; ephemeral turns listing was unavailable and items listing
unsupported. This does not audit provider-side retention or certify other
hosts' logging. No PostToolUse hook is installed or relied on.

`downloadFile(result, absolutePath)` validates the grant and writes to
dot-prefixed, mode-0600 quarantined state beside the chosen destination. The
binding includes attachment, message, size, SHA-256, opaque ETag and current
offset. It never trusts a remote filename and never replaces an existing
destination.

- A whole-object grant expects `200` and the exact length.
- A resumed/chunk grant expects `206`, the exact `Content-Range`, length and
  ETag. If private Blob ignores `Range` or `If-Match`, the helper fails safely
  and keeps no bytes from that response.
- `resumeOffset` returns the verified local prefix; a fresh grant starting at
  that offset continues it. Optional chunks must be at least 16 MiB unless
  they end at the object boundary. Sixty 16 MiB grants or fifteen 64 MiB
  grants cover 1 GB within the 80-grant bound.
- Publication copies from the call's own open partial handle into a new
  exclusive snapshot while hashing exactly what is written. Only an exact
  size/SHA match is synced and linked to the destination.
- `discardPartial` explicitly removes quarantined progress.

Plain HTTPS download, using exactly the returned headers:

```sh
umask 077
curl --fail-with-body --proto '=https' \
  --header 'If-Match: <opaque-etag>' \
  --header 'Range: bytes=<start>-<end>' \
  --output '<quarantined-part>' \
  '<download-url>'
sha256sum '<complete-file>'
```

Omit `Range` for a whole download. Check status, `Content-Range`, length,
ETag, total size and the final SHA-256 before publication. Never log or save
the signed URL in the partial metadata.

## Retention is not access expiry

Without a trusted owner-approved constructor policy—the default and exported
runtime behavior—the bridge never sends DELETE, never aborts multipart
sessions and never releases reserved quota. Expired/rejected records remain
and new reservations eventually receive `attachment_quota_exceeded` instead
of silently discarding data. No provider lifecycle rule is assumed.

Cleanup scaffolding exists only for a constructor-supplied exact policy
`{ physicalDelete: true, approvedBy, approvedAt }`; no environment variable,
request, or MCP tool can enable it. With such a policy it performs bounded,
backed-off deletes and a later recheck. This feature does not supply or adopt
that policy.

Every record stores a digest of the Vercel Blob store identity. Changing the
store makes existing records fail closed with
`attachment_namespace_mismatch`; malformed metadata fails closed with
`attachment_storage_invalid`.

## Repository references

`src/repo-refs.ts` formats and parses immutable references in normal message
text:

```text
Repository references (immutable; resolve with your own authorized Git access):
- github.com/owner/repo@<40 or 64 hex commit>
  - src/file.ts#L10-L42
  - docs/README.md
```

References use full immutable commit IDs and explicitly selected relative
paths (at most 4 repositories and 16 paths each). The bridge never fetches,
clones, unpacks or executes a repository. Resolve only the selected paths
with the receiver's existing authorized Git access. If access is unavailable,
ask for those files explicitly; do not broaden retrieval to a whole tree or
archive.

## Configuration checklist

Configuration, provisioning, spend and deployment are separate operator
actions; local implementation does none of them.

1. Connect a **private** Vercel Blob store to the production project and
   confirm production has `BLOB_STORE_ID` and working OIDC. Do not add a
   static read/write token for this implementation.
2. Set the optional decimal `BRIDGE_ATTACHMENT_MAX_BYTES`, then set
   `BRIDGE_ATTACHMENTS_ENABLED=true` only after receiver policy is approved.
3. Decide retention separately. Do not add a deleting lifecycle or pass a
   cleanup policy without explicit owner approval.
4. Before relying on production, run separately approved real-provider
   negative checks for pathname/size/content-type/no-overwrite, privacy,
   expiry, multipart unknown outcomes, HEAD, opaque ETag, and GET behavior.
   Private signed-URL `Range` and `If-Match` behavior is not treated as
   qualified until that live validation; the helper fails safely if either
   is ignored or malformed.

Official references: [Vercel Blob](https://vercel.com/docs/vercel-blob),
[private storage](https://vercel.com/docs/vercel-blob/private-storage), and
[signed URLs](https://vercel.com/docs/vercel-blob/vercel-signed-urls).

## Local verification scope

Tests use `test/fixtures/fake-blob.ts`, fake store IDs, isolated temporary
files and no live credentials or provider requests. They cover signed URL
shape against the real pinned SDK locally, 1,000,000,000-byte bounded-memory
single and multipart transfers, checkpoint ownership and durable retries,
lost completion reconciliation, download resume/concurrency, ignored ranges,
opaque ETags and final SHA verification. Test-double success does not qualify
undocumented live-provider behavior.
