# Task data and runtime integration

`src/tasks.ts` stores coordination data independently of expiring messages.
`src/task-notices.ts` can atomically stage a task command, an existing v1 notice
and a bounded notice-to-task link. `src/task-integration.ts` connects those
transactions to the complete v1 message path. MCP has three task handlers behind
an explicitly injected constructor capability. The exported core runtime used by
the queue and cron supplies no task option. The public API entrypoint instead
attempts a trusted task-enabled runtime on its first MCP request once ordinary
OAuth and delivery readiness are open; a `task_*` construction error selects a
sticky v1-only fallback for that instance. No environment or request flag alone
can activate tasks. No events, receivers, timers, migrations, credentials or
production workflows change.

## Data access and execution authority

`TaskKernel` requires a synchronous trusted `authorize` callback returning
`dataAllowed`, `ownerKey`, `role` and `coordinate`. Without it, operations fail
with `task_authorization_unavailable`. The local release factory supplies the
server-bound callback from
`src/task-access.ts`, using trusted configured issuer/pin/current role policy,
ACK reads and ACK+SEND commands. The current locked transaction state is a private
fourth callback argument for denial checks. The public API uses this assembly
only when ordinary readiness is already open; queue and cron remain task-disabled.
No work-grant registry or execution adapter exists. Tests use only
synthetic issuer/key/owner fixtures, not native approval or external permission.
Unsupported async callbacks are rejected and their promise
rejections observed without logging callback data.

A claim is a coordination mutex. Assignment, checkpoint text and peer reports
never authorize external effects. Terminal results are explicitly marked
`reported_not_independently_verified`. The assistant workflow must establish
execution authority independently, including whether an ambiguous external
operation may safely be retried. A fresh data-access decision does not renew an
expired message or authorize an expired task's work.

## Task state

The existing store can retain an additive `collaboration: {version: 1, tasks}`
subdocument without changing v1 initialization or SQL schema. A task retains its
identity, owner/coordinator/assignee, description, immutable coordination deadline,
revision, attempt epoch/mutex, latest checkpoint, terminal report and bounded
command history. Existing v1 message-content cleanup ignores this data.

Commands are `create`, `assign`, `claim`, `progress`, `block`, `finish`, `cancel`,
`start` and `reconcile`.
Creation enters `queued`; claim enters `running`; progress preserves `running`;
block enters `blocked`; finish enters `succeeded` or `failed`; cancel enters
`cancelled`. Reading or commanding after the deadline materializes `expired`.
Terminal phases cannot reopen. A coordinator cannot reassign a live mutex.

Mutex expiry preserves checkpoints and enters `reconciliation_required/lease_lost`;
expiry alone cannot acquire another mutex. Without an external operation, an
explicit coordinator assignment can requeue data work. Explicit blocks (`waiting_dependency`,
`outcome_unknown`, `capability_missing`) require coordinator reassignment before
another claim. These transitions coordinate records only. An expired mutex never
establishes that retrying an external effect is safe. Every progress/report is
fenced by both attempt UUID and increasing epoch, even if UUIDs are reused.
The injected positive `leaseMs` is capped by the task deadline; no live duration
is selected. Clock stopping persists even when a command is rejected; other
rejected changes consume no sequence or partial result/ownership mutation.

Each role has a task-local sequence watermark and at most 32 cached command
results. Matching recent commands return their original result before revision
checking. Changed content conflicts; evicted sequences cannot reapply effects.
Replay never renews a mutex. Use `get` for current state, not a historical reply.

Both reads now add `task.caller: {role, nextSequence}` (the direct get returns
the task itself). This is the authenticated caller's watermark, never the peer's
history. Optional read argument `commandId` returns exactly one caller-owned
receipt as `caller.command`: `committed` includes its sequence, original notice
ID when present, and historical result; `unknown` means absent or evicted and
does not prove noncommit. Recovered start results always set
`operationRecorded: false`. No payload, hash, full journal or peer receipt is
exposed. The latest canonical task/operation plus current revision and next
sequence support crash recovery without private scratch files. Sequence is a
snapshot, not a reservation; concurrent writers still meet the same revision
and sequence fences. A null next sequence means numeric exhaustion; stop rather
than guessing or resetting it. Exact replay still requires the exact original command
and notice ID. Without that request, reconcile current state; never guess an
old sequence or relaunch work from a recovered/historical result.

Before launching independently authorized external work, `start` records one
immutable UUID operation identity under the current mutex, atomically with its
notice. Only a newly committed start returns `operationRecorded: true`. Exact
start replay returns `false`, including after a lost commit reply. This field
describes a ledger write, never execution permission. An ambiguous reply must
not launch work again. Each task supports one external operation; no reset or
second operation is allowed. Reassignment preserves its identity and changes
only who reconciles it, never requeues it for launch.

The native workflow must check its independent authority, then launch at most
once, using provider idempotency only if actually supported. Immediately before
the initial launch it must read current task state and check the same assignee,
operation ID, attempt/epoch, live mutex and uncancelled/unexpired task. A delayed
`operationRecorded: true` response is historical evidence, not a durable launch
permit. After that window, reconcile ambiguity instead of launching. A network
launch still cannot be made atomic with this ledger; cancellation races require
provider support or explicit reconciliation. A launch timeout
does not establish whether work started. Fresh authorized `reconcile` reports
the same operation's `running`, `unknown`, `succeeded` or `failed` observation.
Nonterminal observations remain `reconciliation_required` without a mutex;
they do not require heartbeat notices. A known bounded run reference cannot be
rebound or cleared. Unknown launch outcomes may keep it null and remain blocked.
External work can finish hours after the short mutex: read current revision and
reconcile the existing result, rather than reclaiming/relaunching or using an
expired attempt. Cancellation/deadline still forbid new reconciliation writes;
they do not stop external work. `finish` remains for data-only tasks and cannot
bypass reconciliation after `start`.

Reconciliation evidence and run references are reported DATA, not server-verified
provider facts or authority. The native workflow must verify the existing run
and result before reporting them. The bridge cannot atomically launch an external
provider, query its runs or guarantee cancellation, exactly-once execution or a
future hosted turn. If the actual host cannot resolve a lost launch response,
the task stays ambiguous rather than automatically retrying. Tests demonstrate
two-minute/three-hour work and actual local runtime reconciliation in both
directions with synthetic provider evidence; they do not establish native host
execution capability.

## Atomic notice links

`TaskNoticeTransactions.apply(principal, command, {messageId})` uses one existing
store transaction. It stages the task command, invokes a trusted synchronous
`stageNotice` callback, validates the stored v1 status/inbox envelope binding,
then stores the exact command-to-notice binding and notice-to-task link. A staging,
capacity or commit failure rolls the transaction back. After an ambiguous lost
commit response, retrying the exact command and notice returns the original
binding without staging another notice or extending retention.

`Bridge.prepareMessageSend` contains the existing admission and queue prearm;
`Bridge.stageMessage` contains the existing synchronous final insertion. Ordinary
`sendMessage` calls both. The prototype previews task admission on a disposable
copy, runs the full v1 preparation, then stages task and notice together using
the same final insertion inside one transaction. A prearm failure can retain the
existing durable v1 preparation/rate reservation, but commits no new task/notice.
A final insertion failure rolls back task/content/jobs/link together. Existing
scope, lifetime, return-path, rate, capacity and canary checks remain intact.

The older helper-only fixture uses partial v1 helpers; integration tests exercise
the full path, real offline JWT verification, MCP, queue and delivery worker.
Release-candidate tests additionally use the actual server-bound data adapter.
All principals/configuration are synthetic; no production workflow is activated.

`getByMessageId(principal, messageId)` resolves the canonical latest task under
fresh injected data access and the stored owner/recipient binding. It needs no
message content and can therefore work after content expiry or v1 retention
cleanup. It does not read, claim or complete a v1 receipt. The native event body
remains `{event: 'bridge.message.received', data: {messageId}}`. No new event or
polling API is implemented. Bare kernel changes preserve notice links.

Link lifetime must be explicitly injected. The release factory retains expired
link metadata and rejects lookup logically; only isolated purge-enabled fixtures
physically prune it. The canonical task remains. Exact replay after
link expiry neither recreates the link nor republishes a notice. A command first
applied without a notice cannot later be rebound through this helper.

## Capacity and retention limits

Kernel-local ceilings are 100 tasks, 16 KiB per task, 1 MiB collaboration data
and the existing 4 MiB whole document ceiling; constructors can lower them.
Text bounds count serialized bytes. Unresolved tasks are not evicted. Each live
task reserves 4 KiB in kernel accounting for a terminal transition. Notice links
are capped at 1,000 total and 32 per task, with one count slot reserved per live
task for a terminal notice. These count/byte reservations are not guarantees
against legacy writers, v1 notice/job growth or storage outages consuming shared
capacity. Full integration must preserve shared admission before promising more.

The release factory `createTaskCapability` defaults disabled and independently
refuses permanent purge (`purgeEnabled` must be literal `false`; `retention` must
be absent). No collector is constructed. Logical notice expiry rejects lookup
without physically deleting task-link metadata. Full tasks/results/history stay
stored, so existing IDs cannot be reused and capacity blocks new admission.
There is no archive backing store or automatic record eviction. A fresh release
store needs no UUIDv7 helper because identity records are never forgotten.

The earlier `TaskKernel({retention: {...}})` collector remains an isolated synthetic
prototype. Direct experimental integration must explicitly opt into purge; it
cannot be enabled through the release factory, and none of the checked-in
entrypoints supplies that destructive retention configuration.
Its tests preserve optional UUIDv7/clock fences and legacy compact tombstones;
previously written identity markers remain enforced even when GC is disabled.
Those destructive-retention settings are excluded from the live proposal.

For the exact purge-off owner/scope/retention/receiver/rollback contract, see
[task activation contract](task-activation.md).

## Runtime surface and remaining deployment boundary

Only explicit trusted `createRuntime({taskData: {enabled: true, leaseMs,
linkRetentionMs, purgeEnabled: false}, ...})` or direct injected test capability exposes
the three tools: `bridge_task_command`, `bridge_task_get`,
`bridge_task_from_notice`. Default-off and health-only catalogs omit all three;
direct calls are refused. Enabled construction requires a trusted synchronous
data-admission callback and the same store as the bridge. The local release
factory, scope adapter and lazy runtime assembly exist. The public API attempts
that assembly only when ordinary readiness is open; queue and cron remain
v1-only. Every call still passes the existing MCP verifier
and the kernel's fresh injected admission; a new notice additionally passes v1
send-scope admission. Production scopes/grants and verification are unchanged.

The command takes a strict kernel `command` plus `notice: {messageId, sentAt,
expiresAt}`. Stable caller-supplied transport times support precommit retry;
existing v1 validation bounds them to five-minute freshness/one-hour lifetime.
The server fixes peer routing, task thread ID, kind `status` and static notice
text. A committed command replay returns its original message-ID binding:
transport options cannot rewrite content, republish or extend any deadline.
Existing job IDs are returned internally for the ordinary MCP scheduler; they
are removed from tool output. No timer or delivery schedule is added.

The [single activation contract](task-activation.md) records the implemented
server-bound owner/scope adapter, inactive purge-off settings, native receiver
steps, rollout, rollback and acceptance. Both verifiers use the same configured
pin; the adapter derives a common key without equating role-specific principals.
No new identity registry or grant is needed. Local runtime wiring is complete;
the checked-in public entrypoint conditionally attempts it as described above.
Actual verifier/grant/receiver behavior remains to be qualified on a controlled
live target.

Execution still requires the assistant workflow's independent authority. The
bridge does not create host run controls, guarantee on-time execution or recover
external side effects merely because a coordination mutex expired.

`src/webhook-sender.ts` is a provider-neutral HTTPS adapter (Standard Webhooks
signatures or a legacy bearer key) with a fixed event body. Supported evidence
for each actual host's payload-to-context mapping, run start/completion and
duplicate-launch handling remains necessary; bridge code cannot guarantee either
host's scheduler.

## Local verification

With the repository's Node 24.22.3 toolchain:

```sh
node --test test/task*.test.ts
npm test
```

Fixtures use MemoryStore transactions, restart snapshots, fake data contexts,
injected time and failures. They exercise delay, actual v1 cleanup, cancellation,
stale finishes, crash before commit, lost commit replies, duplicates, expiry and
capacity without live messages, database calls or hosted execution.
