# Task-data release candidate and staged activation contract

The adapter, purge-disabled capability and default-off runtime hook are released.
The core `runtime = createRuntime()` still passes no task option. The activation
candidate explicitly opts in only in the API constructor, lazily on the first
MCP request, with a60-second mutex,48-hour notice lookup and purge off. Optional
task-constructor `BridgeError` codes beginning `task_` select the existing v1
runtime for that instance instead; task tools remain absent. This preserves
ordinary authenticated health/read/receipt/unsubscribe when task readiness is
unavailable, without changing either verifier. Unexpected errors retain503.
The fallback is sticky until a fresh instance/deployment; it never silently
enables task tools later. The queue entry uses the unchanged core runtime.
The owner has authorized activation after independent review and both native
receiver preparations; acceptance is coordinated separately. Credentials,
OAuth grants and security configuration are unchanged and outside this release.

Task reads include the authenticated caller's role and next command sequence.
Optional read `commandId` recovers only that caller's bounded cached receipt;
`unknown` means absent or evicted, never permission to retry external work.
Recovered start receipts always say `operationRecorded: false`. Use the current
canonical task/operation, revision and next sequence for reconciliation after a
restart; private scratch journals are not required. Exact replay still needs the
original request and notice ID; recovery never reconstructs or guesses a payload.
Earlier automatic-retention proposals are superseded by this purge-off contract.

## Candidate construction and owner binding

The runtime's trusted constructor accepts an optional `taskData` object. Omission
or `enabled: false` preserves the exact ordinary v1 catalog and performs no task
assembly. There is no environment or request flag. A deliberately disabled
assembly can be prepared as:

```js
createRuntime({
  env: trustedEnvironment,
  taskData: { enabled: false, leaseMs: 60000, linkRetentionMs: 172800000, purgeEnabled: false },
});
```

Only explicit trusted `enabled: true` opts in. It requires the existing verified
OAuth contract and normal delivery/receiver/Friday-contract policy; the narrow
canary exception cannot enable task tools. Constructor validation rejects absent
or malformed policy and purge settings before storage. Catalog discovery stays
storage-free. Task calls recheck readiness, then lazily assemble the existing
store/prearmed bridge through `createTaskCapability`; configured issuer/pin/policy
come from the same runtime configuration as the existing resource verifiers.
Task options cannot override identity, policy or sender. Withdrawn delivery policy
hides task tools and closes calls even on an already-created handler.

`createTaskCapability({enabled: true, store, bridge, policy, clock, leaseMs,
linkRetentionMs, ...limits})` remains the runtime's single construction path.
It defaults disabled and rejects `purgeEnabled` other than literal `false`, or
any supplied `retention` configuration. It constructs `createTaskAccess(policy)`
and a kernel with no task-retention collector. The default-off runtime facade
supplies the capability privately to `createMcpHandler`; only the explicit API
constructor opts in. The core singleton stays v1-only.
Construction also requires both bridge delivery-policy IDs to match and the
existing native prearm callback to be configured. Callback presence alone is not
proof of provider readiness, delivery or hosted execution.

Repository evidence: `src/runtime.mjs` supplies both access verifiers and role
policy IDs from the same configured provider issuer and subject pin.
`createAccessVerifier` checks that pin; its audience/role-specific principal keys
intentionally differ. No live subject pin, token, endpoint, message or deployment
setting was read to implement this feature. This is a repository invariant, not
verification of deployed values or either native client's actual binding.

The adapter derives the shared data owner as
`sha256(JSON.stringify(['bridge-task-owner/v1', configuredIssuer, configuredPinDigest]))`.
The digest is the existing configured subject hash, or SHA256 of the existing raw
subject alternative. It checks internal `VERIFIED_AUTHORIZATION` against the
current configured role/resource policy ID and token expiry. The kernel supplies
the current locked storage document as a private fourth callback argument, so
`resourceDenied(state, principal.principalKey)` is checked again in the final
mutation/read transaction. Preview uses a disposable clone of that same current
transaction document; a denial between prearm and final insertion still wins.
No caller-provided owner, role, policy or permission fields are used.

A different configured issuer/pin produces a different owner key; it cannot
reassign/read the prior owner's records. Role-resource denial retains its current
scope and is not silently converted to global owner revocation. Issuer/pin/scope
configuration changes require rebuilding the adapter alongside the existing
verifier; request arguments cannot select policy.

## Existing-scope contract implemented behind the disabled capability

| Operation | Requirement |
|---|---|
| `bridge_task_get`, `bridge_task_from_notice` | Current role's ACK scope |
| Every `bridge_task_command`, including cached replay | Current role's ACK and directional SEND scopes |
| New native status notice | Complete unchanged v1 message admission/prearm/insertion |

Jarvis uses `bridge:ack:jarvis` and `bridge:send:friday`; Friday uses
`bridge:ack:friday` and `bridge:send:jarvis`. No OAuth scopes/grants, credentials,
registrations, access verifier or existing resource policy are changed.
Both admitted roles may create data records. The stored creator coordinates its
task; existing assignee/revision/attempt fences still govern progress/results.
A claim is a coordination mutex, never authorization for external work.

## Purge off and finite capacity

The release candidate never automatically deletes full task records or task-link
metadata. Expired links return `task_notice_not_found` but remain stored. Terminal
results and the latest checkpoint remain available by known task ID; bounded
replay metadata remains stored. Existing ordinary
v1 content cleanup and receipt rules stay unchanged; this is not a change to the
v1 24-hour content/seven-day message-ID lifecycle.

Proposed first-activation settings, still inactive:

| Setting | Value/behavior |
|---|---|
| Public task capability | Explicitly off until the activation bundle is approved |
| Permanent task/link purge | Off separately; candidate factory refuses activation |
| Workflow coordination deadline | 24-hour default supplied by workflow, immutable; does not grant execution authority |
| Coordination mutex | Explicit 60 seconds, capped by task deadline |
| Exact-notice lookup lifetime | Explicit 48 hours; logical expiry, metadata retained |
| Record limits | 100 full tasks, 16 KiB/task, 1 MiB collaboration, 4 MiB shared row |
| Notice-link limits | 1,000 total, 32/task, with existing terminal count reserve |

At a cap the sender gets an explicit capacity error. No active/terminal record is
silently evicted and no expired authority is revived. Terminal reserves protect
kernel/count accounting, not storage outages or all shared v1 message/job growth.
No archive store is configured. Safe capacity blocking is the selected behavior,
not an implicit promise of unlimited factory throughput. Reclaiming record slots
would need a separately reviewed, recoverable archival operation and its own
approval; do not enable the experimental retention collector to unblock work.

Because records are retained, a fresh candidate store accepts the existing UUID
format and needs no new UUIDv7 native helper. Stores previously used with the
experimental retention prototype keep their identity markers/tombstones enforced;
do not erase them or re-enable an older kernel to bypass them. That prototype
remains synthetic-test-only and is not part of the live activation bundle.

## Remaining receiver/catalog dependencies

Runtime wiring is complete and locally tested in both modes/directions. After
approval, deliberately opt in through the trusted production assembly. Refresh the
actual ChatGPT/Grok Bot catalogs for the three existing candidate task tools;
make no new event schema. The unchanged production assembly still exposes ordinary
v1 only. Local catalog tests do not verify native discovery. Before claiming
native integration, verify the actual Grok receiver's
supported payload-to-context mapping and run identity/start/completion evidence.
Historical Cursor docs do not establish Grok's binding.

Receiver workflow: on the existing event, resolve that exact message ID once with
fresh data access. Read current task state; independently check the owner workflow
for external execution authority. Use task-local command sequence/revision and
current attempt/epoch. Before external launch, atomically record `start` with a
stable operation UUID. A replay returns `operationRecorded: false`; do not relaunch.
Before initial launch, recheck current independent authority, task phase/deadline,
assignee, operation ID, attempt/epoch and live mutex. A delayed first response
does not extend this window; reconcile instead. The bridge cannot atomically
prevent a cancellation racing an external provider call.
After a timeout or elapsed mutex, use `reconcile` for the same operation/run,
never a new claim/launch. Observed running/unknown outcomes stay
`reconciliation_required`; an existing completed result can be reported with
fresh access/current revision, before task deadline and cancellation. Reassignment
cannot clear the operation. Evidence is reported, not verified by the bridge;
the native workflow must verify its actual run and independently authorized work.
No provider idempotency, query/cancellation support or future host turn is assumed.
If launch outcome cannot be resolved, remain blocked. Progress does not renew the
60-second coordination mutex and no heartbeat or polling workflow is required.

For a non-task event, use the ordinary known-ID v1 workflow. Expired task links
stop the task-notice branch; known canonical task IDs remain readable under fresh
access. Never claim/complete expired v1 receipts; ACKs stay terminal. No inbox
polling, ACK-response loop, scheduler or automatic external-work permission is
introduced. These native catalog/workflow changes remain unperformed.

## Concise rollout, rollback and acceptance

1. Use the corrected, reviewed/fingerprinted
   combined candidate, rebased/tested against current main, through the
   existing branch/PR, exact-head green CI, merge and Vercel workflow. Verify the
   deployed source/alias while the task runtime gate stays off.
2. Confirm trusted configuration matches the existing verifiers without exposing
   pin/token values. Deliberately supply the runtime's trusted `taskData` options,
   with purge off. Open the approved verification window, opt in, then refresh the actual
   catalogs/workflows and run bounded acceptance. Disable it if acceptance fails.
3. Acceptance separates task/notice storage, native event emission, exact ID in
   actual ChatGPT/Grok context, hosted execution, current claim/checkpoint/result
   and terminal v1 receipt behavior. Include work exceeding the mutex and resolve
   its existing run without relaunch. HTTP acceptance or a peer-reported host ID is
   insufficient. Local tests cover denial races, crossed roles/owners, stale
   policy/expiry, replay, wrong recipient, capacity and crash/delay behavior;
   do not force live failures or broaden traffic as a test.
4. Roll back by disabling task capability on all instances first. Preserve all
   collaboration data, markers, fences and newer v1 writes; do not restore a stale
   database snapshot or purge records. Revert to the recorded known-good release
   with task handlers disabled if needed. Reconcile already-started external work
   separately; API disable/cancellation does not undo external effects.

Owner identity derivation, row locking and batching are implementation details;
they do not need separate repeated permission questions. The authorized release
adopts the new task-data scope meanings, public tool/native workflow exposure,
release and bounded live acceptance. Permanent deletion is excluded.
Runtime wiring is implemented; production opt-in and native catalog/workflow
changes remain unperformed. Actual supported receiver mapping and run-lifecycle evidence
remain unverified platform dependencies. No code here guarantees host scheduler
timeliness, execution or success.
