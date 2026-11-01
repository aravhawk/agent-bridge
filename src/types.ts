// Shared domain types for the bridge.
//
// Trust boundaries:
//   - Wire inputs (MCP tool arguments, HTTP bodies, queue payloads, provider
//     responses) are `unknown` and only become typed after a validator
//     narrows them. `JsonObject` is the shape after the first "is a plain
//     object" check; its fields are still untrusted `unknown`.
//   - The stored state document is the bridge's own durable JSON row. It is
//     validated on load (store.ts checkState) and, field by field, by each
//     module's own validators before use; the types below describe the shapes
//     those modules write and read.
//   - A VerifiedPrincipal can only be produced by the access verifier
//     (policy.ts); its verified authorization lives under a symbol key that
//     JSON input cannot supply.
import type { VERIFIED_AUTHORIZATION, DELIVERY_TRANSPORT_OUTCOME } from './policy.ts';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
/** A plain object received from outside; every field is still untrusted. */
export type JsonObject = Record<string, unknown>;

/** Peer role IDs are deployment configuration (two lowercase IDs). */
export type Role = string;
export type Millis = number;
export type PolicyIds = Readonly<Record<Role, string>>;

// --- Authorization -------------------------------------------------------------
export interface VerifiedAuthorization {
  readonly expiresAt: Millis;
  readonly policyId: string;
}
/**
 * An authenticated caller as the handlers see it. Runtime guards read the
 * verified-authorization slot when present and fail closed when it is not;
 * only the access verifier (policy.ts) attaches it.
 */
export interface Principal {
  readonly role: Role;
  readonly scopes: readonly string[];
  readonly principalKey: string;
  readonly [VERIFIED_AUTHORIZATION]?: VerifiedAuthorization;
}
/** Produced only by createAccessVerifier: the verified authorization is always present. */
export interface VerifiedPrincipal extends Principal {
  readonly [VERIFIED_AUTHORIZATION]: VerifiedAuthorization;
}
/** Authority recorded with a stored message (verifiedMessageAuthorization, or derived for a SYNC batch). */
export interface MessageAuthorization {
  owner: string;
  role: Role;
  resource: string;
  scope: string | undefined;
  policyId: string;
  tokenExpiresAt: Millis;
  expiresAt: Millis;
  derivedFrom?: 'sync_batch';
}
/** Lease authority recorded with an events subscription (verifiedLease). */
export interface LeaseAuthorization {
  owner: string;
  recipient: Role;
  resource: string;
  scope: string | undefined;
  policyId: string;
  tokenExpiresAt: Millis;
}

// --- Envelopes -------------------------------------------------------------------
export type DailyKind = 'message' | 'status' | 'handoff_request' | 'ack';
export type ProbeKind = 'probe' | 'ack';
/** The validated, normalized v1 daily message envelope (messages.ts validateMessage). */
export interface DailyEnvelope {
  protocol: string;
  id: string;
  from: Role;
  to: Role;
  kind: DailyKind;
  sentAt: string;
  expiresAt: string;
  threadId: string;
  route: 'inbox';
  text?: string;
  correlationId?: string;
  class?: 'wake' | 'sync';
  subject?: string;
  effectiveAt?: string;
  dueAt?: string;
  attachmentIds?: string[];
}
/** The synthetic contract-probe envelope (policy.ts validateEnvelope). */
export interface ProbeEnvelope {
  id: string;
  testId: string;
  from: Role;
  to: Role;
  kind: ProbeKind;
  sentAt: string;
  correlationId?: string;
  marker: string;
  // Absent on probes; declared so either envelope can be read uniformly.
  protocol?: undefined;
  expiresAt?: undefined;
  threadId?: undefined;
  route?: undefined;
  text?: undefined;
  class?: undefined;
  subject?: undefined;
  attachmentIds?: undefined;
  effectiveAt?: undefined;
  dueAt?: undefined;
}
export type Envelope = DailyEnvelope | ProbeEnvelope;

// --- Stored messages -----------------------------------------------------------
export type SyncState = 'pending' | 'delivered' | 'superseded' | 'withdrawn';
export interface SyncInfo {
  state: SyncState;
  key?: string;
  slot?: string;
  queuedAt?: Millis;
  batchId?: string;
  deliveredAt?: Millis;
  via?: string;
  redeliveries?: number;
  supersededBy?: string;
  supersededAt?: Millis;
  withdrawnAt?: Millis;
  reason?: string;
  /** Same-millisecond legacy item whose order against a same-subject peer is unknown. */
  orderUnknown?: boolean;
  /** Re-queued after a rollback native send could no longer deliver; never sent natively again. */
  nativeFailed?: boolean;
}
export interface SyncBatch {
  recipient: Role;
  itemIds: string[];
  reason: string;
  createdAt: Millis;
  trigger?: string;
  lateItemIds?: string[];
  presentedAt?: Millis;
  ackedAt?: Millis;
  reclaimedAt?: Millis;
  rehomedTo?: string;
  rehomedAt?: Millis;
}
export interface StoredMessage {
  envelope: Envelope;
  hash: string;
  storedAt: Millis;
  jobIds: string[];
  authorization: MessageAuthorization;
  retainUntil?: Millis | undefined;
  sync?: SyncInfo;
  syncBatch?: SyncBatch;
  syncBatchIds?: string[];
  admission?: number;
  /** Durable admission sequence (sync.ts stampAdmission). */
  syncSeq?: number;
}
export interface MessageIdEntry { hash: string; kind: string; until: Millis }

// --- Receipts and jobs ---------------------------------------------------------
export interface Receipt {
  state: 'claimed' | 'complete';
  owner?: string;
  claimId?: string;
  leaseUntil?: Millis;
  viaMessage?: string | undefined;
  viaBatch?: string;
  completedAt?: Millis;
  ackMessageId?: string | null;
  batchAckMessageId?: string | null;
  hostedEventId?: unknown;
  hostedTurnId?: unknown;
  evidenceStatus?: string;
  /** The named batches a message completion acknowledged, each with its own ACK. */
  syncBatchAcks?: { batchMessageId: string; ackMessageId: string | null }[];
}
export type JobState = 'pending' | 'leased' | 'accepted' | 'dead' | 'failed';
export interface Job {
  id: string;
  messageId: string;
  recipient: Role;
  subscriptionId: string | null;
  eventId: string;
  body: string;
  state: JobState;
  attempts: number;
  dueAt: Millis;
  leaseId: string | null;
  leaseUntil: Millis | null;
  maxAttempts?: number;
  /** Fenced first transport evidence (worker.ts); never overwritten. */
  firstTransportOutcome?: FirstTransportOutcome;
  transportAttempts?: number;
  lastError?: string | null;
  lastStatus?: number | null;
  acceptedAt?: Millis;
  reofferedAt?: Millis;
}
export interface FirstTransportOutcome {
  at: Millis; workerAttempt: number; status: number | null; error: string | null; terminal: boolean;
}

// --- Subscriptions -------------------------------------------------------------
export interface Subscription {
  id: string;
  owner: string;
  recipient: Role;
  active: boolean;
  status: 'active' | 'unsubscribed' | 'denied' | string;
  name?: string;
  arguments?: Record<string, unknown>;
  expiresAt?: Millis;
  authorization?: LeaseAuthorization;
  sealed?: string;
  fingerprint?: string;
  renewalObservations?: Observation[];
  verifiedUntil?: Millis;
  firstSubscribedAt?: Millis;
  lastSubscribedAt?: Millis;
  renewalCount?: number;
}
/** The callback destination sealed with a subscription (AES-GCM, see webhook.ts createProtector). */
export interface SealedCallback { url: string; secret: string; previous?: { secret: string; until: Millis }[] }
/** The single spent webhook diagnostic attempt, at state[NAMES.diagnosticState] (webhook-diagnostic.ts). */
export interface DiagnosticRecord {
  messageId: string; receiverId: string; owner?: string; attemptedAt: Millis; armedFrom: Millis; armedUntil: Millis;
  outcome: { status: number | null; error: string | null; completedAt?: Millis } | null;
}
/** One bounded observation record (observability.ts); stored copies are re-validated before use. */
export interface Observation {
  at: Millis; outcome: 'success' | 'error'; code: string; reason?: string | undefined;
  authorityExpiry?: string | undefined; refreshBefore?: Millis | null | undefined; owner?: string | undefined;
}
/** The one canary reservation, at state[NAMES.canaryState] (canary.ts). */
export interface CanaryReservation {
  messageId: string; owner: string; from: Millis; until: Millis; subscriptionId: string; hash: string;
  reservedAt: Millis; ackMessageId: string | null; sourceReads?: unknown; ackReads?: unknown;
}
export interface ResourceDenial { resource: string; recipient: Role; status: 'denied'; deniedAt: Millis }

// --- Task coordination DATA (tasks.ts, task-notices.ts, task-retention.ts) ----------
export type TaskPhase = 'queued' | 'running' | 'blocked' | 'reconciliation_required' |
  'succeeded' | 'failed' | 'cancelled' | 'expired';
export type TaskOperation = 'create' | 'assign' | 'claim' | 'progress' | 'finish' | 'block' | 'cancel' | 'start' | 'reconcile';
/** A command after tasks.ts command() validated its exact field set for its operation. */
export interface TaskCommand {
  operation: TaskOperation; taskId: string; commandId: string; sequence: number; expectedRevision?: number;
  assignee?: Role; description?: string; deadline?: Millis; attemptId?: string; epoch?: number; checkpoint?: string;
  outcome?: 'running' | 'unknown' | 'succeeded' | 'failed'; result?: string;
  reason?: 'waiting_dependency' | 'outcome_unknown' | 'capability_missing'; operationId?: string;
  runRef?: string | null; evidence?: string;
}
export interface TaskLease { id: string; epoch: number; role: Role; until: Millis }
export interface TaskObservation { outcome: string; evidence: string; text?: string; at: Millis; evidenceStatus: string }
export interface ExternalOperation {
  id: string; runRef: string | null; recordedAt: Millis; attemptId: string; epoch: number; observation: TaskObservation | null;
}
export interface TaskResult {
  outcome: string; text: string; at: Millis; commandId: string; operationId?: string; evidenceStatus: string;
}
/** The caller-visible command result (tasks.ts output()). */
export interface TaskOutput {
  taskId: string; revision: number; phase: TaskPhase; epoch: number; operationId?: string; attemptId?: string;
  leaseUntil?: Millis; operationRecorded?: boolean;
}
export interface TaskCommandRecord { id: string; sequence: number; hash: string; result: TaskOutput; noticeId?: string }
export interface TaskCommandHistory { through: number; recent: TaskCommandRecord[] }
export interface Task {
  id: string; ownerKey: string; coordinator: Role; assignee: Role; description: string; deadline: Millis;
  phase: TaskPhase; blockedReason: string | null; revision: number; epoch: number; lease: TaskLease | null;
  checkpoint: { text: string; sequence: number; at: Millis } | null; result: TaskResult | null;
  createdAt: Millis; updatedAt: Millis; commands: Record<Role, TaskCommandHistory>; externalOperation?: ExternalOperation;
}
export interface TaskNoticeLink { taskId: string; revision: number; recipient: Role; ownerKey: string; createdAt: Millis; until: Millis }
export interface RetiredTask { ownerKey: string; phase: TaskPhase; revision: number; epoch: number; retiredAt: Millis; until: Millis | null }
export interface TaskIdentity { version: 1; creationWindowMs: number; observedAt: Millis }
export interface Collaboration {
  version: 1; tasks: Record<string, Task>; noticeLinks?: Record<string, TaskNoticeLink>;
  retiredTasks?: Record<string, RetiredTask>; taskIdentity?: TaskIdentity;
}

// --- Private attachment metadata (attachments.ts; re-validated on every use) --------
export type AttachmentRecordState = 'reserved' | 'available' | 'rejected' | 'deleting' | 'deleted';
export interface AttachmentRecord {
  id: string; key: string; namespace: string; from: Role; to: Role; owner: string; policyId: string;
  name: string; kind: string; size: number; sha256: string; mode: string; etag: string | null;
  state: AttachmentRecordState; createdAt: Millis; uploadUntil: Millis; expiresAt: Millis;
  /** A finalize's fenced HEAD lease. */
  lease: { fence: string; until: Millis } | null;
  /** Capabilities and provider calls issued (charged before use, never refunded). */
  issued: { put: number; head: number; get: number };
  /** Physical cleanup bookkeeping (only under an approved retention policy). */
  cleanup: { attempts: number; nextAt: Millis; deletedAt: Millis | null; rechecked: boolean };
}
/** One role's rate window: attempts in the last minute and the day's count. */
export interface AttachmentRate { minute: Millis[]; day: number; dayCount: number }
export interface AttachmentStore {
  records: Record<string, AttachmentRecord>;
  rate: Record<Role, AttachmentRate>;
  getRate?: Record<Role, AttachmentRate>;
}

// --- The state document --------------------------------------------------------
/** state.syncQueues[recipient] (sync.ts); created only once a SYNC item is queued. */
export interface SyncQueue {
  /** slot (subject key or 'id:<messageId>') -> messageId */
  pending: Record<string, string>;
  lastFlushBoundary?: Millis; flushDay?: string; flushCount?: number;
  /** Batch/native message IDs flushed but not yet published to the queue. */
  undispatched?: string[];
}
export interface BridgeState {
  version: 1;
  messages: Record<string, StoredMessage>;
  subscriptions: Record<string, Subscription>;
  jobs: Record<string, Job>;
  receipts: Record<string, Receipt>;
  messageIds?: Record<string, MessageIdEntry>;
  messagePreparations?: Record<string, { hash: string; until: Millis }>;
  probeAdmissions?: Record<Role, Millis[]>;
  resourceDenials?: Record<string, ResourceDenial>;
  syncQueues?: Record<Role, SyncQueue>;
  collaboration?: Collaboration;
  syncAdmissionSeq?: number;
  attachments?: AttachmentStore;
  /** Module-owned sections (attachments, tasks, diagnostics, canary, scheduler, ...), validated by their owners. */
  [section: string]: unknown;
}

// --- Storage -----------------------------------------------------------------
/** A synchronous state transition under the store's row lock. */
export type Transition<T> = (state: BridgeState) => T;
export interface Store {
  transaction<T>(operation: Transition<T>): Promise<T>;
}

// --- Delivery adapter evidence -------------------------------------------------
export interface TransportOutcome { readonly [DELIVERY_TRANSPORT_OUTCOME]?: unknown }
