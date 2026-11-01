import { STATE_TABLE } from './release.ts';
import { BridgeError } from './policy.ts';
import type { BridgeState, Store, Transition } from './types.ts';
import type { PoolClient } from 'pg';

export const emptyState = (): BridgeState => ({ version: 1, messages: {}, subscriptions: {}, jobs: {}, receipts: {} });
const clone = <T>(value: T): T => structuredClone(value);
// The durable row is the bridge's own JSON document; this is its load-time
// shape check (each module validates its own section before use).
function checkState(state: Partial<BridgeState> | null | undefined): asserts state is BridgeState {
  if (state?.version !== 1 || !state.messages || !state.subscriptions || !state.jobs || !state.receipts) {
    throw new BridgeError('storage_version_mismatch', 503);
  }
}

// Reference model for deterministic concurrency/crash tests. Never a production
// fallback: the MCP runtime requires an explicitly configured durable store.
export class MemoryStore implements Store {
  declare state: BridgeState;
  declare tail: Promise<void>;
  constructor(snapshot: BridgeState = emptyState()) { checkState(snapshot); this.state = clone(snapshot); this.tail = Promise.resolve(); }
  async transaction<T>(operation: Transition<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void; this.tail = new Promise<void>(r => { release = r; });
    await previous;
    try {
      const next = clone(this.state);
      const result = operation(next);
      // A transition must be synchronous; a thenable result is refused.
      if ((result as { then?: unknown } | null | undefined)?.then) throw new BridgeError('async_storage_operation_forbidden', 503);
      this.state = next; return clone(result);
    } finally { release(); }
  }
  snapshot(): BridgeState { return clone(this.state); }
}

// A bounded personal bridge store: a single row lock serializes all transitions.
// This deliberately favors auditable transactions over throughput. No network
// call or signing operation is permitted inside the synchronous transition.
// There is no auto-migration or auto-creation of a database or runtime secret.
/** The client operations this store uses (a pg PoolClient, or a test double). */
export type StoreClient = Pick<PoolClient, 'query' | 'release'>;
/** The part of a pg Pool this store uses. */
export interface StorePool { connect(): Promise<StoreClient> }
export class PostgresStore implements Store {
  declare pool: StorePool;
  constructor(pool: StorePool | null | undefined) {
    if (!pool?.connect) throw new BridgeError('storage_configuration_required', 503);
    this.pool = pool;
  }
  async transaction<T>(operation: Transition<T>): Promise<T> {
    let db: StoreClient | undefined;
    try {
      db = await this.pool.connect();
      await db.query('BEGIN');
      await db.query("SET LOCAL lock_timeout = '5s'");
      const result = await db.query<{ document: BridgeState | undefined }>(`SELECT document FROM ${STATE_TABLE} WHERE id=1 FOR UPDATE`);
      const state = result.rows[0]?.document; checkState(state);
      const output = operation(state);
      if ((output as { then?: unknown } | null | undefined)?.then) throw new BridgeError('async_storage_operation_forbidden', 503);
      const serialized = JSON.stringify(state);
      if (Buffer.byteLength(serialized) > 4 * 1024 * 1024) throw new BridgeError('bridge_store_capacity_reached', 503);
      await db.query(`UPDATE ${STATE_TABLE} SET document=$1, revision=revision+1 WHERE id=1`, [serialized]);
      await db.query('COMMIT');
      return output;
    } catch (error) {
      await db?.query('ROLLBACK').catch(() => {});
      if (error instanceof BridgeError) throw error;
      throw new BridgeError('storage_unavailable', 503);
    } finally { db?.release(); }
  }
}
