import { STATE_TABLE } from './release.mjs';
import { BridgeError } from './policy.mjs';

export const emptyState = () => ({ version: 1, messages: {}, subscriptions: {}, jobs: {}, receipts: {} });
const clone = value => structuredClone(value);
function checkState(state) {
  if (state?.version !== 1 || !state.messages || !state.subscriptions || !state.jobs || !state.receipts) {
    throw new BridgeError('storage_version_mismatch', 503);
  }
}

// Reference model for deterministic concurrency/crash tests. Never a production
// fallback: the MCP runtime requires an explicitly configured durable store.
export class MemoryStore {
  constructor(snapshot = emptyState()) { checkState(snapshot); this.state = clone(snapshot); this.tail = Promise.resolve(); }
  async transaction(operation) {
    const previous = this.tail;
    let release; this.tail = new Promise(r => { release = r; });
    await previous;
    try {
      const next = clone(this.state);
      const result = operation(next);
      if (result?.then) throw new BridgeError('async_storage_operation_forbidden', 503);
      this.state = next; return clone(result);
    } finally { release(); }
  }
  snapshot() { return clone(this.state); }
}

// A bounded personal bridge store: a single row lock serializes all transitions.
// This deliberately favors auditable transactions over throughput. No network
// call or signing operation is permitted inside the synchronous transition.
// There is no auto-migration or auto-creation of a database or runtime secret.
export class PostgresStore {
  constructor(pool) {
    if (!pool?.connect) throw new BridgeError('storage_configuration_required', 503);
    this.pool = pool;
  }
  async transaction(operation) {
    let db;
    try {
      db = await this.pool.connect();
      await db.query('BEGIN');
      await db.query("SET LOCAL lock_timeout = '5s'");
      const result = await db.query(`SELECT document FROM ${STATE_TABLE} WHERE id=1 FOR UPDATE`);
      const state = result.rows[0]?.document; checkState(state);
      const output = operation(state);
      if (output?.then) throw new BridgeError('async_storage_operation_forbidden', 503);
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
