import { authorizationPolicyId, BridgeError } from './policy.ts';
import { resourceFor } from './resource.ts';
import { TaskKernel, validateTaskLimits } from './tasks.ts';
import { validateTaskNoticeOptions } from './task-notices.ts';
import { TaskIntegration } from './task-integration.ts';
import { createTaskAccess } from './task-access.ts';
import { PEER_IDS } from './config.ts';
import type { PolicyIdentity } from './policy.ts';
import type { TaskLimits } from './tasks.ts';
import type { TaskBridge } from './task-integration.ts';
import type { TaskAccessPolicy } from './task-access.ts';
import type { TaskRetentionOptions } from './task-retention.ts';
import type { Millis, Store } from './types.ts';

export interface TaskCapabilityLimits {
  leaseMs?: number | undefined; limits?: Partial<TaskLimits> | undefined; linkRetentionMs?: number | undefined;
  maxLinks?: number | undefined; maxLinksPerTask?: number | undefined;
}
export interface TaskCapabilityOptions extends TaskCapabilityLimits {
  enabled?: boolean; store?: Store; bridge?: TaskBridge | undefined; policy?: TaskAccessPolicy | undefined; clock?: () => Millis;
  purgeEnabled?: boolean | undefined; retention?: TaskRetentionOptions | undefined;
}

export function validateTaskCapabilityOptions({ leaseMs, limits, linkRetentionMs, maxLinks, maxLinksPerTask }: TaskCapabilityLimits = {}): void {
  if (!Number.isSafeInteger(leaseMs) || (leaseMs as number) <= 0) throw new BridgeError('task_kernel_configuration_required', 503);
  validateTaskLimits(limits);
  validateTaskNoticeOptions({ linkRetentionMs, maxLinks, maxLinksPerTask });
}

// Runtime assembly requires explicit trusted constructor opt-in; the exported
// production instance stays disabled. Permanent task/link purge is excluded.
export function createTaskCapability({ enabled = false, store, bridge, policy, clock = Date.now,
  leaseMs, linkRetentionMs, limits, maxLinks, maxLinksPerTask, purgeEnabled = false, retention }: TaskCapabilityOptions = {}): TaskIntegration {
  if (enabled !== true) return new TaskIntegration();
  if (purgeEnabled !== false || retention !== undefined) throw new BridgeError('task_purge_not_enabled', 503);
  validateTaskCapabilityOptions({ leaseMs, limits, linkRetentionMs, maxLinks, maxLinksPerTask });
  if (typeof bridge?.prepareMessage !== 'function') throw new BridgeError('task_bridge_configuration_required', 503);
  const authorize = createTaskAccess(policy);
  // bridge.prepareMessage was checked above, so the bridge is present.
  if (PEER_IDS.some(role => bridge!.messagePolicyIds?.[role] !==
      // createTaskAccess(policy) above validated the issuer and subject pin.
      authorizationPolicyId({ ...policy, role, audience: resourceFor(role) } as PolicyIdentity)))
    throw new BridgeError('task_bridge_policy_mismatch', 503);
  const kernel = new TaskKernel({ store: store as Store, clock, leaseMs, limits, authorize });
  return new TaskIntegration({ enabled: true, kernel, bridge, linkRetentionMs, maxLinks, maxLinksPerTask,
    purgeEnabled: false });
}
