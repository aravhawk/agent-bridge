import { authorizationPolicyId, BridgeError } from './policy.mjs';
import { resourceFor } from './resource.mjs';
import { TaskKernel, validateTaskLimits } from './tasks.mjs';
import { validateTaskNoticeOptions } from './task-notices.mjs';
import { TaskIntegration } from './task-integration.mjs';
import { createTaskAccess } from './task-access.mjs';
import { PEER_IDS } from './config.mjs';

export function validateTaskCapabilityOptions({ leaseMs, limits, linkRetentionMs, maxLinks, maxLinksPerTask } = {}) {
  if (!Number.isSafeInteger(leaseMs) || leaseMs <= 0) throw new BridgeError('task_kernel_configuration_required', 503);
  validateTaskLimits(limits);
  validateTaskNoticeOptions({ linkRetentionMs, maxLinks, maxLinksPerTask });
}

// Runtime assembly requires explicit trusted constructor opt-in; the exported
// production instance stays disabled. Permanent task/link purge is excluded.
export function createTaskCapability({ enabled = false, store, bridge, policy, clock = Date.now,
  leaseMs, linkRetentionMs, limits, maxLinks, maxLinksPerTask, purgeEnabled = false, retention } = {}) {
  if (enabled !== true) return new TaskIntegration();
  if (purgeEnabled !== false || retention !== undefined) throw new BridgeError('task_purge_not_enabled', 503);
  validateTaskCapabilityOptions({ leaseMs, limits, linkRetentionMs, maxLinks, maxLinksPerTask });
  if (typeof bridge?.prepareMessage !== 'function') throw new BridgeError('task_bridge_configuration_required', 503);
  const authorize = createTaskAccess(policy);
  if (PEER_IDS.some(role => bridge.messagePolicyIds?.[role] !==
      authorizationPolicyId({ ...policy, role, audience: resourceFor(role) })))
    throw new BridgeError('task_bridge_policy_mismatch', 503);
  const kernel = new TaskKernel({ store, clock, leaseMs, limits, authorize });
  return new TaskIntegration({ enabled: true, kernel, bridge, linkRetentionMs, maxLinks, maxLinksPerTask,
    purgeEnabled: false });
}
