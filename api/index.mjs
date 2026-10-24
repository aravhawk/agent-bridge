import { createResourceRouter } from '../src/resource.mjs';
import { createRuntime, runtime as v1Runtime } from '../src/runtime.mjs';
import { BridgeError } from '../src/policy.mjs';
let runtime;
export const handle = createResourceRouter({ getHandler: role => {
  if (!runtime) {
    try {
      runtime = createRuntime({ taskData: {
        enabled: true, leaseMs: 60000, linkRetentionMs: 172800000, purgeEnabled: false,
      } });
    } catch (error) {
      if (!(error instanceof BridgeError) || !error.code.startsWith('task_')) throw error;
      // Optional task assembly cannot disable the existing authenticated v1
      // health/read/receipt/unsubscribe paths. No task capability in fallback.
      runtime = v1Runtime;
    }
  }
  return runtime.handler(role);
} });
export default { fetch: handle };
