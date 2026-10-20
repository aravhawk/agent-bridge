import { createResourceRouter } from '../src/resource.mjs';
import { runtime } from '../src/runtime.mjs';
export const handle = createResourceRouter({ getHandler: role => runtime.handler(role) });
export default { fetch: handle };
