import { handle as legacy } from '../legacy/index.mjs';
import { createResourceRouter } from '../src/resource.mjs';
import { runtime } from '../src/runtime.mjs';
export const handle = createResourceRouter({ legacy, getHandler: role => runtime.handler(role) });
export default { fetch: handle };
