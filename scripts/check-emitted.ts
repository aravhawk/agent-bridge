// Clean-compile check for `npm run compile:check`: the JavaScript tsc emits
// into dist/ keeps no relative `.ts` import specifiers, and every deployed
// entry point (plus the runtime and the client helper) loads as an ES module.
// Vercel compiles api/*.ts itself; this checks the same sources compile and
// load as plain JavaScript. It reads no credentials and makes no network call.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const root = path.resolve(process.argv[2] ?? 'dist');
const files: string[] = [];
const walk = (dir: string): void => {
  for (const name of readdirSync(dir)) {
    const entry = path.join(dir, name);
    if (statSync(entry).isDirectory()) walk(entry);
    else if (entry.endsWith('.js')) files.push(entry);
  }
};
walk(root);
const specifier = /(?:from\s*|import\s*\()['"]\.{1,2}\/[^'"]*\.ts['"]/;
const leftover = files.filter(file => specifier.test(readFileSync(file, 'utf8')));
if (leftover.length) throw new Error('emitted JavaScript still imports .ts files: ' + leftover.join(', '));
for (const entry of ['api/index.js', 'api/queue.js', 'api/cron.js', 'src/runtime.js', 'src/attachment-client.js']) {
  const loaded: Record<string, unknown> = await import(pathToFileURL(path.join(root, entry)).href);
  if (!Object.keys(loaded).length) throw new Error('emitted entry point has no exports: ' + entry);
}
console.log(`emitted JavaScript OK: ${files.length} modules; entry points load`);
