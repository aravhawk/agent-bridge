import { build } from 'esbuild';
await build({ entryPoints: ['cloudflare/worker.ts'], bundle: true, format: 'esm', platform: 'node', target: 'es2024',
  outfile: 'dist-cloudflare/worker.js', external: ['cloudflare:workers', 'node:*'], alias: { pg: './cloudflare/no-postgres.ts' }, banner: { js: "import { createRequire } from 'node:module'; const require = createRequire('/worker.js');" }, logLevel: 'warning' });
console.log('Cloudflare prototype bundle built (local only)');
