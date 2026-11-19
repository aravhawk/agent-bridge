import { timingSafeEqual } from 'node:crypto';
import { BridgeError } from '../src/policy.ts';
export const MAX_COMMAND_BYTES = 512 * 1024;
export const MAX_TRANSFER_BYTES = 2 * 4 * 1024 * 1024 + 256 * 1024;
export type Fetcher = (request: Request) => Promise<Response>;
export function authorized(request: Request, key: unknown): boolean {
  const value = request.headers.get('authorization');
  if (typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key) || !value || !/^Bearer [a-f0-9]{64}$/.test(value)) return false;
  return timingSafeEqual(Buffer.from(value), Buffer.from('Bearer ' + key));
}
export async function bounded(request: Pick<Request, 'body' | 'headers'>, limit = MAX_COMMAND_BYTES): Promise<string> {
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) throw new BridgeError('backend_request_too_large', 413);
  const reader = request.body?.getReader(); if (!reader) return '';
  const chunks: Uint8Array[] = []; let size = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new BridgeError('backend_timeout', 408)), 10000); });
  try {
    for (;;) {
      const part = await Promise.race([reader.read(), deadline]);
      if (part.done) break;
      size += part.value.byteLength; if (size > limit || chunks.length >= 2048) throw new BridgeError('backend_request_too_large', 413);
      chunks.push(part.value);
    }
    return Buffer.concat(chunks).toString('utf8');
  } catch (error) { void reader.cancel().catch(() => {}); throw error; }
  finally { clearTimeout(timer); }

}
export function errorResponse(error: unknown): Response {
  // Do not forward SDK errors, stack traces, tokens, URLs or SQL text.
  return Response.json({ error: error instanceof BridgeError ? error.code : 'backend_unavailable' },
    { status: error instanceof BridgeError ? error.status : 503, headers: { 'cache-control': 'no-store' } });
}
