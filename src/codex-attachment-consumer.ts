import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { consumeAttachment, AttachmentClientError } from './attachment-client.ts';
import type { AttachmentRequest, ConsumerOptions, ConsumerResult, DownloadGrant, DownloadRequest } from './attachment-client.ts';

// Fixed managed connector only. No caller-controlled command, flags, server,
// tool or URL. Existing Codex authentication stays inside Codex; capabilities
// stay in private pipes / this process, never terminal output or model history.
const SERVER = 'codex_apps', TOOL = 'jarvis_friday_bridge.bridge_attachment_download';
const MAX_PROTOCOL_BYTES = 8 * 1024 * 1024, MAX_STDERR_BYTES = 64 * 1024;
const fail: (code: string) => never = code => { throw new AttachmentClientError(code); };
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('codex_protocol_invalid');
  return value as Record<string, unknown>;
};
interface Pending { resolve: (result: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }

class PrivateCodexClient {
  private readonly child = spawn('codex', ['app-server', '--stdio'], { stdio: ['pipe', 'pipe', 'pipe'] });
  private readonly pending = new Map<number, Pending>();
  private readonly decoder = new StringDecoder('utf8');
  private next = 1;
  private bytes = 0;
  private stderrBytes = 0;
  private buffer = '';
  private stopped: string | undefined;
  private threadId: string | undefined;
  private readonly signal: AbortSignal;
  private readonly abort = () => this.stop('codex_consumer_aborted');
  constructor(signal: AbortSignal) {
    this.signal = signal;
    this.child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    this.child.stdin.on('error', () => this.stop('codex_closed'));
    this.child.stderr.on('data', (chunk: Buffer) => {
      this.stderrBytes += chunk.length; // Consume, never print/save raw diagnostics.
      if (this.stderrBytes > MAX_STDERR_BYTES) this.stop('codex_protocol_limit');
    });
    this.child.on('error', () => this.stop('codex_unavailable'));
    this.child.on('exit', () => this.stop('codex_closed'));
    signal.addEventListener('abort', this.abort, { once: true });
    if (signal.aborted) this.abort();
  }
  private stop(code: string): void {
    if (this.stopped) return;
    this.stopped = code;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new AttachmentClientError(code)); }
    this.pending.clear(); this.child.kill('SIGTERM');
  }
  async close(): Promise<void> {
    this.signal.removeEventListener('abort', this.abort);
    this.stop('codex_closed');
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    await new Promise<void>(resolve => {
      const timer = setTimeout(() => { this.child.kill('SIGKILL'); resolve(); }, 1000);
      this.child.once('exit', () => { clearTimeout(timer); resolve(); });
    });
  }
  private receive(chunk: Buffer): void {
    if (this.stopped) return;
    this.bytes += chunk.length;
    if (this.bytes > MAX_PROTOCOL_BYTES) return this.stop('codex_protocol_limit');
    this.buffer += this.decoder.write(chunk);
    let newline: number;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline); this.buffer = this.buffer.slice(newline + 1);
      let message: Record<string, unknown>;
      try { message = record(JSON.parse(line)); } catch { return this.stop('codex_protocol_invalid'); }
      // Never answer approvals, permissions, elicitation or other server requests.
      if (typeof message.method === 'string') {
        if (message.id !== undefined) return this.stop('codex_interaction_required');
        if (/^(item|turn)\//.test(message.method)) return this.stop('codex_history_unexpected');
        continue;
      }
      if (typeof message.id !== 'number') return this.stop('codex_protocol_invalid');
      const p = this.pending.get(message.id);
      if (!p) return this.stop('codex_protocol_invalid');
      this.pending.delete(message.id); clearTimeout(p.timer);
      if (message.error !== undefined) {
        // Do not propagate raw error objects, messages, URLs or response data.
        p.reject(new AttachmentClientError('codex_rpc_failed'));
      } else p.resolve(message.result);
    }
  }
  private rpc(method: string, params: object, timeoutMs = 15000): Promise<unknown> {
    if (this.stopped) return Promise.reject(new AttachmentClientError(this.stopped));
    return new Promise((resolve, reject) => {
      const id = this.next++, timer = setTimeout(() => this.stop('codex_rpc_timeout'), timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n', error => { if (error) this.stop('codex_closed'); });
    });
  }
  private verifyThread(value: unknown): void {
    const thread = record(record(value).thread);
    // Ephemeral no-model sessions must have no rollout and no result history.
    if (thread.path !== null || !Array.isArray(thread.turns) || thread.turns.length !== 0) fail('codex_history_unverified');
  }
  async start(): Promise<void> {
    await this.rpc('initialize', { clientInfo: { name: 'agent_bridge_private_attachment_consumer', version: '1.0.0' },
      capabilities: { experimentalApi: true } }, 10000);
    this.child.stdin.write(JSON.stringify({ method: 'initialized' }) + '\n');
    const started = await this.rpc('thread/start', { cwd: process.cwd(), ephemeral: true }, 10000);
    this.verifyThread(started);
    const id = record(record(started).thread).id;
    if (typeof id !== 'string' || !id.length || id.length > 160) fail('codex_protocol_invalid');
    this.threadId = id;
    const inventory = record(await this.rpc('mcpServerStatus/list', { threadId: id, serverName: SERVER, detail: 'toolsAndAuthOnly', limit: 100 }));
    if (!Array.isArray(inventory.data) || inventory.nextCursor) fail('codex_tool_unavailable');
    const server = inventory.data.map(record).find(s => s.name === SERVER);
    if (!server) fail('codex_tool_unavailable');
    const entries = Object.values(record(server.tools));
    if (!entries.some(t => record(t).name === TOOL)) fail('codex_tool_unavailable');
    await this.verifyNoHistory();
  }
  private async verifyNoHistory(): Promise<void> {
    this.verifyThread(await this.rpc('thread/read', { threadId: this.threadId, includeTurns: false }));
  }
  async acquire(args: DownloadRequest): Promise<DownloadGrant> {
    const raw = record(await this.rpc('mcpServer/tool/call', { threadId: this.threadId, server: SERVER, tool: TOOL, arguments: args }));
    if (raw.isError) fail('codex_grant_refused');
    await this.verifyNoHistory();
    let value = raw.structuredContent;
    if (value === undefined && Array.isArray(raw.content)) {
      const text = raw.content.map(record).find(c => c.type === 'text')?.text;
      if (typeof text !== 'string') fail('codex_protocol_invalid');
      try { value = JSON.parse(text); } catch { fail('codex_protocol_invalid'); }
    }
    const grant = record(value);
    // Only a provisional shape here; consumeAttachment validates exact expected
    // IDs/size/hash/range and downloadFile validates provider URL/headers/expiry.
    if (typeof grant.attachmentId !== 'string' || typeof grant.messageId !== 'string' || typeof grant.size !== 'number' ||
      typeof grant.sha256 !== 'string' || !grant.download) fail('codex_protocol_invalid');
    return grant as unknown as DownloadGrant;
  }
}

/** One private, no-model Codex session and one bounded chunk; never claims/completes a receipt. */
export async function consumeCodexAttachment(request: AttachmentRequest, destinationPath: string,
  options: ConsumerOptions = {}): Promise<ConsumerResult> {
  const timeoutMs = options.timeoutMs ?? 45000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 55000) fail('invalid_timeout');
  const timer = AbortSignal.timeout(timeoutMs), signal = options.signal ? AbortSignal.any([options.signal, timer]) : timer;
  // Validate non-secret inputs using the same consumer before starting Codex.
  // The acquisition callback is lazy: startup happens only after validation and
  // filesystem preflight, and it shares the outer overall deadline.
  let client: PrivateCodexClient | undefined;
  try {
    return await consumeAttachment(request, destinationPath, async args => {
      client = new PrivateCodexClient(signal);
      await client.start();
      return client.acquire(args);
    }, { ...options, signal, timeoutMs });
  } finally { await client?.close(); }
}
