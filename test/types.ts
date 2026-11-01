// Type-only views for test assertions. Import with `import type`: this module
// declares no runtime values and is never loaded by the test runner.
//
// A parsed JSON-RPC response is read by each test as the member its scenario
// expects (result or error); if that member is missing, the test fails at
// runtime, so both are declared present for assertion convenience.
export interface RpcError { code: number; message: string; data?: { reason?: string } }
export interface RpcResponse<R = Record<string, unknown>> {
  jsonrpc: '2.0';
  id: string | number | null;
  result: R;
  error: RpcError;
}
/** An MCP tools/call result (mcp.ts toolResult). */
export interface ToolCallResult<S = Record<string, unknown>> {
  content: { type: 'text'; text: string }[];
  structuredContent: S;
  isError: boolean;
}
export type ToolResponse<S = Record<string, unknown>> = RpcResponse<ToolCallResult<S>>;
/** tools/list entries (mcp.ts / task-integration.ts ToolDefinition). */
export interface ListedTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown> & { properties: Record<string, Record<string, unknown>>; required?: string[] };
  annotations: Record<string, boolean>;
}
/** A task tool's structured result as the task tests read it (command result, read view, or tool error). */
export type TaskToolOutput = Partial<import('../src/types.ts').TaskOutput & Omit<import('../src/tasks.ts').TaskView, 'result'> & {
  result: import('../src/types.ts').TaskResult | null; noticeMessageId: string; jobIds: string[];
  task: import('../src/tasks.ts').TaskView; messageId: string; noticeRevision: number; error: string;
  scheduling: string; deliveryScheduled: boolean; expired: boolean;
}>;
/** An HTTP status plus the parsed JSON-RPC body, as several local rpc() helpers return it. */
export type RpcReply<S = TaskToolOutput> = { status: number } & Partial<RpcResponse<ToolCallResult<S>>>;
