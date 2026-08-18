import { Cause, type Exit, Option } from 'effect';
import type { AppRuntime } from '../app-env';
import {
  ErrorCode,
  err,
  type JsonRpcId,
  type JsonRpcResponse,
  type JsonRpcResultResponse,
  ok,
  PROTOCOL_VERSION,
  PROTOCOL_VERSION_META_KEY,
  SERVER_INFO_META_KEY,
  SERVER_NAME,
  SERVER_VERSION,
  SUPPORTED_VERSIONS
} from './protocol';
import { TOOL_RUNNERS, TOOLS, type ToolProgramError } from './tools';

/**
 * Everything a request needs to be processed on its own — no session, no
 * per-connection memory. `handleRpc` is a pure function of `(request, ctx)`:
 * the same request always maps to the same response shape, and two independent
 * calls never share state. That IS the `2026-07-28` statelessness guarantee.
 */
export interface McpContext {
  /** The raw HTTP request headers (carry `x-api-key` for per-request auth). */
  readonly headers: Headers;
  /** The shared app runtime the tool programs run on. */
  readonly runtime: AppRuntime;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** `DiscoverResult` — server identity, versions, capabilities. */
const discoverResult = () => ({
  resultType: 'complete',
  supportedVersions: [...SUPPORTED_VERSIONS],
  capabilities: { tools: { listChanged: false } },
  // The brief asks for a top-level `serverInfo`; the spec also carries it in
  // `_meta['io.modelcontextprotocol/serverInfo']`. We emit BOTH so either a
  // brief-shaped or a strictly-spec-shaped client finds it.
  serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
  instructions:
    `bit exposes vulnerability-methodology retrieval (bit_retrieve) and ingestion (bit_ingest) tools.`,
  ttlMs: 3_600_000,
  cacheScope: 'public',
  _meta: { [SERVER_INFO_META_KEY]: { name: SERVER_NAME, version: SERVER_VERSION } }
});

/** `tools/list` result — static, deterministic, with cache hints. */
const toolsListResult = () => ({
  resultType: 'complete',
  tools: TOOLS,
  ttlMs: 3_600_000,
  cacheScope: 'public'
});

/** A `resultType:'complete'` tool-execution error (caller can self-correct). */
const toolExecutionError = (id: JsonRpcId | null, message: string): JsonRpcResultResponse =>
  ok(id, {
    resultType: 'complete',
    content: [{ type: 'text', text: message }],
    isError: true
  });

/**
 * Map a tool program's modeled failure to a wire response.
 *
 * Auth failures are PROTOCOL errors (the tool never ran) -> JSON-RPC error with
 * an application-defined code. Everything else (validation, embedding, rerank,
 * repo) is a TOOL-EXECUTION error the caller can act on -> `isError:true`
 * result, per the spec's protocol-vs-tool-execution error distinction.
 */
const toolErrorToResponse = (
  id: JsonRpcId | null,
  error: ToolProgramError
): JsonRpcResponse => {
  switch (error._tag) {
    case 'UnauthorizedError':
      return err(id, ErrorCode.Unauthorized, 'Authentication is required.', { httpStatus: 401 });
    case 'ForbiddenError':
      return err(id, ErrorCode.Forbidden, 'You do not have permission to use this tool.', {
        httpStatus: 403
      });
    case 'AuthProviderError':
    case 'AuthEntityLookupError':
      return err(id, ErrorCode.InternalError, 'Unable to verify authentication.');
    case 'RetrieveQueryParseError':
    case 'RecordInputParseError':
      return toolExecutionError(id, error.message);
    case 'EmbedError':
      return toolExecutionError(id, 'Unable to embed the input.');
    case 'RerankError':
      return toolExecutionError(id, 'Unable to rerank candidates.');
    case 'RetrievalRepoError':
      return toolExecutionError(id, 'Unable to run the retrieval.');
    case 'IngestRepoError':
      return toolExecutionError(id, 'Unable to store the record.');
    default:
      return err(id, ErrorCode.InternalError, 'Internal server error.');
  }
};

/** Map a tool program's `Exit` to a JSON-RPC response. */
const toolExitToResponse = (
  id: JsonRpcId | null,
  exit: Exit.Exit<unknown, ToolProgramError>
): JsonRpcResponse => {
  if (exit._tag === 'Success') {
    const payload = exit.value;
    return ok(id, {
      resultType: 'complete',
      content: [{ type: 'text', text: JSON.stringify(payload) }],
      structuredContent: payload,
      isError: false
    });
  }
  // A defect (unmodeled throw) has no `failureOption` -> generic internal error.
  const failure = Cause.failureOption(exit.cause);
  if (Option.isNone(failure)) {
    return err(id, ErrorCode.InternalError, 'Internal server error.');
  }
  return toolErrorToResponse(id, failure.value);
};

/** Dispatch a `tools/call`: resolve + run the named tool on the runtime. */
const handleToolsCall = async (
  id: JsonRpcId | null,
  params: Record<string, unknown>,
  ctx: McpContext
): Promise<JsonRpcResponse> => {
  const name = params.name;
  if (typeof name !== 'string') {
    return err(id, ErrorCode.InvalidParams, 'tools/call requires a string "name".');
  }
  const runner = Object.prototype.hasOwnProperty.call(TOOL_RUNNERS, name)
    ? TOOL_RUNNERS[name]
    : undefined;
  if (runner === undefined) {
    return err(id, ErrorCode.InvalidParams, `Unknown tool: ${name}`);
  }
  // `arguments` is optional, but when present it MUST be an object — a string /
  // number / array / null is a malformed call, not an empty argument set.
  const rawArgs: unknown = params.arguments;
  if (rawArgs !== undefined && !isRecord(rawArgs)) {
    return err(id, ErrorCode.InvalidParams, 'tools/call "arguments" must be an object.');
  }
  const args = isRecord(rawArgs) ? rawArgs : {};
  const exit = await ctx.runtime.runPromiseExit(runner(args, ctx.headers));
  return toolExitToResponse(id, exit);
};

/**
 * Pure JSON-RPC 2.0 dispatcher implementing the `2026-07-28` methods. Takes a
 * single parsed request value + context; returns a single response. No
 * `initialize`, no session state, no `Mcp-Session-Id`.
 */
export const handleRpc = async (
  request: unknown,
  ctx: McpContext
): Promise<JsonRpcResponse | null> => {
  if (!isRecord(request)) {
    return err(null, ErrorCode.InvalidRequest, 'Invalid JSON-RPC request.');
  }
  // A request with no `id` member is a JSON-RPC notification: the server MUST
  // NOT send a response. We don't handle any client notifications, so ignore it
  // (returning `null` signals "no response" to the transport).
  if (!('id' in request)) {
    return null;
  }
  // MCP 2026-07-28 requires the id to be a string or an integer; null, booleans,
  // non-integer numbers, and objects are invalid. Reject rather than coerce.
  const rawId: unknown = request.id;
  if (typeof rawId !== 'string' && !(typeof rawId === 'number' && Number.isInteger(rawId))) {
    return err(null, ErrorCode.InvalidRequest, 'JSON-RPC id must be a string or an integer.');
  }
  const id: JsonRpcId = rawId;

  if (request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
    return err(id, ErrorCode.InvalidRequest, 'Invalid JSON-RPC request.');
  }
  const params = isRecord(request.params) ? request.params : {};

  // Per-request protocol version. If a client pins one, it MUST be supported;
  // if absent, be lenient so bare stateless calls work without negotiation.
  const meta = isRecord(params._meta) ? params._meta : undefined;
  const pinnedVersion = meta?.[PROTOCOL_VERSION_META_KEY];
  if (pinnedVersion !== undefined && pinnedVersion !== PROTOCOL_VERSION) {
    return err(
      id,
      ErrorCode.UnsupportedProtocolVersion,
      `Unsupported protocol version: ${String(pinnedVersion)}`,
      { supported: [...SUPPORTED_VERSIONS] }
    );
  }

  switch (request.method) {
    case 'server/discover':
      return ok(id, discoverResult());
    case 'tools/list':
      return ok(id, toolsListResult());
    case 'tools/call':
      return handleToolsCall(id, params, ctx);
    default:
      return err(id, ErrorCode.MethodNotFound, `Method not found: ${request.method}`);
  }
};
