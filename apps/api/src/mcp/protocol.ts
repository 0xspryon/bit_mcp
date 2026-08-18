/**
 * Hand-rolled, stateless JSON-RPC 2.0 wire types + envelope helpers for the MCP
 * doorway, implementing spec revision `2026-07-28`.
 *
 * Why hand-rolled: the published `@modelcontextprotocol/sdk` only implements
 * `2025-11-25` (the `initialize` handshake + per-connection sessions). The
 * `2026-07-28` contract this doorway targets is stateless — every request is
 * self-contained, carrying its own protocol metadata in `_meta` — and adds the
 * result `resultType` envelope, `server/discover`, and the `ttlMs`/`cacheScope`
 * cache hints. None of that exists in the SDK, so there is no dependency here.
 */

/** The single protocol revision this server speaks. */
export const PROTOCOL_VERSION = '2026-07-28' as const;

/** Advertised in `server/discover` and echoed in the `-32022` error data. */
export const SUPPORTED_VERSIONS = [PROTOCOL_VERSION] as const;

/** Server identity (self-reported; never used for security decisions). */
export const SERVER_NAME = 'bit' as const;
export const SERVER_VERSION = '0.1.0' as const;

// Reserved `_meta` keys from the spec's per-request/per-response protocol fields.
export const PROTOCOL_VERSION_META_KEY = 'io.modelcontextprotocol/protocolVersion' as const;
export const CLIENT_CAPABILITIES_META_KEY = 'io.modelcontextprotocol/clientCapabilities' as const;
export const SERVER_INFO_META_KEY = 'io.modelcontextprotocol/serverInfo' as const;

/**
 * JSON-RPC / MCP error codes.
 *
 * The standard JSON-RPC codes plus the `2026-07-28` `-32022`
 * `UnsupportedProtocolVersion`. Auth failures use application-defined codes
 * OUTSIDE the reserved `-32768..-32000` range (the spec requires new,
 * non-standard codes to live there), so `40100`/`40300` cannot be mistaken for
 * a protocol-defined code.
 */
export const ErrorCode = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
  /** `2026-07-28` UnsupportedProtocolVersion. */
  UnsupportedProtocolVersion: -32022,
  /** Application-defined: caller is unauthenticated. */
  Unauthorized: 40100,
  /** Application-defined: caller lacks the required permission. */
  Forbidden: 40300
} as const;

export type JsonRpcId = string | number;

export interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: JsonRpcId | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

/** A successful result. Every result carries a `resultType` (`2026-07-28`). */
export interface JsonRpcResultResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId | null;
  readonly result: { readonly resultType: string } & Record<string, unknown>;
}

export interface JsonRpcErrorResponse {
  readonly jsonrpc: '2.0';
  readonly id: JsonRpcId | null;
  readonly error: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export type JsonRpcResponse = JsonRpcResultResponse | JsonRpcErrorResponse;

/** Build a JSON-RPC result response. */
export const ok = (
  id: JsonRpcId | null,
  result: { resultType: string } & Record<string, unknown>
): JsonRpcResultResponse => ({ jsonrpc: '2.0', id, result });

/** Build a JSON-RPC error response. */
export const err = (
  id: JsonRpcId | null,
  code: number,
  message: string,
  data?: unknown
): JsonRpcErrorResponse => ({
  jsonrpc: '2.0',
  id,
  error: { code, message, ...(data !== undefined ? { data } : {}) }
});
