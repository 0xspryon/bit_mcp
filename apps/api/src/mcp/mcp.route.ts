import { Hono } from 'hono';
import type { HonoEnv } from '../app-env';
import { handleRpc, type McpContext } from './handle-rpc';
import { ErrorCode, err } from './protocol';

/**
 * The MCP doorway: a stateless Streamable-HTTP `application/json` endpoint.
 *
 * `POST /` reads one JSON-RPC request object (or a batch array), builds a
 * self-contained {@link McpContext} from the raw request headers + shared
 * runtime, and returns a single JSON response. There is NO SSE stream, NO
 * `Mcp-Session-Id`, and NO handshake — each POST stands entirely on its own.
 */
/** Max JSON-RPC requests per batch. Bounds pre-auth fan-out (each item triggers
 * an auth lookup); combined with the route's body-size cap this keeps an
 * unauthenticated caller from amplifying work. */
const MAX_BATCH = 20;

export const mcpRoute = new Hono<HonoEnv>().post('/', async (c) => {
  const ctx: McpContext = {
    headers: c.req.raw.headers,
    runtime: c.get('runtime')
  };

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(err(null, ErrorCode.ParseError, 'Parse error: request body is not valid JSON.'));
  }

  if (Array.isArray(body)) {
    if (body.length === 0) {
      return c.json(err(null, ErrorCode.InvalidRequest, 'Invalid Request: empty batch.'));
    }
    if (body.length > MAX_BATCH) {
      return c.json(
        err(null, ErrorCode.InvalidRequest, `Invalid Request: batch exceeds ${MAX_BATCH} items.`)
      );
    }
    const responses = await Promise.all(body.map((item) => handleRpc(item, ctx)));
    // Notifications (id-less requests) yield null and get no response. If the
    // whole batch was notifications, send back no content.
    const answered = responses.filter((r): r is NonNullable<typeof r> => r !== null);
    if (answered.length === 0) {
      return c.body(null, 202);
    }
    return c.json(answered);
  }

  const response = await handleRpc(body, ctx);
  if (response === null) {
    // A lone notification: accepted, no response body.
    return c.body(null, 202);
  }
  return c.json(response);
});
