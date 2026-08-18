import { Hono } from 'hono';
import type { HonoEnv } from '../app-env';
import { mcpRoute } from '../mcp/mcp.route';
import { adminUsersRoute } from './admin/users';
import { healthRoute } from './health/health';
import { meKeyRoute } from './me/key';
import { ingestRoute } from './ingest/ingest';
import { recordsRoute } from './records/records';
import { retrieveRoute } from './retrieve/retrieve';

/**
 * Every versioned API route, as one Hono sub-app. `index.ts` mounts this at
 * {@link API_BASE_PATH} (`/api/v1`); better-auth keeps its own unversioned
 * `/api/auth/*` prefix and is deliberately NOT part of this tree.
 *
 * The RPC client in `hc.ts` is typed on this sub-app, so paths here are
 * prefix-free and consumers pass `/api/v1` as the client's base URL.
 */
export const appRoutes = new Hono<HonoEnv>()
  .route('/', healthRoute)
  .route('/', ingestRoute)
  .route('/', retrieveRoute)
  .route('/', recordsRoute)
  .route('/admin/users', adminUsersRoute)
  .route('/me/key', meKeyRoute)
  // MCP doorway — a stateless JSON-RPC 2.0 endpoint over the same rag-core
  // services as the HTTP routes above.
  .route('/mcp', mcpRoute);
