import { closePlainPool } from '@repo/db';
import { httpPortConfig } from '@repo/env';
import { Effect } from 'effect';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import type { AppRuntime, HonoEnv } from './app-env';
import { auth } from './lib/auth';
import { makeAppRuntime } from './managed-runtime';
import { mcpRoute } from './mcp/mcp.route';
import { healthRoute } from './routes/health/health';
import { ingestRoute } from './routes/ingest/ingest';
import { recordsRoute } from './routes/records/records';
import { retrieveRoute } from './routes/retrieve/retrieve';
import { ensureInitialAppState } from './startup';

/** Cap request bodies so an unauthenticated caller cannot force parsing of an
 * arbitrarily large payload before the auth check runs. 1 MiB comfortably fits
 * a single record ingest. */
const MAX_BODY_BYTES = 1024 * 1024;

const jsonBodyLimit = bodyLimit({
  maxSize: MAX_BODY_BYTES,
  onError: (c) =>
    c.json(
      { error: { code: 'PAYLOAD_TOO_LARGE' as const, message: 'Request body too large.' } },
      413
    )
});

export const createApp = (runtime: AppRuntime) => {
  const app = new Hono<HonoEnv>()
    .use('*', async (c, next) => {
      c.set('runtime', runtime);
      c.set('requestId', Bun.randomUUIDv7());
      await next();
    })

    // Body-size cap on the JSON write/read endpoints (defense-in-depth DoS).
    .use('/ingest', jsonBodyLimit)
    .use('/retrieve', jsonBodyLimit)
    .use('/mcp', jsonBodyLimit)
    .use('/records/:id/status', jsonBodyLimit)

    // better-auth owns everything under /api/auth/*.
    .on(['POST', 'GET'], '/api/auth/*', (c) => auth.handler(c.req.raw))

    // API routes mounted at root, per the public path contract.
    .route('/', healthRoute)
    .route('/', ingestRoute)
    .route('/', retrieveRoute)
    .route('/', recordsRoute)

    // MCP doorway mounts here — a stateless JSON-RPC 2.0 endpoint over the same
    // rag-core services as the HTTP routes above.
    .route('/mcp', mcpRoute)

    .onError((error, c) => {
      console.error(error);
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    });

  return app;
};

/** Route types for a future Hono RPC client (`hc<AppType>`). */
export type AppType = ReturnType<typeof createApp>;

// Guard the server bootstrap so importing this module under test neither runs
// the fail-fast startup probe nor binds a port.
const isTest = process.env.NODE_ENV === 'test' || Boolean(process.env.VITEST);

const bootstrap = async () => {
  const runtime = makeAppRuntime();
  // Fail fast: bad config (EMBEDDING_DIM !== 1024, missing endpoint) or an
  // unreachable embedding/rerank server aborts boot before we bind a port.
  await runtime.runPromise(ensureInitialAppState);
  const port = await runtime.runPromise(Effect.orElseSucceed(httpPortConfig, () => 3000));
  const app = createApp(runtime);
  const server = Bun.serve({ port, fetch: app.fetch });
  console.error(`bit api listening on :${port}`);

  // Graceful shutdown: stop accepting connections, dispose the Effect runtime
  // (which closes the @effect/sql pool), close the plain better-auth pool, then
  // exit — so a container stop drains cleanly instead of dropping connections.
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`received ${signal}, shutting down…`);
    try {
      server.stop(true);
      await runtime.dispose();
      await closePlainPool();
    } finally {
      process.exit(0);
    }
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
};

if (!isTest) {
  await bootstrap();
}
