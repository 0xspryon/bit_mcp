import { closePlainPool } from '@repo/db';
import { httpPortConfig } from '@repo/env';
import { Effect } from 'effect';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { createMiddleware } from 'hono/factory';
import type { AppRuntime, HonoEnv } from './app-env';
import { API_BASE_PATH } from './hc';
import { auth, baseURL, trustedOrigins } from './lib/auth';
import { makeAppRuntime } from './managed-runtime';
import { appRoutes } from './routes/index';
import { ensureInitialAppState } from './startup';

/** Cap request bodies so an unauthenticated caller cannot force parsing of an
 * arbitrarily large payload before the auth check runs. 1 MiB comfortably fits
 * a single record ingest. */
const MAX_BODY_BYTES = 1024 * 1024;

/**
 * Reject cross-site state changes on the versioned API.
 *
 * better-auth validates origins on its own `/api/auth/*` routes, but nothing
 * covered `/api/v1/*` — so a destructive cookie-authenticated POST (notably
 * `/me/key/refresh`) rested entirely on the session cookie's `SameSite=Lax`
 * default being set elsewhere. This makes the protection explicit and local.
 *
 * Same-origin browser requests send `Origin` on unsafe methods; non-browser
 * callers (agents on `x-api-key`) send none, and are unaffected — a cookie is
 * what makes CSRF possible, and those requests carry none.
 */
const sameOriginOnly = createMiddleware(async (c, next) => {
  const origin = c.req.header('origin');
  if (origin) {
    const allowed = [baseURL, ...trustedOrigins];
    const isAllowed = allowed.some((candidate) => {
      try {
        return new URL(candidate).origin === new URL(origin).origin;
      } catch {
        return false;
      }
    });
    if (!isAllowed) {
      return c.json(
        { error: { code: 'FORBIDDEN' as const, message: 'Cross-origin request rejected.' } },
        403
      );
    }
  }
  await next();
});

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
      // `crypto.randomUUID` rather than `Bun.randomUUIDv7`: the Bun global is
      // absent under vitest's Node workers, which threw on every request and
      // made `createApp` untestable in the integration suites.
      c.set('requestId', crypto.randomUUID());
      await next();
    })

    // CSRF guard on every state-changing method under /api/v1.
    .on(['POST', 'PATCH', 'PUT', 'DELETE'], `${API_BASE_PATH}/*`, sameOriginOnly)

    // Body-size cap on the JSON write/read endpoints (defense-in-depth DoS).
    .use(`${API_BASE_PATH}/ingest`, jsonBodyLimit)
    .use(`${API_BASE_PATH}/retrieve`, jsonBodyLimit)
    .use(`${API_BASE_PATH}/mcp`, jsonBodyLimit)
    .use(`${API_BASE_PATH}/records/:id/status`, jsonBodyLimit)

    // better-auth owns everything under /api/auth/*, outside the versioned tree.
    .on(['POST', 'GET'], '/api/auth/*', (c) => auth.handler(c.req.raw))

    // Every other route — HTTP + the MCP doorway — lives under /api/v1.
    .route(API_BASE_PATH, appRoutes)

    .onError((error, c) => {
      console.error(error);
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    });

  return app;
};

/** Route types for the whole app. RPC clients use `Client` from `./hc` instead,
 * which is typed on the versioned sub-app alone. */
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
