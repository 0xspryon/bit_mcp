import { Layer, ManagedRuntime } from 'effect';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { AppRuntime } from '../app-env';

const dockerAvailable = inject('dockerAvailable');
const databaseUrl = inject('databaseUrl');

// MUST run before anything imports `@repo/db`: its plain pool — the one
// better-auth writes through — captures DATABASE_URL at module load, unlike
// the Effect layers which read it through `Config` at build time. Every other
// suite gets away with static imports only because none of them exercise real
// better-auth. Hence the dynamic imports throughout this file.
if (dockerAvailable) {
  process.env.DATABASE_URL = databaseUrl;
  process.env.EMBEDDING_DIM = '1024';
}

/** Deferred import so `lib/auth` binds to the container DATABASE_URL. */
const makeApp = async (runtime: AppRuntime) => {
  const { createApp } = await import('../index');
  return createApp(runtime);
};

/**
 * The API-key doorway, end to end, with NO auth doubles.
 *
 * Every other suite substitutes `makeAuthServiceTest`, which is precisely why
 * this path went unverified: the api-key plugin authenticates STATELESSLY and
 * synthesizes an in-memory session whose id is the APIKEY row's id, so the
 * `session` table lookup inside `authenticate()` necessarily misses. Treating
 * that miss as `UnauthorizedError` 401'd every agent request to the MCP
 * doorway — the product's primary path.
 *
 * This suite therefore wires the REAL `AuthServiceLive` and the REAL
 * User/Session repos over the testcontainers Postgres, mints a genuine key
 * through better-auth, and drives `POST /api/v1/mcp` with it.
 */

describe.skipIf(!dockerAvailable)('API-key auth e2e', () => {
  let runtime: AppRuntime;
  let pool: Pool;
  let app: Awaited<ReturnType<typeof makeApp>>;
  let userKey = '';
  const userId = 'apikey-user-1';

  const callTool = async (key: string | null, name: string) => {
    const res = (await app.request('/api/v1/mcp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(key ? { 'x-api-key': key } : {})
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name, arguments: { query: 'sql injection login', namespaces: ['acme'], k: 3 } }
      })
    })) as Response;
    return (await res.json()) as {
      result?: Record<string, unknown>;
      error?: { code: number; message: string; data?: unknown };
    };
  };

  beforeAll(async () => {
    const { makeAdminPool, truncateCorpus } = await import('./support/harness');
    pool = makeAdminPool(databaseUrl);
    await truncateCorpus(pool);
    await pool.query('DELETE FROM "bit"."apikey"');
    await pool.query('DELETE FROM "bit"."session"');
    await pool.query('DELETE FROM "bit"."user"');
    // A plain `user`: role `user` grants record:['read'] but not ingest, so the
    // two tools below exercise both the allow and the deny path.
    await pool.query(
      `INSERT INTO "bit"."user" (id, name, email, email_verified, role, created_at, updated_at)
       VALUES ($1, 'nyx_operator', 'nyx@example.com', true, 'user', now(), now())`,
      [userId]
    );

    const { auth } = await import('../lib/auth');
    const created = await auth.api.createApiKey({
      body: { userId, name: 'integration' }
    });
    userKey = (created as unknown as { key: string }).key;

    const { makeEmbeddingServiceTest, makeRerankServiceTest, IngestServiceLive, RetrieverServiceLive } =
      await import('@repo/rag-core');
    const { RecordRepoDefault, SessionRepoDefault, SourceRepoDefault, UserRepoDefault } =
      await import('@repo/db');
    const embedding = makeEmbeddingServiceTest();
    const rerank = makeRerankServiceTest();
    const dbInfra = Layer.mergeAll(RecordRepoDefault, SourceRepoDefault);
    const deps = Layer.mergeAll(dbInfra, embedding, rerank);

    // The whole point: real auth, real user/session repos.
    const { AuthServiceLive } = await import('../lib/effect-auth');
    const layer = Layer.mergeAll(
      AuthServiceLive,
      UserRepoDefault,
      SessionRepoDefault,
      dbInfra,
      embedding,
      rerank,
      RetrieverServiceLive.pipe(Layer.provide(deps)),
      IngestServiceLive.pipe(Layer.provide(deps))
    );
    runtime = ManagedRuntime.make(layer) as unknown as AppRuntime;

    app = await makeApp(runtime);
  });

  afterAll(async () => {
    await pool.end();
    await runtime.dispose();
  });

  it('mints a key whose secret is returned once', () => {
    expect(userKey).toMatch(/^.{10,}$/);
  });

  /**
   * The regression. Before the fix this returned the Unauthorized JSON-RPC
   * error because `authenticate()` demanded a `session` row that an api-key
   * caller never has.
   */
  it('authenticates an x-api-key caller against the MCP doorway', async () => {
    const body = await callTool(userKey, 'bit_retrieve');
    expect(body.error).toBeUndefined();
    expect(body.result).toBeDefined();
  });

  it('still rejects a request with no key at all', async () => {
    const body = await callTool(null, 'bit_retrieve');
    expect(body.error).toBeDefined();
    expect(body.error?.message).toMatch(/Authentication is required/i);
  });

  it('still rejects a bogus key', async () => {
    const body = await callTool('bit_sk_not_a_real_key_at_all_0000', 'bit_retrieve');
    expect(body.error).toBeDefined();
    expect(body.result).toBeUndefined();
  });

  /**
   * Authorization must keep working off the live user role, NOT the session:
   * a `user` holds record:['read'] but not record:['ingest'].
   */
  it('still enforces per-role permissions for an x-api-key caller', async () => {
    const body = await callTool(userKey, 'bit_ingest');
    expect(body.error).toBeDefined();
    expect(body.error?.message).toMatch(/permission/i);
  });
});
