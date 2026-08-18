import { defineConfig } from 'vitest/config';

/**
 * Integration test project. Kept SEPARATE from `vitest.config.ts` (unit) so the
 * fast unit run (`bun run test`) never boots Docker. This config:
 *  - matches only `*.integration.test.ts`,
 *  - boots the shared testcontainers Postgres (+ optional TEI) once via
 *    `globalSetup`,
 *  - runs files serially (a single shared DB) with a long timeout.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.integration.test.ts'],
    globalSetup: ['src/integration/support/global-setup.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 600_000,
    env: {
      NODE_ENV: 'test',
      // `lib/auth` throws at import if this is unset.
      BETTER_AUTH_SECRET: 'test-secret-not-used-for-real-signing',
      // The health handler + config reads need these present (values are only
      // used verbatim; the fake-embedder suites never call the endpoint).
      EMBEDDING_DIM: '1024',
      EMBEDDING_ENDPOINT: 'http://tei-embeddings.invalid',
      RERANK_ENDPOINT: 'http://tei-reranker.invalid',
      // Placeholder; each suite overrides process.env.DATABASE_URL with the
      // container URI before building its runtime.
      DATABASE_URL: 'postgres://test:test@localhost:5432/test'
    }
  }
});
