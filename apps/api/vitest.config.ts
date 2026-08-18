import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The unit tests exercise the route PROGRAMS with test doubles — no real DB,
    // TEI server, or mail provider is touched.
    include: ['src/**/*.unit.test.ts'],
    env: {
      NODE_ENV: 'test',
      // `lib/auth` throws at import if this is unset (an unset secret makes
      // better-auth sign sessions with a well-known default). Supply a dummy so
      // importing the auth-dependent handlers under test does not throw.
      BETTER_AUTH_SECRET: 'test-secret-not-used-for-real-signing',
      // pg's Pool is lazy, but keep a placeholder so nothing reads an empty URL.
      DATABASE_URL: 'postgres://test:test@localhost:5432/test'
    }
  }
});
