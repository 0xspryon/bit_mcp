import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema';
import { apikey } from './schema';

/**
 * Plain (non-Effect) Drizzle handle over a bounded `pg.Pool`.
 *
 * This is a SECOND pool, separate from the Effect `@effect/sql-pg` pool in
 * `effect-db.ts`. It exists because better-auth's `drizzleAdapter` needs a
 * synchronous Drizzle instance and cannot consume the Effect-managed client;
 * the seeder uses it too. Both pools are intentionally bounded, and both are
 * disposed on graceful shutdown (see `apps/api/src/index.ts`).
 */
const databaseUrl = process.env.DATABASE_URL ?? '';

const pool = new Pool({
  connectionString: databaseUrl,
  max: 10
});

export const db = drizzle(pool, { schema });

/** Close the plain pool (called on graceful shutdown). */
export const closePlainPool = (): Promise<void> => pool.end();

/**
 * Does this account already hold a usable API key?
 *
 * bit's contract is one key per account (see the connect-an-agent screen:
 * "you hold one key at a time"), which better-auth's api-key plugin does not
 * enforce on its own. The `/api-key/create` before-hook uses this to reject a
 * second key server-side, so the invariant does not depend on the UI.
 *
 * Uses the plain handle deliberately — better-auth writes api keys through
 * this same pool, so the check sees exactly what the plugin sees. Revoked keys
 * are deleted rather than disabled, but `enabled` is filtered anyway so a
 * disabled row can never block a fresh create.
 */
export const hasEnabledApiKey = async (userId: string): Promise<boolean> => {
  const rows = await db
    .select({ id: apikey.id })
    .from(apikey)
    .where(and(eq(apikey.referenceId, userId), eq(apikey.enabled, true)))
    .limit(1);
  return rows.length > 0;
};
