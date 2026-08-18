import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema';

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
