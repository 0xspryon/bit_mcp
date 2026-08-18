import { sql } from 'drizzle-orm';
import type { SeederDb } from './types';

// Same schema drizzle-kit uses for its migration journal (`drizzle_bit`, see
// packages/db/drizzle.config.ts), so all bookkeeping tables live together and
// never collide with the application `bit` schema.
export const ensureTrackingTable = async (db: SeederDb): Promise<void> => {
  await db.execute(sql`CREATE SCHEMA IF NOT EXISTS "drizzle_bit"`);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS "drizzle_bit"."__seeds_applied" (
      "name" text PRIMARY KEY,
      "applied_at" timestamp with time zone DEFAULT now() NOT NULL
    )
  `);
};

export const appliedSeedNames = async (db: SeederDb): Promise<ReadonlySet<string>> => {
  const result = await db.execute(sql`SELECT "name" FROM "drizzle_bit"."__seeds_applied"`);
  return new Set(result.rows.map((row) => String(row.name)));
};

export const recordApplied = async (db: SeederDb, name: string): Promise<void> => {
  await db.execute(sql`INSERT INTO "drizzle_bit"."__seeds_applied" ("name") VALUES (${name})`);
};
