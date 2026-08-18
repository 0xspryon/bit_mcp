// Applies all pending seeds and records each in drizzle_bit.__seeds_applied —
// the seeding counterpart of `db:migrate`. Each seed runs in a tracking
// transaction, but note the corpus seed ingests records on its own rag-core
// runtime/pool (each RecordRepo.insert is its own transaction), so those rows
// commit as they are inserted, independently of this tracking transaction. That
// is safe: re-runs dedup by content_hash and re-promote to `active`, and the
// whole flow is idempotent under the compose retry loop.
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from '@repo/db/schema';
import { selectPending } from './runner';
import { seeds } from './seeds/index';
import { appliedSeedNames, ensureTrackingTable, recordApplied } from './tracking';

const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? '' });
const db = drizzle(pool, { schema });

try {
  await ensureTrackingTable(db);
  const applied = await appliedSeedNames(db);
  const pending = selectPending(seeds, applied);

  for (const seed of pending) {
    await db.transaction(async (tx) => {
      await seed.run(tx);
      await recordApplied(tx, seed.name);
    });
    console.log(`seed applied: ${seed.name}`);
  }

  console.log(
    pending.length === 0
      ? `No pending seeds (${applied.size} already applied)`
      : `Applied ${pending.length} seed(s)`
  );
} finally {
  await pool.end();
}
