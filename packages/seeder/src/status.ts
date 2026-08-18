// Prints each registered seed with its applied/pending state.
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from '@repo/db/schema';
import { seeds } from './seeds/index';
import { appliedSeedNames, ensureTrackingTable } from './tracking';

const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? '' });
const db = drizzle(pool, { schema });

try {
  await ensureTrackingTable(db);
  const applied = await appliedSeedNames(db);
  for (const seed of seeds) {
    console.log(`${applied.has(seed.name) ? 'applied' : 'pending'}  ${seed.name}`);
  }
  const unknown = [...applied].filter((name) => !seeds.some((seed) => seed.name === name));
  for (const name of unknown) {
    console.log(`applied  ${name} (no longer in registry!)`);
  }
} finally {
  await pool.end();
}
