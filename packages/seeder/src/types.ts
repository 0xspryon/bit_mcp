import type { NodePgQueryResultHKT } from 'drizzle-orm/node-postgres';
import type { PgDatabase } from 'drizzle-orm/pg-core';
import type * as schema from '@repo/db/schema';

/** Accepts both the root database handle and the per-seed transaction. */
export type SeederDb = PgDatabase<NodePgQueryResultHKT, typeof schema>;

export interface Seed {
  /**
   * Stable ordered id in the form `NNNN_description`. Applied seeds are
   * recorded under this name in `drizzle_bit.__seeds_applied`, so never
   * rename or delete a seed once it has run anywhere.
   */
  readonly name: string;
  readonly run: (db: SeederDb) => Promise<void>;
}
