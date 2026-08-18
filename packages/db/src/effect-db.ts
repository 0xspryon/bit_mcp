import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import * as PgClient from '@effect/sql-pg/PgClient';
import type { SqlError } from '@effect/sql/SqlError';
import { Config, Data, Layer, Redacted } from 'effect';
import * as schema from './schema';

export const PgLive = PgClient.layerConfig({
  url: Config.string('DATABASE_URL').pipe(Config.map(Redacted.make)),
  // Bound the Effect connection pool (this is the primary app pool; the plain
  // pool in `db.ts` serves better-auth/seeder separately).
  maxConnections: Config.integer('DB_POOL_MAX').pipe(Config.withDefault(20))
});

// provideMerge (not provide) so SqlClient stays visible to repos — compound
// state transitions (inserting a record plus its record_sources rows) need
// SqlClient.withTransaction around multiple drizzle statements.
export const DrizzleLive = PgDrizzle.layerWithConfig({ schema } as never).pipe(
  Layer.provideMerge(PgLive)
);

export class DBNotFoundError extends Data.TaggedError('DBNotFoundError')<{
  entity: string;
  value: string;
}> {}

export type DbError = SqlError | DBNotFoundError;
