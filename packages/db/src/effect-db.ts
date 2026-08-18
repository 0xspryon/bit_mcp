import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import * as PgClient from '@effect/sql-pg/PgClient';
import { types as pgTypes } from 'pg';
import type { SqlError } from '@effect/sql/SqlError';
import { Config, Data, Layer, Redacted } from 'effect';
import * as schema from './schema';

/**
 * Postgres OIDs for the naive date/time types: `timestamp`, `timestamptz`,
 * `date`. better-auth's tables use `timestamp without time zone` and store a
 * UTC wall clock in them.
 */
const TIMESTAMP_OIDS = [1114, 1184, 1082];

/**
 * Hand naive timestamps to drizzle as STRINGS, not `Date`s.
 *
 * `pg` bundles pg-types@2.2.0, whose default parser for OID 1114 builds a Date
 * in the PROCESS's local timezone — so a row stored as `09:41` reads back as
 * `07:41Z` on a UTC+2 host. drizzle's own `PgTimestamp.mapFromDriverValue`
 * appends `+0000` and gets it right, but only ever sees a string; once pg has
 * already produced a Date, that correction never runs and the shift is silent.
 *
 * The plain `node-postgres` pool in `db.ts` (which better-auth writes through)
 * takes the string path already, so without this the reader and the writer
 * disagree about what a stored timestamp means. Verified: pg-types@2.2.0 with
 * TZ=Europe/Berlin turns '2026-08-18 09:41:00' into 2026-08-18T07:41:00.000Z.
 */
const timestampAsString = {
  // Delegate through `pg`'s own `types` export rather than importing pg-types
  // directly — that guarantees the fallback for every other OID is exactly the
  // parser this pg instance would have used.
  getTypeParser: ((oid: number, format?: unknown) =>
    TIMESTAMP_OIDS.includes(oid)
      ? (value: string) => value
      : (pgTypes.getTypeParser as (o: number, f?: unknown) => unknown)(
          oid,
          format
        )) as typeof pgTypes.getTypeParser
};

export const PgLive = PgClient.layerConfig({
  url: Config.string('DATABASE_URL').pipe(Config.map(Redacted.make)),
  // Bound the Effect connection pool (this is the primary app pool; the plain
  // pool in `db.ts` serves better-auth/seeder separately).
  maxConnections: Config.integer('DB_POOL_MAX').pipe(Config.withDefault(20)),
  types: Config.succeed(timestampAsString)
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
