import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import type { SqlError } from '@effect/sql/SqlError';
import { and, countDistinct, eq, gt, max, sql, type InferSelectModel } from 'drizzle-orm';
import { Context, Effect, Layer } from 'effect';
import { DrizzleLive, DBNotFoundError } from '../effect-db';
import { apikey, session, user } from '../schema';

export type User = InferSelectModel<typeof user>;

/**
 * One row of the admin user directory: the account plus the three aggregates
 * the console shows next to it.
 *
 * `lastSeen` is derived from api-key usage rather than session activity on
 * purpose — an account's agents are what actually exercise bit, and a stale
 * browser session says nothing about whether anyone is using the corpus.
 */
export type AdminUserRow = {
  id: string;
  name: string;
  email: string;
  role: string | null;
  banned: boolean | null;
  banReason: string | null;
  banExpires: Date | null;
  createdAt: Date;
  /** Sessions that have not yet expired. Revoked sessions are deleted. */
  activeSessions: number;
  /** Usable api keys. bit's contract caps this at one, so it reads as 0 or 1. */
  apiKeys: number;
  /** Most recent api-key request across the account's keys; null if never used. */
  lastSeen: Date | null;
};

export class UserRepo extends Context.Tag('@repo/db/UserRepo')<
  UserRepo,
  {
    findById: (id: string) => Effect.Effect<User, SqlError | DBNotFoundError>;
    findByEmail: (email: string) => Effect.Effect<User, SqlError | DBNotFoundError>;
    /** Every account with its session/key aggregates, newest first. */
    listForAdmin: () => Effect.Effect<ReadonlyArray<AdminUserRow>, SqlError>;
  }
>() {}

export const UserRepoLive = Layer.effect(
  UserRepo,
  Effect.gen(function* () {
    const db = yield* PgDrizzle.PgDrizzle;

    return {
      findById: (id) =>
        db
          .select()
          .from(user)
          .where(eq(user.id, id))
          .limit(1)
          .pipe(
            Effect.flatMap((rows) => {
              if (rows[0]) {
                return Effect.succeed(rows[0]);
              }
              return Effect.fail(new DBNotFoundError({ entity: 'user', value: id }));
            })
          ),
      // Both aggregates come off one query, so the joins fan out against each
      // other (a user with 2 sessions and 1 key yields 2 rows). countDistinct
      // is what keeps the counts honest — a plain count would multiply them.
      listForAdmin: () =>
        db
          .select({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            banned: user.banned,
            banReason: user.banReason,
            banExpires: user.banExpires,
            createdAt: user.createdAt,
            activeSessions: countDistinct(session.id),
            apiKeys: countDistinct(apikey.id),
            lastSeen: max(apikey.lastRequest)
          })
          .from(user)
          // `expires_at` is `timestamp WITHOUT time zone` holding a UTC wall
          // clock, while `now()` is `timestamptz` — comparing them directly
          // makes Postgres convert using the SERVER's TimeZone GUC, so on a
          // non-UTC database sessions would expire hours early or late. Compare
          // against UTC explicitly so the result never depends on server config.
          .leftJoin(
            session,
            and(eq(session.userId, user.id), gt(session.expiresAt, sql`(now() at time zone 'utc')`))
          )
          .leftJoin(apikey, and(eq(apikey.referenceId, user.id), eq(apikey.enabled, true)))
          .groupBy(user.id)
          .orderBy(sql`${user.createdAt} desc`),
      findByEmail: (email) =>
        db
          .select()
          .from(user)
          .where(eq(user.email, email.toLowerCase()))
          .limit(1)
          .pipe(
            Effect.flatMap((rows) => {
              if (rows[0]) {
                return Effect.succeed(rows[0]);
              }
              return Effect.fail(new DBNotFoundError({ entity: 'user', value: email.toLowerCase() }));
            })
          )
    };
  })
);

export const UserRepoDefault = UserRepoLive.pipe(Layer.provide(DrizzleLive));

export const makeUserRepoTest = (implementation: Context.Tag.Service<UserRepo>) =>
  Layer.succeed(UserRepo, implementation);
