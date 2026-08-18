import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import type { SqlError } from '@effect/sql/SqlError';
import { eq, type InferSelectModel } from 'drizzle-orm';
import { Context, Effect, Layer } from 'effect';
import { DrizzleLive, DBNotFoundError } from '../effect-db';
import { user } from '../schema';

export type User = InferSelectModel<typeof user>;

export class UserRepo extends Context.Tag('@repo/db/UserRepo')<
  UserRepo,
  {
    findById: (id: string) => Effect.Effect<User, SqlError | DBNotFoundError>;
    findByEmail: (email: string) => Effect.Effect<User, SqlError | DBNotFoundError>;
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
