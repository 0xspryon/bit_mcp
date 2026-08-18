import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import type { SqlError } from '@effect/sql/SqlError';
import { eq, type InferSelectModel } from 'drizzle-orm';
import { Context, Effect, Layer } from 'effect';
import { DrizzleLive, DBNotFoundError } from '../effect-db';
import { session } from '../schema';

export type Session = InferSelectModel<typeof session>;

export class SessionRepo extends Context.Tag('@repo/db/SessionRepo')<
  SessionRepo,
  {
    findById: (id: string) => Effect.Effect<Session, SqlError | DBNotFoundError>;
  }
>() {}

export const SessionRepoLive = Layer.effect(
  SessionRepo,
  Effect.gen(function* () {
    const db = yield* PgDrizzle.PgDrizzle;

    return {
      findById: (id) =>
        db
          .select()
          .from(session)
          .where(eq(session.id, id))
          .limit(1)
          .pipe(
            Effect.flatMap((rows) => {
              if (rows[0]) {
                return Effect.succeed(rows[0]);
              }
              return Effect.fail(new DBNotFoundError({ entity: 'session', value: id }));
            })
          )
    };
  })
);

export const SessionRepoDefault = SessionRepoLive.pipe(Layer.provide(DrizzleLive));

export const makeSessionRepoTest = (implementation: Context.Tag.Service<SessionRepo>) =>
  Layer.succeed(SessionRepo, implementation);
