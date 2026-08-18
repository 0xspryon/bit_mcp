import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import type { SqlError } from '@effect/sql/SqlError';
import { eq, type InferSelectModel } from 'drizzle-orm';
import { Context, Effect, Layer, Option } from 'effect';
import { DrizzleLive } from '../effect-db';
import { sources } from '../schema';

export type SourceRow = InferSelectModel<typeof sources>;

export class SourceRepo extends Context.Tag('@repo/db/SourceRepo')<
  SourceRepo,
  {
    /** INSERT ... ON CONFLICT (url) DO UPDATE, resolving the row id. */
    upsertByUrl: (
      url: string,
      title: string | null,
      qualityTier: number,
      kind: string | null
    ) => Effect.Effect<string, SqlError>;
    getById: (id: string) => Effect.Effect<Option.Option<SourceRow>, SqlError>;
  }
>() {}

export const SourceRepoLive = Layer.effect(
  SourceRepo,
  Effect.gen(function* () {
    const db = yield* PgDrizzle.PgDrizzle;

    return {
      upsertByUrl: (url, title, qualityTier, kind) =>
        db
          .insert(sources)
          .values({ url, title, qualityTier, kind })
          .onConflictDoUpdate({
            target: sources.url,
            set: { title, qualityTier, kind }
          })
          .returning({ id: sources.id })
          .pipe(
            Effect.flatMap((rows) => {
              const created = rows[0];
              if (!created) {
                return Effect.dieMessage('source upsert returned no id');
              }
              return Effect.succeed(created.id);
            })
          ),
      getById: (id) =>
        db
          .select()
          .from(sources)
          .where(eq(sources.id, id))
          .limit(1)
          .pipe(Effect.map((rows) => Option.fromNullable(rows[0])))
    };
  })
);

export const SourceRepoDefault = SourceRepoLive.pipe(Layer.provide(DrizzleLive));

export const makeSourceRepoTest = (implementation: Context.Tag.Service<SourceRepo>) =>
  Layer.succeed(SourceRepo, implementation);
