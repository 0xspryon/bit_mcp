import { RecordRepo, type RecordInsert, type RecordSourceUpsert } from '@repo/db';
import { Context, Data, Effect, Layer, Option } from 'effect';
import { contentHash } from './content-hash';
import { assertEmbeddingDim, EmbeddingService, type EmbedError } from './embedding';
import { decodeRecordInput, type RecordInputParseError } from './schema';

/**
 * `IngestService` — the write path.
 *
 * Validate -> hash -> dedup -> embed -> upsert sources -> insert record.
 * Dedup is by {@link contentHash}: an existing record short-circuits before
 * any embedding or insert happens.
 */

export interface IngestResult {
  readonly id: string;
  readonly deduped: boolean;
  readonly status: string;
}

/** Repo/SQL failures, re-tagged so `IngestError` is a closed tagged union. */
export class IngestRepoError extends Data.TaggedError('IngestRepoError')<{
  readonly reason: string;
  readonly cause: unknown;
}> {}

export type IngestError = RecordInputParseError | EmbedError | IngestRepoError;

export class IngestService extends Context.Tag('@repo/rag-core/IngestService')<
  IngestService,
  {
    readonly ingest: (input: unknown) => Effect.Effect<IngestResult, IngestError>;
  }
>() {}

export const IngestServiceLive = Layer.effect(
  IngestService,
  Effect.gen(function* () {
    const records = yield* RecordRepo;
    const embedding = yield* EmbeddingService;

    const ingest = (input: unknown): Effect.Effect<IngestResult, IngestError> =>
      Effect.gen(function* () {
        // 1. Validate.
        const record = yield* decodeRecordInput(input);

        // 2. Dedup key.
        const hash = contentHash({
          title: record.title,
          symptom: record.symptom,
          procedure: record.procedure
        });

        // 3. Dedup: an existing record short-circuits the embed + insert, but
        // still MERGES the incoming namespaces onto the existing row so a dedup
        // hit under a new vuln-class records that membership (no re-embed).
        const existing = yield* records
          .findByHash(hash)
          .pipe(Effect.mapError((cause) => new IngestRepoError({ reason: 'findByHash failed', cause })));
        if (Option.isSome(existing)) {
          yield* records
            .addNamespaces(existing.value.id, record.namespaces)
            .pipe(
              Effect.mapError((cause) => new IngestRepoError({ reason: 'addNamespaces failed', cause }))
            );
          return {
            id: existing.value.id,
            deduped: true,
            status: existing.value.status
          } satisfies IngestResult;
        }

        // 4. Embed the symptom + procedure, guard the dimension.
        const vec = yield* embedding
          .embed(`${record.symptom}\n${record.procedure}`)
          .pipe(Effect.flatMap(assertEmbeddingDim));

        // 5. Sources to upsert + link (deduped by url). The record insert is
        // atomic with these — see RecordRepo.insert.
        const uniqueSources: RecordSourceUpsert[] = [
          ...new Map(
            record.sources.map((s) => [
              s.url,
              { url: s.url, title: s.title ?? null, qualityTier: s.tier, kind: s.kind ?? null }
            ])
          ).values()
        ];

        // 6. Build the insert row. `embedding` is passed as number[] (drizzle's
        // vector value form). `fts`, `id`, `status` (defaults 'staging') and
        // timestamps are all omitted so the DB owns them.
        const row: RecordInsert = {
          namespaces: [...record.namespaces],
          title: record.title,
          symptom: record.symptom,
          procedure: record.procedure,
          whenToUse: record.whenToUse ?? null,
          confirmationSignal: record.confirmationSignal ?? null,
          preconditions: [...record.preconditions],
          appliesTo: [...record.appliesTo],
          cwe: [...record.cwe],
          vrt: [...record.vrt],
          chainsWith: [...record.chainsWith],
          qualityTier: record.qualityTier,
          contentHash: hash,
          embedding: Array.from(vec)
        };

        // 7. Atomic + idempotent insert. On a race/duplicate, `inserted` is
        // false and the existing row's status is returned.
        const result = yield* records
          .insert(row, uniqueSources)
          .pipe(Effect.mapError((cause) => new IngestRepoError({ reason: 'record insert failed', cause })));

        return {
          id: result.id,
          deduped: !result.inserted,
          status: result.status
        } satisfies IngestResult;
      });

    return { ingest };
  })
);

/** Test layer over injected repo + embedding layers (compose with make*Test). */
export const makeIngestServiceTest = (): Layer.Layer<
  IngestService,
  never,
  RecordRepo | EmbeddingService
> => IngestServiceLive;
