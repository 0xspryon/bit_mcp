import { RecordRepo, type Filter, type RecordReadRow } from '@repo/db';
import { Context, Data, Effect, Layer } from 'effect';
import { EmbeddingService, type EmbedError } from './embedding';
import { RerankService, type RerankError } from './rerank';
import { reciprocalRankFusion } from './rrf';
import {
  decodeRetrieveQuery,
  type Chunk,
  type RetrievalResult,
  type RetrieveQueryParseError
} from './schema';

/**
 * `RetrieverService` — the read path.
 *
 * Validate -> hard filter (status:'active' + namespace/filters) -> hybrid
 * candidate gen (dense ∥ lexical) -> RRF fuse -> rerank -> top-k -> hydrate
 * sources -> Chunk[]. Filters are correctness (a namespaced query must never
 * leak another namespace), not ranking.
 *
 * The result carries `diagnostics` alongside the chunks because the dense leg
 * can silently return fewer candidates than requested: its filters are applied
 * as POST-filters on an approximate index scan, so a selective filter starves
 * the walk before `CANDIDATE_K` survivors accumulate. RRF then fuses a short
 * dense list with a full lexical one and the shortfall becomes invisible in the
 * output. Reporting the per-leg counts is what makes it visible — see
 * `RetrievalDiagnostics` in ./schema and `RecordRepo.nearest` for the mechanism.
 */

// Fan-out widths, per the read-path brief.
const CANDIDATE_K = 30; // per-leg candidate pool
const FUSED_K = 20; // survivors handed to the reranker

export class RetrievalRepoError extends Data.TaggedError('RetrievalRepoError')<{
  readonly reason: string;
  readonly cause: unknown;
}> {}

export type RetrievalError =
  | RetrieveQueryParseError
  | EmbedError
  | RerankError
  | RetrievalRepoError;

export class RetrieverService extends Context.Tag('@repo/rag-core/RetrieverService')<
  RetrieverService,
  {
    readonly retrieve: (query: unknown) => Effect.Effect<RetrievalResult, RetrievalError>;
  }
>() {}

export const RetrieverServiceLive = Layer.effect(
  RetrieverService,
  Effect.gen(function* () {
    const records = yield* RecordRepo;
    const embedding = yield* EmbeddingService;
    const reranker = yield* RerankService;

    const retrieve = (input: unknown): Effect.Effect<RetrievalResult, RetrievalError> =>
      Effect.gen(function* () {
        // 1. Validate.
        const q = yield* decodeRetrieveQuery(input);

        // 2. Build the HARD filter. status is always 'active'.
        const f = q.filters;
        const filter: Filter = {
          status: 'active',
          ...(q.namespaces !== undefined && q.namespaces.length > 0
            ? { namespaces: q.namespaces }
            : {}),
          ...(f?.cwe !== undefined ? { cwe: f.cwe } : {}),
          ...(f?.product !== undefined ? { product: f.product } : {}),
          ...(f?.minTier !== undefined ? { minTier: f.minTier } : {})
        };

        // 3. Hybrid candidate generation, in parallel.
        const denseLeg = embedding
          .embed(q.query)
          .pipe(
            Effect.flatMap((vec) =>
              records
                .nearest(vec, filter, CANDIDATE_K)
                .pipe(Effect.mapError((cause) => new RetrievalRepoError({ reason: 'nearest failed', cause })))
            )
          );
        const lexicalLeg = records
          .lexical(q.query, filter, CANDIDATE_K)
          .pipe(Effect.mapError((cause) => new RetrievalRepoError({ reason: 'lexical failed', cause })));

        const [denseRows, lexicalRows] = yield* Effect.all([denseLeg, lexicalLeg], {
          concurrency: 'unbounded'
        });

        // 3b. Record what each leg actually produced BEFORE fusion collapses
        // the two lists into one. After RRF there is no way to tell a short
        // dense leg from a dense leg that simply agreed with the lexical one.
        const diagnostics = {
          semantic_search_k: CANDIDATE_K,
          semantic_search_count: denseRows.length,
          semantic_search_degraded: denseRows.length < CANDIDATE_K,
          lexical_search_k: CANDIDATE_K,
          lexical_search_count: lexicalRows.length
        };

        // 4. Fuse and take the top FUSED_K.
        const fused = reciprocalRankFusion<RecordReadRow>(
          [denseRows, lexicalRows],
          (r) => r.id
        )
          .slice(0, FUSED_K)
          .map((entry) => entry.item);

        // 5. Rerank and take top-k.
        const reranked = yield* reranker.rerank(q.query, fused);
        const topK = reranked.slice(0, q.k);

        // 6. Hydrate sources and build Chunks (snake_case output contract).
        const ids = topK.map((s) => s.record.id);
        const sourcesByRecord = yield* records
          .sourcesFor(ids)
          .pipe(Effect.mapError((cause) => new RetrievalRepoError({ reason: 'sourcesFor failed', cause })));

        const chunks = topK.map(({ record, score }): Chunk => {
          const sources = (sourcesByRecord.get(record.id) ?? []).map((src) => ({
            url: src.url,
            title: src.title,
            tier: src.tier
          }));
          return {
            id: record.id,
            title: record.title,
            namespaces: record.namespaces,
            procedure: record.procedure,
            confirmation_signal: record.confirmationSignal ?? null,
            chains_with: record.chainsWith,
            sources,
            quality_tier: record.qualityTier,
            score,
            kind: 'methodology'
          };
        });

        return { chunks, diagnostics };
      });

    return { retrieve };
  })
);

/** Test layer over injected repo + embedding + rerank layers. */
export const makeRetrieverServiceTest = (): Layer.Layer<
  RetrieverService,
  never,
  RecordRepo | EmbeddingService | RerankService
> => RetrieverServiceLive;
