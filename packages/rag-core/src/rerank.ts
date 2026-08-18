import type { RecordReadRow } from '@repo/db';
import { rerankConfig } from '@repo/env';
import { Context, Data, Effect, Layer } from 'effect';

/**
 * `RerankService` — a cross-encoder that re-orders candidate records against a
 * query, best-first. Used as the final ordering step after RRF fusion.
 */

export interface Scored {
  readonly record: RecordReadRow;
  readonly score: number;
}

/** Per-request timeout for the TEI rerank call. */
const RERANK_TIMEOUT_MS = 20_000;

export class RerankError extends Data.TaggedError('RerankError')<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class RerankService extends Context.Tag('@repo/rag-core/RerankService')<
  RerankService,
  {
    readonly rerank: (
      query: string,
      docs: readonly RecordReadRow[]
    ) => Effect.Effect<Scored[], RerankError>;
  }
>() {}

/** The text a reranker scores for a record: the human-readable fields. */
const docText = (d: RecordReadRow): string => `${d.title}\n${d.symptom}\n${d.procedure}`;

/** One entry of a TEI reranker `/rerank` response. */
interface TeiRerankEntry {
  readonly index: number;
  readonly score: number;
}

const isRerankEntry = (value: unknown): value is TeiRerankEntry =>
  typeof value === 'object' &&
  value !== null &&
  typeof (value as { index?: unknown }).index === 'number' &&
  typeof (value as { score?: unknown }).score === 'number' &&
  Number.isFinite((value as { score: number }).score);

/**
 * Live impl backed by a TEI reranker. POSTs
 * `{ query, texts, raw_scores: false }` to `${endpoint}/rerank`, expects
 * `[{ index, score }]`, maps each result back to its record via `index`
 * (bounds-guarded), and returns them sorted by score descending.
 */
export const RerankServiceLive = Layer.effect(
  RerankService,
  Effect.gen(function* () {
    const config = yield* rerankConfig;
    return {
      rerank: (query, docs) => {
        if (docs.length === 0) {
          return Effect.succeed<Scored[]>([]);
        }
        return Effect.tryPromise({
          try: async (): Promise<unknown> => {
            const response = await fetch(`${config.endpoint}/rerank`, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                query,
                texts: docs.map(docText),
                raw_scores: false
              }),
              // Bound the request so a hung reranker can't stall retrieval; a
              // timeout aborts and surfaces as RerankError.
              signal: AbortSignal.timeout(RERANK_TIMEOUT_MS)
            });
            if (!response.ok) {
              throw new Error(`TEI /rerank responded ${response.status} ${response.statusText}`);
            }
            return await response.json();
          },
          catch: (cause) => new RerankError({ reason: 'rerank request failed', cause })
        }).pipe(
          // The response is untrusted: a non-array body, wrong length, malformed
          // entry, non-finite score, or an out-of-range/duplicate index all
          // surface as a typed RerankError rather than being silently dropped
          // (which would quietly change the ranking) or thrown as a defect.
          Effect.flatMap((body) => {
            if (!Array.isArray(body)) {
              return Effect.fail(new RerankError({ reason: 'TEI /rerank returned a non-array body' }));
            }
            if (body.length !== docs.length) {
              return Effect.fail(
                new RerankError({
                  reason: `TEI /rerank returned ${body.length} entries for ${docs.length} documents`
                })
              );
            }
            const scored: Scored[] = [];
            const seen = new Set<number>();
            for (const entry of body) {
              if (!isRerankEntry(entry)) {
                return Effect.fail(new RerankError({ reason: 'TEI /rerank returned a malformed entry' }));
              }
              const { index, score } = entry;
              if (!Number.isInteger(index) || index < 0 || index >= docs.length) {
                return Effect.fail(
                  new RerankError({ reason: `TEI /rerank returned an out-of-range index ${index}` })
                );
              }
              if (seen.has(index)) {
                return Effect.fail(
                  new RerankError({ reason: `TEI /rerank returned a duplicate index ${index}` })
                );
              }
              seen.add(index);
              const record = docs[index];
              if (record === undefined) {
                return Effect.fail(
                  new RerankError({ reason: `TEI /rerank index ${index} is out of bounds` })
                );
              }
              scored.push({ record, score });
            }
            return Effect.succeed(scored.sort((a, b) => b.score - a.score));
          })
        );
      }
    };
  })
);

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

const tokenize = (s: string): string[] =>
  s
    .toLowerCase()
    .split(/\W+/)
    .filter((t) => t.length > 0);

/**
 * Deterministic fake reranker: scores each doc by lexical overlap — the count
 * of query tokens present in `${title} ${symptom} ${procedure} ${whenToUse}`.
 * Sorted descending, stable for equal scores. Pass `overrides.rerank` to
 * inject custom scoring.
 */
export const makeRerankServiceTest = (overrides?: {
  rerank?: (query: string, docs: readonly RecordReadRow[]) => Effect.Effect<Scored[], RerankError>;
}): Layer.Layer<RerankService> =>
  Layer.succeed(RerankService, {
    rerank:
      overrides?.rerank ??
      ((query, docs) => {
        const queryTokens = new Set(tokenize(query));
        const scored = docs.map((record, index) => {
          const haystack = new Set(
            tokenize(
              `${record.title} ${record.symptom} ${record.procedure} ${record.whenToUse ?? ''}`
            )
          );
          let score = 0;
          for (const token of queryTokens) {
            if (haystack.has(token)) score += 1;
          }
          return { record, score, index };
        });
        // Stable sort: higher score first, original order for ties.
        scored.sort((a, b) => (b.score !== a.score ? b.score - a.score : a.index - b.index));
        return Effect.succeed(scored.map(({ record, score }) => ({ record, score })));
      })
  });
