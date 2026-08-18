import { embeddingConfig, EMBEDDING_DIM } from '@repo/env';
import { Context, Data, Effect, Layer } from 'effect';
import { normalize } from './content-hash';

/**
 * `EmbeddingService` — turns text into a dense vector.
 *
 * The resolved vector length MUST equal {@link EMBEDDING_DIM} (1024, the store
 * column width). A wrong length is a hard failure, not a silent corruption of
 * the index, so every path routes through {@link assertEmbeddingDim}.
 */

/** Per-request timeout for the TEI embed call. */
const EMBED_TIMEOUT_MS = 15_000;

export class EmbedError extends Data.TaggedError('EmbedError')<{
  readonly reason: string;
  readonly cause?: unknown;
}> {}

export class EmbeddingService extends Context.Tag('@repo/rag-core/EmbeddingService')<
  EmbeddingService,
  {
    readonly embed: (text: string) => Effect.Effect<Float32Array, EmbedError>;
  }
>() {}

/** Guard used by both the live impl and the ingest path: fail unless the
 * vector has exactly {@link EMBEDDING_DIM} elements. */
export const assertEmbeddingDim = (vec: Float32Array): Effect.Effect<Float32Array, EmbedError> =>
  vec.length === EMBEDDING_DIM
    ? Effect.succeed(vec)
    : Effect.fail(
        new EmbedError({
          reason: `embedding must have ${EMBEDDING_DIM} dimensions; got ${vec.length}`
        })
      );

/** Validate an untrusted TEI row into a finite-valued vector of the right
 * dimension. A malformed shape, a non-number, or a `NaN`/`Infinity` element
 * (which would silently corrupt cosine ordering) becomes a typed `EmbedError`
 * rather than being trusted. */
const toFiniteVector = (row: unknown): Effect.Effect<Float32Array, EmbedError> => {
  if (!Array.isArray(row)) {
    return Effect.fail(new EmbedError({ reason: 'TEI /embed row is not an array' }));
  }
  const vec = new Float32Array(row.length);
  for (let i = 0; i < row.length; i++) {
    const value: unknown = row[i];
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return Effect.fail(
        new EmbedError({ reason: `TEI /embed returned a non-finite value at index ${i}` })
      );
    }
    vec[i] = value;
  }
  return assertEmbeddingDim(vec);
};

/**
 * Live impl backed by a TEI server. POSTs `{ inputs, normalize: true }` to
 * `${endpoint}/embed`, expects `number[][]`, then validates row 0 into a
 * finite-valued vector of dimension {@link EMBEDDING_DIM}.
 */
export const EmbeddingServiceLive = Layer.effect(
  EmbeddingService,
  Effect.gen(function* () {
    const config = yield* embeddingConfig;
    return {
      embed: (text) =>
        Effect.tryPromise({
          try: async (): Promise<unknown> => {
            const response = await fetch(`${config.endpoint}/embed`, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ inputs: text, normalize: true }),
              // Bound the request so a hung TEI can't stall a retrieval/ingest
              // indefinitely; a timeout aborts and surfaces as EmbedError.
              signal: AbortSignal.timeout(EMBED_TIMEOUT_MS)
            });
            if (!response.ok) {
              throw new Error(`TEI /embed responded ${response.status} ${response.statusText}`);
            }
            return await response.json();
          },
          catch: (cause) => new EmbedError({ reason: 'embedding request failed', cause })
        }).pipe(
          Effect.flatMap((body) => {
            if (!Array.isArray(body)) {
              return Effect.fail(new EmbedError({ reason: 'TEI /embed returned a non-array body' }));
            }
            const first: unknown = body[0];
            if (first === undefined) {
              return Effect.fail(new EmbedError({ reason: 'TEI /embed returned no embedding row' }));
            }
            return toFiniteVector(first);
          })
        )
    };
  })
);

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/** mulberry32 PRNG — deterministic, seeded by a 32-bit integer. */
const mulberry32 = (seed: number): (() => number) => {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/** Simple deterministic 32-bit string hash (FNV-1a-ish) over normalized text. */
const hashSeed = (text: string): number => {
  const s = normalize(text);
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
};

/** Deterministic fake embed: equal text -> equal L2-normalized 1024-vector. */
const fakeEmbed = (text: string): Float32Array => {
  const rng = mulberry32(hashSeed(text));
  const vec = new Float32Array(EMBEDDING_DIM);
  let norm = 0;
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    const v = rng() * 2 - 1;
    vec[i] = v;
    norm += v * v;
  }
  const inv = norm > 0 ? 1 / Math.sqrt(norm) : 0;
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    vec[i] = (vec[i] ?? 0) * inv;
  }
  return vec;
};

/**
 * In-memory test layer. By default produces a deterministic, L2-normalized
 * length-1024 vector seeded from the normalized text. Pass `overrides.embed`
 * to inject custom geometry (e.g. a non-1024 vector to exercise the guard).
 * The default still routes through {@link assertEmbeddingDim} so a bad custom
 * function surfaces the same `EmbedError` the live impl would.
 */
export const makeEmbeddingServiceTest = (overrides?: {
  embed?: (text: string) => Effect.Effect<Float32Array, EmbedError>;
}): Layer.Layer<EmbeddingService> =>
  Layer.succeed(EmbeddingService, {
    embed:
      overrides?.embed ??
      ((text) => assertEmbeddingDim(fakeEmbed(text)))
  });
