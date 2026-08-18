import { Data, Effect, ParseResult, Schema } from 'effect';

/**
 * Effect `Schema` definitions for the RAG core write- and read-paths.
 *
 * Every payload that crosses a doorway (HTTP / MCP) is validated with these
 * schemas before a service touches it. The schemas are the single source of
 * truth: the exported TypeScript types are *derived* from them
 * (`Schema.Schema.Type<...>`), never hand-written.
 *
 * Note the deliberate asymmetry between input and output shapes:
 *  - Inputs never carry an embedding. The API owns vector production; a
 *    caller-supplied embedding is never trusted, so there is no such field.
 *  - The retrieval output ({@link Chunk}) uses snake_case keys
 *    (`confirmation_signal`, `quality_tier`) to mirror the public JSON
 *    contract, even though `RecordRow` uses camelCase internally.
 */

// ---------------------------------------------------------------------------
// Size limits
//
// These bound each field so a single request can't store unbounded text, and —
// critically — so the embedded fields stay within the bge-m3 window (~8192
// tokens ≈ ~32k chars). `symptom` + `procedure` are what get embedded; their
// combined cap (8000 + 20000 = 28000 chars ≈ ~7000 tokens) leaves headroom so
// TEI never silently truncates the embedding input. Oversized input is
// REJECTED with a clear message rather than truncated.
// ---------------------------------------------------------------------------

export const LIMITS = {
  namespace: 128,
  sourceKind: 64,
  title: 300,
  symptom: 8000,
  procedure: 20000,
  text: 4000, // whenToUse, confirmationSignal
  product: 128,
  query: 8000,
  url: 2048,
  arrayItems: 32,
  preconditionItem: 500,
  tokenItem: 256, // appliesTo / vrt / chainsWith element
  cweMin: 1,
  cweMax: 2000
} as const;

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

/** A string that is trimmed on decode (so `" acme "` is stored as `"acme"` and
 * matches exact filters), required non-empty, and length-bounded. */
const NonEmptyBounded = (max: number, label: string) =>
  Schema.Trim.pipe(
    Schema.minLength(1, { message: () => `${label} must not be empty` }),
    Schema.maxLength(max, { message: () => `${label} must be at most ${max} characters` })
  );

/** An optional trimmed, length-bounded string. */
const OptionalBounded = (max: number, label: string) =>
  Schema.optional(
    Schema.Trim.pipe(
      Schema.maxLength(max, { message: () => `${label} must be at most ${max} characters` })
    )
  );

/** A trimmed http(s) URL, length-bounded. */
const isHttpUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};
const HttpUrl = Schema.Trim.pipe(
  Schema.minLength(1, { message: () => 'url must not be empty' }),
  Schema.maxLength(LIMITS.url, { message: () => `url must be at most ${LIMITS.url} characters` }),
  Schema.filter(isHttpUrl, { message: () => 'url must be a valid http(s) URL' })
);

/** A CWE identifier: a positive integer within a sane range. */
const Cwe = Schema.Int.pipe(Schema.between(LIMITS.cweMin, LIMITS.cweMax));

/** The namespaces a record belongs to (≥1 vuln-class). Each element is a
 * trimmed, non-empty, length-bounded string; the array itself is capped and
 * must carry at least one entry. Retrieval filters by array OVERLAP. */
const NamespacesArray = Schema.Array(NonEmptyBounded(LIMITS.namespace, 'namespaces')).pipe(
  Schema.minItems(1, { message: () => 'namespaces must have at least one entry' }),
  Schema.maxItems(LIMITS.arrayItems, {
    message: () => `namespaces must have at most ${LIMITS.arrayItems} items`
  })
);

/** A bounded array of trimmed, non-empty, length-capped tokens. */
const TokenArray = (itemMax: number, label: string) =>
  Schema.Array(NonEmptyBounded(itemMax, label)).pipe(
    Schema.maxItems(LIMITS.arrayItems, {
      message: () => `${label} must have at most ${LIMITS.arrayItems} items`
    })
  );

/** Integer quality tier, 1 (best) .. 5 (worst). */
const QualityTier = Schema.Int.pipe(Schema.between(1, 5));

// ---------------------------------------------------------------------------
// Write path — RecordInput
// ---------------------------------------------------------------------------

/** A bounded array of CWE ids. */
const CweArray = Schema.Array(Cwe).pipe(
  Schema.maxItems(LIMITS.arrayItems, {
    message: () => `cwe must have at most ${LIMITS.arrayItems} items`
  })
);

/** A source citation supplied alongside a record on the write path. */
export const SourceInput = Schema.Struct({
  url: HttpUrl,
  title: OptionalBounded(LIMITS.title, 'source title'),
  tier: Schema.optionalWith(QualityTier, { default: () => 3 }),
  kind: OptionalBounded(LIMITS.sourceKind, 'source kind')
});
export type SourceInput = Schema.Schema.Type<typeof SourceInput>;

/**
 * Caller-supplied structured methodology content. The API produces the vector
 * from this — there is intentionally NO embedding field here.
 */
export const RecordInput = Schema.Struct({
  namespaces: NamespacesArray,
  title: NonEmptyBounded(LIMITS.title, 'title'),
  symptom: NonEmptyBounded(LIMITS.symptom, 'symptom'),
  procedure: NonEmptyBounded(LIMITS.procedure, 'procedure'),
  whenToUse: OptionalBounded(LIMITS.text, 'whenToUse'),
  confirmationSignal: OptionalBounded(LIMITS.text, 'confirmationSignal'),
  preconditions: Schema.optionalWith(TokenArray(LIMITS.preconditionItem, 'preconditions'), {
    default: () => []
  }),
  appliesTo: Schema.optionalWith(TokenArray(LIMITS.tokenItem, 'appliesTo'), { default: () => [] }),
  cwe: Schema.optionalWith(CweArray, { default: () => [] }),
  vrt: Schema.optionalWith(TokenArray(LIMITS.tokenItem, 'vrt'), { default: () => [] }),
  chainsWith: Schema.optionalWith(TokenArray(LIMITS.tokenItem, 'chainsWith'), { default: () => [] }),
  qualityTier: Schema.optionalWith(QualityTier, { default: () => 3 }),
  sources: Schema.optionalWith(
    Schema.Array(SourceInput).pipe(
      Schema.maxItems(LIMITS.arrayItems, {
        message: () => `sources must have at most ${LIMITS.arrayItems} items`
      })
    ),
    { default: () => [] }
  )
});
export type RecordInput = Schema.Schema.Type<typeof RecordInput>;

// ---------------------------------------------------------------------------
// Read path — RetrieveQuery
// ---------------------------------------------------------------------------

/** Hard correctness filters applied to retrieval (never used for ranking). */
export const RetrieveFilters = Schema.Struct({
  cwe: Schema.optional(CweArray),
  product: Schema.optional(NonEmptyBounded(LIMITS.product, 'product')),
  minTier: Schema.optional(QualityTier)
});
export type RetrieveFilters = Schema.Schema.Type<typeof RetrieveFilters>;

export const RetrieveQuery = Schema.Struct({
  query: NonEmptyBounded(LIMITS.query, 'query'),
  // Optional HARD namespace filter: when present (≥1 entry) a record is
  // returned only if its `namespaces` OVERLAP this list. Absent = all.
  namespaces: Schema.optional(NamespacesArray),
  filters: Schema.optional(RetrieveFilters),
  // Number of chunks to return. Validated to 1..50; defaults to 5.
  k: Schema.optionalWith(Schema.Int.pipe(Schema.between(1, 50)), { default: () => 5 })
});
export type RetrieveQuery = Schema.Schema.Type<typeof RetrieveQuery>;

// ---------------------------------------------------------------------------
// Output — Chunk (snake_case public JSON contract)
// ---------------------------------------------------------------------------

export const ChunkSource = Schema.Struct({
  url: Schema.String,
  title: Schema.NullOr(Schema.String),
  tier: Schema.Number
});
export type ChunkSource = Schema.Schema.Type<typeof ChunkSource>;

export const Chunk = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  namespaces: Schema.Array(Schema.String),
  procedure: Schema.String,
  confirmation_signal: Schema.NullOr(Schema.String),
  // Related record/class ids the agent can pivot to (e.g. a 403-bypass chains
  // to cache-poisoning and ssrf). Broadens the agent's scope beyond the single
  // retrieved methodology.
  chains_with: Schema.Array(Schema.String),
  sources: Schema.Array(ChunkSource),
  quality_tier: Schema.Number,
  score: Schema.Number,
  kind: Schema.Literal('methodology')
});
export type Chunk = Schema.Schema.Type<typeof Chunk>;

// ---------------------------------------------------------------------------
// Output — RetrievalDiagnostics
//
// Why the read path reports its own candidate counts.
//
// The dense leg is an HNSW (approximate) index scan, and every filter — status,
// deleted_at, namespaces, cwe, product, minTier — is applied by Postgres as a
// POST-filter on rows the index emits, not as a pre-filter that narrows what
// the index searches. The graph walk visits a bounded number of rows, so:
//
//     rows returned  ≈  rows visited  ×  filter selectivity
//
// When a caller's filters are selective, that product can fall below the
// requested candidate count and the dense leg quietly returns short. Measured
// on pgvector 0.8.6 with a filter matching ~2% of rows and `ef_search = 100`,
// asking for 30 candidates yielded 18. Nothing errors: RRF still fuses the
// short dense list with the lexical leg, so the caller sees a plausible — but
// thinner — result set with no indication that recall was degraded.
//
// These counts make that visible. `semantic_search_degraded` is the actionable
// signal: when true, the dense leg hit the bound and the ranking is drawn from
// a smaller pool than intended. See `RecordRepo.nearest` for the mechanism.
// ---------------------------------------------------------------------------

export const RetrievalDiagnostics = Schema.Struct({
  /** Candidates the dense (vector) leg was asked for. */
  semantic_search_k: Schema.Number,
  /** Candidates the dense leg actually returned, AFTER filtering. */
  semantic_search_count: Schema.Number,
  /** `semantic_search_count < semantic_search_k` — the ANN walk ran out of
   * candidates under the filter, so recall for this query is degraded. */
  semantic_search_degraded: Schema.Boolean,
  /** Candidates the lexical (full-text) leg was asked for. */
  lexical_search_k: Schema.Number,
  /** Candidates the lexical leg actually returned. Unlike the dense leg this
   * is an exact scan, so a short count here means the corpus genuinely holds
   * no more matches — not that anything was truncated. */
  lexical_search_count: Schema.Number
});
export type RetrievalDiagnostics = Schema.Schema.Type<typeof RetrievalDiagnostics>;

/** What the read path resolves: the ranked chunks plus the candidate-generation
 * diagnostics that produced them. */
export const RetrievalResult = Schema.Struct({
  chunks: Schema.Array(Chunk),
  diagnostics: RetrievalDiagnostics
});
export type RetrievalResult = Schema.Schema.Type<typeof RetrievalResult>;

// ---------------------------------------------------------------------------
// Tagged parse errors — mapped from Effect's `ParseError`
// ---------------------------------------------------------------------------

export interface ValidationIssue {
  readonly path: ReadonlyArray<string | number>;
  readonly message: string;
}

const toPath = (path: ReadonlyArray<PropertyKey>): Array<string | number> =>
  path.flatMap((key) => (typeof key === 'string' || typeof key === 'number' ? [key] : []));

const formatParseIssues = (error: ParseResult.ParseError): Array<ValidationIssue> =>
  ParseResult.ArrayFormatter.formatErrorSync(error).map((formatted) => ({
    path: toPath(formatted.path),
    message: formatted.message
  }));

export class RecordInputParseError extends Data.TaggedError('RecordInputParseError')<{
  readonly message: string;
  readonly issues: ReadonlyArray<ValidationIssue>;
}> {}

export class RetrieveQueryParseError extends Data.TaggedError('RetrieveQueryParseError')<{
  readonly message: string;
  readonly issues: ReadonlyArray<ValidationIssue>;
}> {}

/** Decode `unknown` into a validated {@link RecordInput}, mapping any
 * `ParseError` into a tagged {@link RecordInputParseError}. */
export const decodeRecordInput = (
  input: unknown
): Effect.Effect<RecordInput, RecordInputParseError> =>
  Schema.decodeUnknown(RecordInput, { errors: 'all', onExcessProperty: 'error' })(input).pipe(
    Effect.mapError(
      (error) =>
        new RecordInputParseError({
          message: 'Invalid record input.',
          issues: formatParseIssues(error)
        })
    )
  );

/** Decode `unknown` into a validated {@link RetrieveQuery}, mapping any
 * `ParseError` into a tagged {@link RetrieveQueryParseError}. */
export const decodeRetrieveQuery = (
  input: unknown
): Effect.Effect<RetrieveQuery, RetrieveQueryParseError> =>
  Schema.decodeUnknown(RetrieveQuery, { errors: 'all', onExcessProperty: 'error' })(input).pipe(
    Effect.mapError(
      (error) =>
        new RetrieveQueryParseError({
          message: 'Invalid retrieve query.',
          issues: formatParseIssues(error)
        })
    )
  );
