import * as PgDrizzle from '@effect/sql-drizzle/Pg';
import * as SqlClient from '@effect/sql/SqlClient';
import type { SqlError } from '@effect/sql/SqlError';
import {
  and,
  asc,
  desc,
  eq,
  getTableColumns,
  inArray,
  isNull,
  lte,
  sql,
  type InferInsertModel,
  type InferSelectModel,
  type SQL
} from 'drizzle-orm';
import { Context, Effect, Layer, Option } from 'effect';
import { DrizzleLive } from '../effect-db';
import { records, recordSources, sources } from '../schema';

/** A source citation attached to a record, as needed to build a retrieval Chunk. */
export interface RecordSourceRow {
  readonly url: string;
  readonly title: string | null;
  readonly tier: number;
}

/** A source to upsert (by url) and link when inserting a record. */
export interface RecordSourceUpsert {
  readonly url: string;
  readonly title: string | null;
  readonly qualityTier: number;
  readonly kind: string | null;
}

/** Lifecycle status of a record. New records land in `staging`; retrieval only
 * sees `active`; an admin promotes or demotes between the two. Retiring a
 * record is a soft delete (`deleted_at`), not a status. */
export type RecordStatus = 'staging' | 'active';

export type RecordRow = InferSelectModel<typeof records>;
// `fts` is a generated (STORED) column and is therefore absent from the insert
// shape drizzle infers — callers never supply it.
export type RecordInsert = InferInsertModel<typeof records>;

// Read queries never need the heavy `embedding` (1024 floats) or the generated
// `fts` value — the retriever ranks by SQL and the API returns a DTO that omits
// both. Projecting them out at the SQL level avoids transferring vectors that
// are immediately discarded (matters most for admin list-by-status).
const { embedding: _embedding, fts: _fts, ...recordReadColumns } = getTableColumns(records);
/** A record row without the `embedding`/`fts` columns (all read paths use this). */
export type RecordReadRow = Omit<RecordRow, 'embedding' | 'fts'>;

/** Retrieval filters. These are HARD correctness filters: a namespaced query
 * must NEVER return a record from another namespace. Retrieval always passes
 * `status: 'active'`. Soft-deleted rows are excluded unconditionally and are
 * not expressible here — see {@link recordFilterConditions}. */
export interface Filter {
  readonly status: RecordStatus;
  /** Array OVERLAP (`&&`) against `records.namespaces` when present & non-empty.
   * A record shares at least one namespace with the query, or it is never
   * returned. This is a HARD isolation filter, not a ranking signal. */
  readonly namespaces?: readonly string[];
  /** Array OVERLAP (`&&`) against `records.cwe` when present & non-empty. */
  readonly cwe?: readonly number[];
  /** Case-insensitive substring match against any `records.applies_to` element
   * (product/tech fingerprint), when present. LIKE wildcards in the value are
   * escaped so they match literally. */
  readonly product?: string;
  /** `quality_tier <= minTier` (tier 1 is highest quality, so `minTier: 2`
   * admits tiers 1 and 2). */
  readonly minTier?: number;
}

/** HNSW `ef_search`: the size of the candidate list the graph search keeps.
 * It must be >= the query `LIMIT` (k) and larger values trade speed for recall.
 * 100 sits comfortably above the retriever's k1 (30) at the project's <1M-record
 * scale. Set per query on the query's own connection via `SET LOCAL` inside a
 * transaction.
 *
 * This knob does TWO things, not one, and the second is easy to miss:
 *
 *  1. At execution it bounds the graph walk, which caps how many rows can
 *     survive the WHERE clause (see `nearest`). Measured on pgvector 0.8.6,
 *     20k rows, a filter matching ~2% of them, asking for k=30:
 *       ef_search =  10 ->  2 rows returned
 *       ef_search =  40 -> 10 rows returned
 *       ef_search = 100 -> 18 rows returned
 *
 *  2. At PLANNING it feeds pgvector's cost estimate for the index path, so it
 *     also decides whether the HNSW index is used at all. In that same setup,
 *     ef_search=100 chose the index (18 rows) while ef_search=200 made the
 *     index look expensive enough that Postgres switched to a sequential scan
 *     plus sort — which is exact, and returned all 30.
 *
 * So raising this does not simply buy more recall: past a threshold it flips
 * the plan entirely. Re-measure against the real corpus before changing it;
 * the numbers above come from uniform random vectors, which is close to
 * worst-case for HNSW (no cluster structure to guide the walk). */
const HNSW_EF_SEARCH = 100;

/** `int[]` literal bound as parameters, e.g. `array[1, 2]::int[]`. */
const intArray = (nums: readonly number[]): SQL =>
  sql`array[${sql.join(
    nums.map((n) => sql`${n}`),
    sql`, `
  )}]::int[]`;

/** `text[]` literal bound as parameters, e.g. `array['a', 'b']::text[]`. Each
 * element is bound as a parameter (never interpolated) so values are safe. */
const textArray = (strings: readonly string[]): SQL =>
  sql`array[${sql.join(
    strings.map((s) => sql`${s}`),
    sql`, `
  )}]::text[]`;

/** pgvector literal for the cosine (`<=>`) operator: `'[a,b,c]'::vector`. */
const vectorParam = (vec: Float32Array): SQL =>
  sql`${`[${Array.from(vec).join(',')}]`}::vector`;

/** Escape LIKE/ILIKE wildcards so a caller-supplied product fingerprint matches
 * literally (a `%` or `_` in the value must not act as a wildcard). Paired with
 * `ESCAPE '\'` on the ILIKE. */
const escapeLike = (value: string): string => value.replace(/[\\%_]/g, (ch) => `\\${ch}`);

/** Pure, DB-free translation of a {@link Filter} into drizzle SQL conditions.
 * The `status` and `deleted_at is null` predicates are always present; every
 * other predicate is added only when its field is set. Exported so it can be
 * unit-tested without a DB.
 *
 * These are semantically hard filters, but on the dense path (`nearest`) they
 * are executed as POST-filters over an approximate index scan, never as a
 * pre-filter that narrows what the index searches. Correctness is unaffected —
 * nothing that fails a predicate is ever returned — but COMPLETENESS is: the
 * more selective the filter, the fewer of the walk's bounded candidates survive
 * it. See `nearest` for the failure mode and the measured numbers. */
export const recordFilterConditions = (f: Filter): SQL[] => {
  const conditions: SQL[] = [eq(records.status, f.status), isNull(records.deletedAt)];
  if (f.namespaces !== undefined && f.namespaces.length > 0) {
    conditions.push(sql`${records.namespaces} && ${textArray(f.namespaces)}`);
  }
  if (f.cwe !== undefined && f.cwe.length > 0) {
    conditions.push(sql`${records.cwe} && ${intArray(f.cwe)}`);
  }
  if (f.product !== undefined) {
    conditions.push(
      sql`exists (select 1 from unnest(${records.appliesTo}) as a where a ilike ${`%${escapeLike(f.product)}%`} escape '\\')`
    );
  }
  if (f.minTier !== undefined) {
    conditions.push(lte(records.qualityTier, f.minTier));
  }
  return conditions;
};

export class RecordRepo extends Context.Tag('@repo/db/RecordRepo')<
  RecordRepo,
  {
    /** Atomically upserts the record and its sources in ONE transaction.
     *
     * The record is inserted with `ON CONFLICT (content_hash) DO UPDATE`: on a
     * fresh insert, the sources are upserted (by url) and linked; on a conflict
     * (a concurrent or repeat ingest of identical content) the existing row's
     * `namespaces` are MERGED with the incoming ones (distinct union) and no
     * sources are written — the existing row's id + status are returned. A fresh
     * INSERT is distinguished from a conflict/merge via the `(xmax = 0)` system
     * idiom (true only for a just-inserted row). This makes ingest idempotent
     * and race-safe, and — because sources are written only after a real insert,
     * inside the same transaction — guarantees no orphan or mutated source rows
     * when a write fails. */
    insert: (
      row: RecordInsert,
      sources: readonly RecordSourceUpsert[]
    ) => Effect.Effect<{ id: string; inserted: boolean; status: string }, SqlError>;
    /** Look up a record by its dedup hash. Deliberately NOT filtered by
     * `deleted_at`: `content_hash` is UNIQUE, so a soft-deleted row still owns
     * its hash and re-ingesting identical content must dedup onto it rather
     * than embed and then collide on insert. */
    findByHash: (hash: string) => Effect.Effect<Option.Option<RecordReadRow>, SqlError>;
    /** Merge (distinct union) the given namespaces onto an existing record's
     * `namespaces` array. Resolves the updated row, or `None` when the id does
     * not exist. Used by the ingest fast-path so a dedup hit still records the
     * new membership without re-embedding. */
    addNamespaces: (
      id: string,
      namespaces: readonly string[]
    ) => Effect.Effect<Option.Option<RecordReadRow>, SqlError>;
    /** Cosine (`<=>`) nearest neighbours under the given filter, UP TO k rows.
     * Soft-deleted rows are excluded.
     *
     * MAY RETURN FEWER THAN k EVEN WHEN MORE MATCHING ROWS EXIST. This is not a
     * bug to fix at the call site; it is how an approximate index interacts
     * with a WHERE clause, and callers must treat a short result as a possible
     * recall signal rather than as "the corpus holds nothing more". The
     * retriever surfaces it to clients via `RetrievalDiagnostics`.
     *
     * Postgres executes this as a pipeline, not as three phases. There is no
     * point at which all rows are ordered or all rows are filtered. The Limit
     * pulls one row at a time from the index scan; the scan walks the HNSW
     * graph to the next-nearest row, applies the filter, discards it on a miss
     * and walks on, yields it on a hit; the Limit counts only survivors and
     * stops the walk once it has k. So the filter is applied BEFORE anything
     * counts toward k — you never get "top k, then filtered down".
     *
     * The catch is that the walk is finite. Every row it discards is discarded
     * correctly, but the rows that WOULD pass are simply never visited, so:
     *
     *     rows returned  ≈  rows visited  ×  filter selectivity
     *
     * and when that product falls under k you get a short list with no error.
     * Measured on pgvector 0.8.6 (the `compose.yml` image), 20k rows, k=30,
     * ef_search=100:
     *
     *   filter selectivity 33%    -> 92 rows visited, 30 returned  (fine)
     *   filter selectivity  2%    -> index chosen,    18 returned  (short)
     *   filter selectivity  0.1%  -> 703 rows visited, 0 returned  (empty)
     *
     * What keeps this rare in practice is the planner: below roughly 1-2%
     * selectivity it costs the HNSW path above a sequential scan and switches
     * to scan-plus-sort, which is exact and returns everything. That is a cost
     * estimate, not a guarantee — it shifts with table size, statistics,
     * `ef_search` (see HNSW_EF_SEARCH) and a stale ANALYZE. The exposed band is
     * filters selective enough to starve the walk but not selective enough to
     * trigger the switch.
     *
     * Real embeddings are kinder than those figures suggest: bge-m3 vectors
     * cluster by topic and `namespaces` correlates with topic, so for an
     * on-topic query the walk moves toward the surviving set instead of
     * orthogonally to it. The pathological case is a query whose semantics do
     * not align with its namespace filter.
     *
     * If this needs closing rather than reporting, the options are a partial
     * index matching the always-on predicate (`status = 'active' AND deleted_at
     * IS NULL`) or `hnsw.iterative_scan` with a raised `hnsw.max_scan_tuples`. */
    nearest: (vec: Float32Array, f: Filter, k: number) => Effect.Effect<RecordReadRow[], SqlError>;
    /** Full-text (`websearch_to_tsquery`) matches under the filter, ranked, k
     * rows. Soft-deleted rows are excluded. */
    lexical: (query: string, f: Filter, k: number) => Effect.Effect<RecordReadRow[], SqlError>;
    /** Fetch one record by id. Deliberately does NOT filter `deleted_at`: this
     * is the admin fetch-by-id path, and a curator must still be able to
     * inspect a soft-deleted record. */
    getById: (id: string) => Effect.Effect<Option.Option<RecordReadRow>, SqlError>;
    /** Source citations for each of the given record ids, keyed by record id.
     * Records with no sources are simply absent from the map. */
    sourcesFor: (
      recordIds: readonly string[]
    ) => Effect.Effect<ReadonlyMap<string, RecordSourceRow[]>, SqlError>;
    /** Set a record's lifecycle status (admin curation). Resolves the updated
     * row, or `None` when the id does not exist. */
    updateStatus: (
      id: string,
      status: RecordStatus
    ) => Effect.Effect<Option.Option<RecordReadRow>, SqlError>;
    /** List records with the given status, newest first, up to `limit`.
     * Soft-deleted rows are excluded. */
    listByStatus: (status: RecordStatus, limit: number) => Effect.Effect<RecordReadRow[], SqlError>;
  }
>() {}

export const RecordRepoLive = Layer.effect(
  RecordRepo,
  Effect.gen(function* () {
    const db = yield* PgDrizzle.PgDrizzle;
    const sqlClient = yield* SqlClient.SqlClient;

    return {
      insert: (row, sourceUpserts) =>
        sqlClient.withTransaction(
          Effect.gen(function* () {
            // ON CONFLICT (content_hash) DO UPDATE: a conflict merges the
            // incoming namespaces onto the existing row (distinct union) instead
            // of doing nothing, so a repeat/concurrent ingest under a new
            // namespace still records that membership. `(xmax = 0)` is true only
            // for a freshly inserted row, so it distinguishes insert from merge.
            const upsertedRows = yield* db
              .insert(records)
              .values(row)
              .onConflictDoUpdate({
                target: records.contentHash,
                set: {
                  namespaces: sql`(select array(select distinct e from unnest(${records.namespaces} || excluded.namespaces) e))`,
                  updatedAt: sql`now()`
                }
              })
              .returning({
                id: records.id,
                status: records.status,
                inserted: sql<boolean>`(xmax = 0)`
              });
            const created = upsertedRows[0];
            if (!created) {
              return yield* Effect.dieMessage(
                'record upsert returned no row'
              );
            }
            if (!created.inserted) {
              // Conflict/merge: identical content_hash already existed. Its
              // namespaces were merged above; write no sources, return the row.
              return { id: created.id, inserted: false, status: created.status };
            }
            const recordId = created.id;
            // Sources are written only after the record insert succeeds, in the
            // same transaction, so a later failure rolls everything back.
            for (const s of sourceUpserts) {
              const sourceRows = yield* db
                .insert(sources)
                .values({ url: s.url, title: s.title, qualityTier: s.qualityTier, kind: s.kind })
                .onConflictDoUpdate({
                  target: sources.url,
                  set: { title: s.title, qualityTier: s.qualityTier, kind: s.kind }
                })
                .returning({ id: sources.id });
              const sourceRow = sourceRows[0];
              if (sourceRow) {
                yield* db
                  .insert(recordSources)
                  .values({ recordId, sourceId: sourceRow.id })
                  .onConflictDoNothing();
              }
            }
            return { id: recordId, inserted: true, status: created.status };
          })
        ),
      findByHash: (hash) =>
        db
          .select(recordReadColumns)
          .from(records)
          .where(eq(records.contentHash, hash))
          .limit(1)
          .pipe(Effect.map((rows) => Option.fromNullable(rows[0]))),
      addNamespaces: (id, namespaces) =>
        db
          .update(records)
          .set({
            namespaces: sql`(select array(select distinct e from unnest(${records.namespaces} || ${textArray(namespaces)}) e))`,
            updatedAt: sql`now()`
          })
          .where(eq(records.id, id))
          .returning(recordReadColumns)
          .pipe(Effect.map((rows) => Option.fromNullable(rows[0]))),
      nearest: (vec, f, k) =>
        // `SET LOCAL` only affects the current transaction, so wrapping the
        // ef_search setting and the query in one transaction guarantees they run
        // on the same pooled connection.
        //
        // NOTE: `.where(...)` below reads like a pre-filter but Postgres applies
        // it as a post-filter on rows the HNSW index emits, so this can resolve
        // fewer than `k` rows. See the `nearest` doc on the interface above.
        sqlClient.withTransaction(
          Effect.gen(function* () {
            // HNSW_EF_SEARCH is a fixed integer constant (not user input); SET
            // does not accept bind parameters, so it must be a literal.
            yield* sqlClient.unsafe(`SET LOCAL hnsw.ef_search = ${HNSW_EF_SEARCH}`);
            return yield* db
              .select(recordReadColumns)
              .from(records)
              .where(and(...recordFilterConditions(f)))
              .orderBy(asc(sql`${records.embedding} <=> ${vectorParam(vec)}`))
              .limit(k);
          })
        ),
      lexical: (query, f, k) => {
        const tsquery = sql`websearch_to_tsquery('english', ${query})`;
        return db
          .select(recordReadColumns)
          .from(records)
          .where(and(sql`${records.fts} @@ ${tsquery}`, ...recordFilterConditions(f)))
          .orderBy(desc(sql`ts_rank(${records.fts}, ${tsquery})`))
          .limit(k);
      },
      getById: (id) =>
        db
          .select(recordReadColumns)
          .from(records)
          .where(eq(records.id, id))
          .limit(1)
          .pipe(Effect.map((rows) => Option.fromNullable(rows[0]))),
      sourcesFor: (recordIds) => {
        if (recordIds.length === 0) {
          return Effect.succeed(new Map<string, RecordSourceRow[]>());
        }
        return db
          .select({
            recordId: recordSources.recordId,
            url: sources.url,
            title: sources.title,
            tier: sources.qualityTier
          })
          .from(recordSources)
          .innerJoin(sources, eq(recordSources.sourceId, sources.id))
          .where(inArray(recordSources.recordId, [...recordIds]))
          .pipe(
            Effect.map((rows) => {
              const byRecord = new Map<string, RecordSourceRow[]>();
              for (const row of rows) {
                const list = byRecord.get(row.recordId) ?? [];
                list.push({ url: row.url, title: row.title, tier: row.tier });
                byRecord.set(row.recordId, list);
              }
              return byRecord;
            })
          );
      },
      updateStatus: (id, status) =>
        db
          .update(records)
          .set({ status, updatedAt: sql`now()` })
          .where(eq(records.id, id))
          .returning(recordReadColumns)
          .pipe(Effect.map((rows) => Option.fromNullable(rows[0]))),
      listByStatus: (status, limit) =>
        db
          .select(recordReadColumns)
          .from(records)
          .where(and(eq(records.status, status), isNull(records.deletedAt)))
          .orderBy(desc(records.createdAt))
          .limit(limit)
    };
  })
);

export const RecordRepoDefault = RecordRepoLive.pipe(Layer.provide(DrizzleLive));

export const makeRecordRepoTest = (implementation: Context.Tag.Service<RecordRepo>) =>
  Layer.succeed(RecordRepo, implementation);
