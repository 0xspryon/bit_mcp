import { RecordRepo, type DbError, type RecordReadRow, type RecordSourceRow } from '@repo/db';
import { Cause, Data, Effect, Exit, Option } from 'effect';
import type { HonoContext, HonoEnv } from '../../app-env';
import {
  authErrorToResponse,
  authenticate,
  handleNever,
  isAuthError,
  requirePermissions
} from '../../lib/effect-auth';
import {
  isRequestValidationError,
  requestValidationErrorToResponse
} from '../../lib/schema-validator';
import { validateListQuery, validateStatusUpdate } from './records.validator';

// Recover the SqlError arm of the repo error channel without a direct
// `@effect/sql` dependency in this app (mirrors `lib/effect-auth`).
type SqlError = Exclude<DbError, { _tag: 'DBNotFoundError' }>;

/** Record ids are `uuid` in Postgres; reject anything that isn't a UUID up
 * front so a malformed id returns 404 (indistinguishable from an absent id)
 * rather than a 500 from a Postgres cast error — no format/enumeration oracle. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The requested record id does not exist. */
class RecordNotFoundError extends Data.TaggedError('RecordNotFoundError')<{ id: string }> {}
/** A repo/SQL failure, re-tagged so the route error is a closed tagged union. */
class RecordRepoError extends Data.TaggedError('RecordRepoError')<{ cause: SqlError }> {}

/**
 * The public record shape returned by the API. Deliberately a curated DTO, NOT
 * the raw `RecordRow`: it omits the internal `embedding` (1024 floats),
 * `content_hash` (dedup key), and generated `fts` column. `status`/`version` are
 * included because this route is admin-only and drives the curation workflow.
 */
export interface RecordDto {
  readonly id: string;
  readonly namespaces: readonly string[];
  readonly title: string;
  readonly symptom: string;
  readonly whenToUse: string | null;
  readonly procedure: string;
  readonly confirmationSignal: string | null;
  readonly preconditions: readonly string[];
  readonly appliesTo: readonly string[];
  readonly cwe: readonly number[];
  readonly vrt: readonly string[];
  readonly chainsWith: readonly string[];
  readonly qualityTier: number;
  readonly status: string;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  /** Soft-delete marker; `null` for a live record. Surfaced because the
   * fetch-by-id path returns deleted records too, and a curator has to be able
   * to tell them apart. */
  readonly deletedAt: Date | null;
  readonly sources: ReadonlyArray<{ url: string; title: string | null; tier: number }>;
}

const toRecordDto = (row: RecordReadRow, sources: readonly RecordSourceRow[]): RecordDto => ({
  id: row.id,
  namespaces: row.namespaces,
  title: row.title,
  symptom: row.symptom,
  whenToUse: row.whenToUse,
  procedure: row.procedure,
  confirmationSignal: row.confirmationSignal,
  preconditions: row.preconditions,
  appliesTo: row.appliesTo,
  cwe: row.cwe,
  vrt: row.vrt,
  chainsWith: row.chainsWith,
  qualityTier: row.qualityTier,
  status: row.status,
  version: row.version,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
  deletedAt: row.deletedAt,
  sources: sources.map((s) => ({ url: s.url, title: s.title, tier: s.tier }))
});

/**
 * `GET /api/v1/records/:id` — fetch a single record by id. Admin-only (HTTP is the
 * admin/curation doorway); returns the public {@link RecordDto}, any status,
 * INCLUDING soft-deleted records (`deletedAt` tells them apart). This path
 * deliberately does not filter on `deleted_at` — the retrieve/list paths do.
 */
export const recordByIdRouteProgram = (headers: Headers, id: string) =>
  Effect.gen(function* () {
    const authenticated = yield* authenticate(headers);
    yield* requirePermissions({ management: ['access'] })(authenticated);
    if (!UUID_RE.test(id)) {
      return yield* Effect.fail(new RecordNotFoundError({ id }));
    }
    const repo = yield* RecordRepo;
    const found = yield* repo
      .getById(id)
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    if (Option.isNone(found)) {
      return yield* Effect.fail(new RecordNotFoundError({ id }));
    }
    const sourcesById = yield* repo
      .sourcesFor([id])
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    return toRecordDto(found.value, sourcesById.get(id) ?? []);
  });

/**
 * `PATCH /api/v1/records/:id/status` — admin curation: promote (`staging`→`active`) or
 * demote (`active`→`staging`) a record. Admin-only. Returns the updated
 * {@link RecordDto}.
 */
export const updateRecordStatusRouteProgram = (headers: Headers, id: string, body: unknown) =>
  Effect.gen(function* () {
    const authenticated = yield* authenticate(headers);
    yield* requirePermissions({ management: ['access'] })(authenticated);
    if (!UUID_RE.test(id)) {
      return yield* Effect.fail(new RecordNotFoundError({ id }));
    }
    const { status } = yield* validateStatusUpdate(body);
    const repo = yield* RecordRepo;
    const updated = yield* repo
      .updateStatus(id, status)
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    if (Option.isNone(updated)) {
      return yield* Effect.fail(new RecordNotFoundError({ id }));
    }
    const sourcesById = yield* repo
      .sourcesFor([id])
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    return toRecordDto(updated.value, sourcesById.get(id) ?? []);
  });

/**
 * `GET /api/v1/records?status=&limit=` — admin list of records by lifecycle status
 * (defaults to `staging`, for the review queue). Admin-only.
 */
export const listRecordsRouteProgram = (headers: Headers, query: unknown) =>
  Effect.gen(function* () {
    const authenticated = yield* authenticate(headers);
    yield* requirePermissions({ management: ['access'] })(authenticated);
    const { status, limit } = yield* validateListQuery(query);
    const repo = yield* RecordRepo;
    const rows = yield* repo
      .listByStatus(status, limit)
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    const ids = rows.map((r) => r.id);
    const sourcesById = yield* repo
      .sourcesFor(ids)
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new RecordRepoError({ cause }))));
    return rows.map((r) => toRecordDto(r, sourcesById.get(r.id) ?? []));
  });

export type RecordsRouteError =
  | Effect.Effect.Error<ReturnType<typeof recordByIdRouteProgram>>
  | Effect.Effect.Error<ReturnType<typeof updateRecordStatusRouteProgram>>
  | Effect.Effect.Error<ReturnType<typeof listRecordsRouteProgram>>;

const recordsErrorToResponse = (c: HonoContext<HonoEnv>, error: RecordsRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);
  if (isRequestValidationError(error)) return requestValidationErrorToResponse(c, error);

  switch (error._tag) {
    case 'RecordNotFoundError':
      return c.json(
        { error: { code: 'NOT_FOUND' as const, message: 'Record was not found.' } },
        404
      );
    case 'RecordRepoError':
      return c.json(
        { error: { code: 'RECORD_REPO_ERROR' as const, message: 'Unable to load the record.' } },
        500
      );
    default:
      return handleNever(c, error);
  }
};

const exitToResponse = <T>(c: HonoContext<HonoEnv>, exit: Exit.Exit<T, RecordsRouteError>) =>
  Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return recordsErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });

export async function recordByIdHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const headers = c.req.raw.headers;
  const id = c.req.param('id') ?? '';
  const exit = await runtime.runPromiseExit(recordByIdRouteProgram(headers, id));
  return exitToResponse(c, exit);
}

export async function updateRecordStatusHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const headers = c.req.raw.headers;
  const id = c.req.param('id') ?? '';
  const body: unknown = await c.req.json().catch(() => null);
  const exit = await runtime.runPromiseExit(updateRecordStatusRouteProgram(headers, id, body));
  return exitToResponse(c, exit);
}

export async function listRecordsHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const headers = c.req.raw.headers;
  // Build the query object, omitting absent params so the schema defaults apply.
  const query: Record<string, string> = {};
  const status = c.req.query('status');
  if (status !== undefined) query.status = status;
  const limit = c.req.query('limit');
  if (limit !== undefined) query.limit = limit;
  const exit = await runtime.runPromiseExit(listRecordsRouteProgram(headers, query));
  return exitToResponse(c, exit);
}
