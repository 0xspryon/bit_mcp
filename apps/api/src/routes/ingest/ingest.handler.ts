import { IngestService, type RecordInputParseError } from '@repo/rag-core';
import { Cause, Effect, Exit, Option } from 'effect';
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
  parseJsonBody,
  requestValidationErrorToResponse
} from '../../lib/schema-validator';
import { ingestJsonError } from './ingest.validator';

/**
 * `POST /ingest` — write path. Requires `record:['ingest']` (admin-only in the
 * seeded role model). The record body is validated by the service itself.
 */
export const ingestRouteProgram = (c: HonoContext<HonoEnv>, headers: Headers) =>
  Effect.gen(function* () {
    const body = yield* parseJsonBody(c, ingestJsonError);
    const authenticated = yield* authenticate(headers);
    // HTTP is admin-only: gated on the admin `management` permission (ingestion
    // is admin-only anyway; this also keeps every HTTP route behind one gate).
    yield* requirePermissions({ management: ['access'] })(authenticated);
    const ingest = yield* IngestService;
    const result = yield* ingest.ingest(body);
    return { id: result.id, deduped: result.deduped, status: result.status };
  });

export type IngestRouteError = Effect.Effect.Error<ReturnType<typeof ingestRouteProgram>>;

const recordInputParseErrorToResponse = (
  c: HonoContext<HonoEnv>,
  error: RecordInputParseError
) =>
  c.json(
    { error: { code: 'INVALID_INGEST_INPUT' as const, message: error.message, issues: error.issues } },
    400
  );

const ingestErrorToResponse = (c: HonoContext<HonoEnv>, error: IngestRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);
  if (isRequestValidationError(error)) return requestValidationErrorToResponse(c, error);

  switch (error._tag) {
    case 'RecordInputParseError':
      return recordInputParseErrorToResponse(c, error);
    case 'EmbedError':
      return c.json(
        { error: { code: 'EMBEDDING_FAILED' as const, message: 'Unable to embed the record.' } },
        500
      );
    case 'IngestRepoError':
      return c.json(
        { error: { code: 'INGEST_REPO_ERROR' as const, message: 'Unable to store the record.' } },
        500
      );
    default:
      return handleNever(c, error);
  }
};

const exitToResponse = <T>(c: HonoContext<HonoEnv>, exit: Exit.Exit<T, IngestRouteError>) =>
  Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return ingestErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });

export async function ingestHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const headers = c.req.raw.headers;
  const exit = await runtime.runPromiseExit(ingestRouteProgram(c, headers));
  return exitToResponse(c, exit);
}
