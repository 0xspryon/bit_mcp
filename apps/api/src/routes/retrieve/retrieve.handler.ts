import { RetrieverService, type RetrieveQueryParseError } from '@repo/rag-core';
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
import { retrieveJsonError } from './retrieve.validator';

/**
 * `POST /retrieve` — read path. Requires `record:['read']`. The query body is
 * validated by the service itself.
 */
export const retrieveRouteProgram = (c: HonoContext<HonoEnv>, headers: Headers) =>
  Effect.gen(function* () {
    const body = yield* parseJsonBody(c, retrieveJsonError);
    const authenticated = yield* authenticate(headers);
    // HTTP is the admin/batch doorway: gated on the admin-only `management`
    // permission. Non-agent retrieval for users goes through the MCP doorway.
    yield* requirePermissions(headers, { management: ['access'] })(authenticated);
    const retriever = yield* RetrieverService;
    // `{ chunks, diagnostics }` — the diagnostics report each retrieval leg's
    // candidate count against what it was asked for, so a caller can tell a
    // genuinely small result set apart from one the ANN index truncated.
    return yield* retriever.retrieve(body);
  });

export type RetrieveRouteError = Effect.Effect.Error<ReturnType<typeof retrieveRouteProgram>>;

const retrieveQueryParseErrorToResponse = (
  c: HonoContext<HonoEnv>,
  error: RetrieveQueryParseError
) =>
  c.json(
    {
      error: {
        code: 'INVALID_RETRIEVE_INPUT' as const,
        message: error.message,
        issues: error.issues
      }
    },
    400
  );

const retrieveErrorToResponse = (c: HonoContext<HonoEnv>, error: RetrieveRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);
  if (isRequestValidationError(error)) return requestValidationErrorToResponse(c, error);

  switch (error._tag) {
    case 'RetrieveQueryParseError':
      return retrieveQueryParseErrorToResponse(c, error);
    case 'EmbedError':
      return c.json(
        { error: { code: 'EMBEDDING_FAILED' as const, message: 'Unable to embed the query.' } },
        500
      );
    case 'RerankError':
      return c.json(
        { error: { code: 'RERANK_FAILED' as const, message: 'Unable to rerank candidates.' } },
        500
      );
    case 'RetrievalRepoError':
      return c.json(
        {
          error: { code: 'RETRIEVAL_REPO_ERROR' as const, message: 'Unable to run the retrieval.' }
        },
        500
      );
    default:
      return handleNever(c, error);
  }
};

const exitToResponse = <T>(c: HonoContext<HonoEnv>, exit: Exit.Exit<T, RetrieveRouteError>) =>
  Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return retrieveErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });

export async function retrieveHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const headers = c.req.raw.headers;
  const exit = await runtime.runPromiseExit(retrieveRouteProgram(c, headers));
  return exitToResponse(c, exit);
}
