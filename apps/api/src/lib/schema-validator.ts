import { Data, Effect, ParseResult, Schema } from 'effect';
import type { Context as HonoContext } from 'hono';

export type ValidationIssue = {
  path: Array<string | number>;
  message: string;
};

export type ValidationErrorConfig<TCode extends string = string> = {
  code: TCode;
  message: string;
};

// Generic over the code so each route's literal error code survives into the
// route schema (and from there into any RPC client types).
export class RequestValidationError<TCode extends string = string> extends Data.TaggedError(
  'RequestValidationError'
)<{
  code: TCode;
  message: string;
  issues: Array<ValidationIssue>;
}> {}

const toPath = (path: ReadonlyArray<PropertyKey>) =>
  path.flatMap((key) => (typeof key === 'string' || typeof key === 'number' ? [key] : []));

const formatParseIssues = (error: ParseResult.ParseError): Array<ValidationIssue> =>
  ParseResult.ArrayFormatter.formatErrorSync(error).map((formatted) => ({
    path: toPath(formatted.path),
    message: formatted.message
  }));

export const parseJsonBody = <TCode extends string>(
  c: HonoContext,
  config: ValidationErrorConfig<TCode>
) =>
  Effect.tryPromise({
    try: () => c.req.json() as Promise<unknown>,
    catch: () =>
      new RequestValidationError({
        code: config.code,
        message: 'Request body must be valid JSON.',
        issues: [{ path: [], message: 'Request body must be valid JSON.' }]
      })
  });

/**
 * Validates the input per the provided schema and, on a validation error,
 * fails with a RequestValidationError carrying formatted issues.
 */
export const validateInput =
  <A, I, R, TCode extends string>(
    schema: Schema.Schema<A, I, R>,
    config: ValidationErrorConfig<TCode>
  ) =>
  (input: unknown) =>
    Schema.decodeUnknown(schema, {
      errors: 'all',
      onExcessProperty: 'ignore'
    })(input).pipe(
      Effect.mapError(
        (error) =>
          new RequestValidationError({
            code: config.code,
            message: config.message,
            issues: formatParseIssues(error)
          })
      )
    );

export const isRequestValidationError = (error: unknown): error is RequestValidationError<string> =>
  error instanceof RequestValidationError;

export const requestValidationErrorToResponse = <TCode extends string>(
  c: HonoContext,
  error: RequestValidationError<TCode>
) =>
  c.json(
    {
      error: {
        code: error.code,
        message: error.message,
        issues: error.issues
      }
    },
    400
  );
