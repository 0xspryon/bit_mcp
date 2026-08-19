import { type DbError, type Session, SessionRepo, type User, UserRepo } from '@repo/db';
import { APIError } from 'better-auth/api';
import { Context, Data, Effect, Layer, Option } from 'effect';
import type { Context as HonoContext } from 'hono';
import { auth } from './auth';
import { isSupportedRole, type Role } from './auth-roles';

export type AuthSession = {
  user: {
    id: string;
  };
  session: {
    id: string;
  };
};

export type UserAndSession = {
  user: Omit<User, 'role'> & { role: Role | null };
  /**
   * The caller's row in the `session` table — ABSENT for API-key callers.
   *
   * The api-key plugin authenticates statelessly: it verifies the key against
   * the `apikey` table and then synthesizes a session-shaped object in memory
   * whose `id` is the APIKEY row's id. Nothing is ever written to `session`, so
   * looking that id up there always misses. That is correct behaviour, not a
   * failure — the key is the credential, and a key deliberately does not create
   * server-side session state.
   *
   * It is an Option rather than a silently-absent field so a future consumer
   * has to decide what a missing session means AT ITS OWN CALL SITE (see
   * {@link requireSessionRow}) instead of `authenticate` guessing on its
   * behalf. Authorization never depends on this: `requirePermissions` derives
   * the role live from the user, which is a real row either way.
   */
  session: Option.Option<Session>;
};

export type Permissions = Record<string, Array<string>>;

/** Who is being authorized — resolved by {@link authenticate} beforehand. */
export type Principal = { userId: string; role: string | null };

// The repo error channel is `SqlError | DBNotFoundError`; recover the SqlError
// arm without a direct `@effect/sql` dependency in this app.
type SqlError = Exclude<DbError, { _tag: 'DBNotFoundError' }>;

export class AuthProviderError extends Data.TaggedError('AuthProviderError')<{
  cause: unknown;
}> { }

export class AuthEntityLookupError extends Data.TaggedError('AuthEntityLookupError')<{
  cause: SqlError;
}> { }

export class UnauthorizedError extends Data.TaggedError('UnauthorizedError')<{}> { }

export class ForbiddenError extends Data.TaggedError('ForbiddenError')<{}> { }

export class AuthService extends Context.Tag('@api/lib/AuthService')<
  AuthService,
  {
    getSession: (headers: Headers) => Effect.Effect<AuthSession | null, AuthProviderError>;
    /**
     * Check permissions for an ALREADY-RESOLVED principal.
     *
     * Deliberately takes the user rather than headers. better-auth's
     * `/admin/has-permission` calls `getAuthoritativeSessionFromCtx`, which
     * re-reads the session from the database and therefore finds nothing for
     * an API-key caller — and because headers were supplied it then throws
     * UNAUTHORIZED rather than falling through. Passing the principal skips
     * session resolution entirely, so cookie and API-key callers authorize
     * through exactly the same path.
     */
    userHasPermission: (
      principal: Principal,
      permissions: Permissions
    ) => Effect.Effect<boolean, AuthProviderError>;
  }
>() { }

/**
 * Does this thrown value mean "the caller's credential was refused"?
 *
 * better-auth does NOT return `null` from `getSession` for a bad API key — the
 * api-key plugin THROWS an `APIError`, and it uses several statuses for what is
 * one condition (`INVALID_API_KEY` arrives as both `UNAUTHORIZED` and
 * `FORBIDDEN`, a missing row as `NOT_FOUND`). Matching on the status class
 * rather than an enumerated code list means a plugin update that adds a
 * rejection reason does not silently start reporting 500s again.
 *
 * 429 is the deliberate exception: rate limiting is not a statement about the
 * credential, and collapsing it into "unauthenticated" would send a caller off
 * to re-mint a key that was never the problem. It stays a provider error.
 *
 * A 5xx, a network failure, or any non-`APIError` throw is a real provider
 * failure and must keep its own identity — we could not determine anything, and
 * reporting that as "unauthenticated" would be a lie in the dangerous direction.
 */
export const isCredentialRejection = (cause: unknown): boolean =>
  cause instanceof APIError &&
  cause.statusCode >= 400 &&
  cause.statusCode < 500 &&
  cause.statusCode !== 429;

export const AuthServiceLive = Layer.succeed(AuthService, {
  getSession: (headers) =>
    Effect.tryPromise({
      try: async () => auth.api.getSession({ headers }),
      catch: (cause) => new AuthProviderError({ cause })
    }).pipe(
      // A refused credential is the CALLER's error, not ours. Folding it back
      // to `null` puts it on the same path as a request that carried no
      // credential at all, which `authenticate` already turns into
      // `UnauthorizedError` -> 401 / `40100`. Left as a raw provider failure it
      // surfaced as an HTTP 500 and a JSON-RPC `-32603`, so every stale key on
      // an agent read as the server being broken.
      Effect.catchTag('AuthProviderError', (error) =>
        isCredentialRejection(error.cause)
          ? Effect.succeed(null)
          : Effect.fail(error)
      ),
      Effect.map((session) =>
        session
          ? {
            user: { id: session.user.id },
            session: { id: session.session.id }
          }
          : null
      )
    ),
  userHasPermission: (principal, permissions) =>
    Effect.tryPromise({
      try: async () => {
        // NO `headers`: supplying them makes the endpoint demand an
        // authoritative session, which an API-key caller never has. With the
        // role in the body it authorizes the principal directly.
        // Narrow to a configured role. An unrecognised value falls back to
        // `user` (least privilege); `requirePermissions` rejects it outright
        // straight after, so this can only ever under-grant.
        const role: Role =
          principal.role !== null && isSupportedRole(principal.role) ? principal.role : 'user';
        const result = await auth.api.userHasPermission({
          body: { userId: principal.userId, role, permissions }
        });

        return result.success;
      },
      catch: (cause) => new AuthProviderError({ cause })
    })
});

export const makeAuthServiceTest = (implementation: Context.Tag.Service<AuthService>) =>
  Layer.succeed(AuthService, implementation);

export const authenticate = (headers: Headers) =>
  Effect.gen(function*() {
    const authService = yield* AuthService;
    const userRepo = yield* UserRepo;
    const sessionRepo = yield* SessionRepo;
    const authSession = yield* authService.getSession(headers);

    if (!authSession) {
      return yield* Effect.fail(new UnauthorizedError());
    }

    const [user, session] = yield* Effect.all(
      [
        userRepo.findById(authSession.user.id).pipe(
          Effect.catchTags({
            SqlError: (cause) => Effect.fail(new AuthEntityLookupError({ cause })),
            DBNotFoundError: () => Effect.fail(new UnauthorizedError())
          })
        ),
        // A missing row means "authenticated by API key", not "unauthenticated"
        // — see UserAndSession.session. A SqlError is still a real failure: we
        // could not determine anything, so it must not read as "no session".
        sessionRepo.findById(authSession.session.id).pipe(
          Effect.map(Option.some),
          Effect.catchTags({
            SqlError: (cause) => Effect.fail(new AuthEntityLookupError({ cause })),
            DBNotFoundError: () => Effect.succeed(Option.none<Session>())
          })
        )
      ],
      { concurrency: 'unbounded' }
    );
    return { user, session } as UserAndSession;
  });

/**
 * Demand a real `session` row, for the call sites that genuinely need one —
 * anything reading `impersonatedBy`, the session's own expiry, or its ip/user
 * agent. Fails `UnauthorizedError` when the caller authenticated with an API
 * key, because those requests have no session to reason about.
 *
 * Use this at the exact point the session is needed rather than widening
 * `authenticate`, so a stateless API-key caller keeps working on every path
 * that does not actually require one.
 */
export const requireSessionRow = (userAndSession: UserAndSession) =>
  Option.match(userAndSession.session, {
    onNone: () => Effect.fail(new UnauthorizedError()),
    onSome: (session) => Effect.succeed(session)
  });

export const requirePermissions =
  (permissions: Permissions) =>
    (userAndSession: UserAndSession) =>
      Effect.gen(function*() {
        const authService = yield* AuthService;
        const allowed = yield* authService.userHasPermission(
          { userId: userAndSession.user.id, role: userAndSession.user.role },
          permissions
        );
        if (!allowed) {
          return yield* Effect.fail(new ForbiddenError());
        }
        const role = userAndSession.user.role;
        if (role && !isSupportedRole(role)) {
          return yield* Effect.fail(new ForbiddenError());
        }
        return userAndSession;
      });

export type AuthError =
  | Effect.Effect.Error<ReturnType<typeof authenticate>>
  | Effect.Effect.Error<ReturnType<ReturnType<typeof requirePermissions>>>;

export const isAuthError = (error: unknown): error is AuthError =>
  error instanceof AuthProviderError ||
  error instanceof AuthEntityLookupError ||
  error instanceof UnauthorizedError ||
  error instanceof ForbiddenError;

export function handleNever(c: HonoContext, _: never) {
  return c.json(
    { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'internal server error' } },
    500
  );
}

export const authErrorToResponse = (c: HonoContext, error: AuthError) => {
  switch (error._tag) {
    case 'UnauthorizedError':
      return c.json(
        {
          error: {
            code: 'UNAUTHORIZED' as const,
            message: 'Authentication is required.'
          }
        },
        401
      );
    case 'ForbiddenError':
      return c.json(
        {
          error: {
            code: 'FORBIDDEN' as const,
            message: 'You do not have permission to access this resource.'
          }
        },
        403
      );
    case 'AuthProviderError':
      return c.json(
        {
          error: {
            code: 'AUTH_PROVIDER_FAILED' as const,
            message: 'Unable to verify authentication.'
          }
        },
        500
      );
    case 'AuthEntityLookupError':
      return c.json(
        {
          error: {
            code: 'AUTH_ENTITY_LOOKUP_FAILED' as const,
            message: 'Unable to verify authentication.'
          }
        },
        500
      );
    default:
      return handleNever(c, error);
  }
};
