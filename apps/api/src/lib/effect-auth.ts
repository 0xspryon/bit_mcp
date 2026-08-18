import { type DbError, type Session, SessionRepo, type User, UserRepo } from '@repo/db';
import { Context, Data, Effect, Layer } from 'effect';
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
  session: Session;
};

export type Permissions = Record<string, Array<string>>;

// The repo error channel is `SqlError | DBNotFoundError`; recover the SqlError
// arm without a direct `@effect/sql` dependency in this app.
type SqlError = Exclude<DbError, { _tag: 'DBNotFoundError' }>;

export class AuthProviderError extends Data.TaggedError('AuthProviderError')<{
  cause: unknown;
}> {}

export class AuthEntityLookupError extends Data.TaggedError('AuthEntityLookupError')<{
  cause: SqlError;
}> {}

export class UnauthorizedError extends Data.TaggedError('UnauthorizedError')<{}> {}

export class ForbiddenError extends Data.TaggedError('ForbiddenError')<{}> {}

export class AuthService extends Context.Tag('@api/lib/AuthService')<
  AuthService,
  {
    getSession: (headers: Headers) => Effect.Effect<AuthSession | null, AuthProviderError>;
    userHasPermission: (
      headers: Headers,
      permissions: Permissions
    ) => Effect.Effect<boolean, AuthProviderError>;
  }
>() {}

export const AuthServiceLive = Layer.succeed(AuthService, {
  getSession: (headers) =>
    Effect.tryPromise({
      try: async () => auth.api.getSession({ headers }),
      catch: (cause) => new AuthProviderError({ cause })
    }).pipe(
      Effect.map((session) =>
        session
          ? {
              user: { id: session.user.id },
              session: { id: session.session.id }
            }
          : null
      )
    ),
  userHasPermission: (headers, permissions) =>
    Effect.tryPromise({
      try: async () => {
        const result = await auth.api.userHasPermission({
          headers,
          body: { permissions }
        });

        return result.success;
      },
      catch: (cause) => new AuthProviderError({ cause })
    })
});

export const makeAuthServiceTest = (implementation: Context.Tag.Service<AuthService>) =>
  Layer.succeed(AuthService, implementation);

export const authenticate = (headers: Headers) =>
  Effect.gen(function* () {
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
        sessionRepo.findById(authSession.session.id).pipe(
          Effect.catchTags({
            SqlError: (cause) => Effect.fail(new AuthEntityLookupError({ cause })),
            DBNotFoundError: () => Effect.fail(new UnauthorizedError())
          })
        )
      ],
      { concurrency: 'unbounded' }
    );
    return { user, session } as UserAndSession;
  });

export const requirePermissions =
  (headers: Headers, permissions: Permissions) =>
  (userAndSession: UserAndSession) =>
    Effect.gen(function* () {
      const authService = yield* AuthService;
      const allowed = yield* authService.userHasPermission(headers, permissions);

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
