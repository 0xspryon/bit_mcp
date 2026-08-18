import { type AdminUserRow, type DbError, UserRepo } from '@repo/db';
import { Cause, Data, Effect, Exit, Option } from 'effect';
import type { HonoContext, HonoEnv } from '../../app-env';
import {
  authErrorToResponse,
  authenticate,
  handleNever,
  isAuthError,
  requirePermissions
} from '../../lib/effect-auth';

// Recover the SqlError arm of the repo error channel without a direct
// `@effect/sql` dependency in this app (mirrors `lib/effect-auth`).
type SqlError = Exclude<DbError, { _tag: 'DBNotFoundError' }>;

/** A repo/SQL failure, re-tagged so the route error stays a closed union. */
class AdminUserRepoError extends Data.TaggedError('AdminUserRepoError')<{ cause: SqlError }> {}

/**
 * One account as the console renders it. A curated DTO, NOT the raw row:
 * `image`, `emailVerified`, `isAnonymous` and `updatedAt` are all withheld
 * because nothing in the users screen shows them, and an admin directory is
 * the wrong place to widen an account's exposed surface by default.
 */
export interface AdminUserDto {
  readonly id: string;
  readonly name: string;
  readonly email: string;
  /** `null` for a row predating the role column; the UI reads that as `user`. */
  readonly role: string | null;
  readonly banned: boolean;
  readonly banReason: string | null;
  /** `null` on a banned account means the ban is indefinite. */
  readonly banExpires: Date | null;
  readonly createdAt: Date;
  readonly activeSessions: number;
  readonly apiKeys: number;
  readonly lastSeen: Date | null;
}

const toAdminUserDto = (row: AdminUserRow): AdminUserDto => ({
  id: row.id,
  name: row.name,
  email: row.email,
  role: row.role,
  // The column is nullable with a `false` default; collapse it so the client
  // never has to distinguish "not banned" from "never set".
  banned: row.banned ?? false,
  banReason: row.banReason,
  banExpires: row.banExpires,
  createdAt: row.createdAt,
  activeSessions: row.activeSessions,
  apiKeys: row.apiKeys,
  lastSeen: row.lastSeen
});

/**
 * `GET /api/v1/admin/users` — the account directory behind the users screen.
 *
 * Admin-only via the `management:['access']` gate. This exists rather than
 * better-auth's own `list-users` because the screen needs per-account session
 * and api-key aggregates that endpoint does not join.
 *
 * Unpaginated on purpose: bit's accounts arrive one Discord sign-in at a time
 * and the screen is a single scrolling table. If that stops being true, this
 * is the place to add a cursor — the DTO already carries `createdAt`.
 */
export const listAdminUsersRouteProgram = (headers: Headers) =>
  Effect.gen(function* () {
    const authenticated = yield* authenticate(headers);
    yield* requirePermissions({ management: ['access'] })(authenticated);
    const repo = yield* UserRepo;
    const rows = yield* repo
      .listForAdmin()
      .pipe(Effect.catchTag('SqlError', (cause) => Effect.fail(new AdminUserRepoError({ cause }))));
    return { users: rows.map(toAdminUserDto) };
  });

export type AdminUsersRouteError = Effect.Effect.Error<
  ReturnType<typeof listAdminUsersRouteProgram>
>;

const adminUsersErrorToResponse = (c: HonoContext<HonoEnv>, error: AdminUsersRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);

  switch (error._tag) {
    case 'AdminUserRepoError':
      return c.json(
        { error: { code: 'ADMIN_USER_REPO_ERROR' as const, message: 'Unable to load users.' } },
        500
      );
    default:
      return handleNever(c, error);
  }
};

export async function listAdminUsersHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const exit: Exit.Exit<{ users: AdminUserDto[] }, AdminUsersRouteError> =
    await runtime.runPromiseExit(listAdminUsersRouteProgram(c.req.raw.headers));

  return Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return adminUsersErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });
}
