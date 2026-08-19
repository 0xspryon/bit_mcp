import { DBNotFoundError, makeSessionRepoTest, makeUserRepoTest, type Session, type User } from '@repo/db';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import { APIError } from 'better-auth/api';
import {
  authenticate,
  isCredentialRejection,
  makeAuthServiceTest,
  requirePermissions,
  requireSessionRow,
  type Permissions
} from './effect-auth';

const user = (overrides: Partial<User> = {}): User => ({
  id: 'user-1',
  name: 'nyx_operator',
  email: 'nyx@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-08-01T00:00:00.000Z'),
  updatedAt: new Date('2026-08-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'user',
  banned: false,
  banReason: null,
  banExpires: null,
  ...overrides
});

const session = (): Session => ({
  id: 'session-1',
  expiresAt: new Date('2026-09-02T00:00:00.000Z'),
  token: 'token',
  createdAt: new Date('2026-08-01T00:00:00.000Z'),
  updatedAt: new Date('2026-08-01T00:00:00.000Z'),
  ipAddress: null,
  userAgent: null,
  userId: 'user-1',
  impersonatedBy: null,
  activeOrganizationId: null
});

const getFailure = <E>(exit: Exit.Exit<unknown, E>) => {
  if (!Exit.isFailure(exit)) throw new Error('Expected effect to fail');
  const failure = Cause.failureOption(exit.cause);
  if (Option.isNone(failure)) throw new Error('Expected typed failure');
  return failure.value;
};

/**
 * `sessionRow: 'missing'` models an API-KEY caller: the plugin synthesizes a
 * session whose id is the apikey row's id, so the `session` table lookup misses.
 */
const makeLayer = (
  options: {
    hasSession?: boolean;
    sessionRow?: 'present' | 'missing';
    granted?: Permissions;
    role?: string | null;
  } = {}
) => {
  const currentUser = user({ role: options.role === undefined ? 'user' : options.role });
  const currentSession = session();
  const granted = options.granted ?? { record: ['read'] };

  return Layer.mergeAll(
    makeAuthServiceTest({
      getSession: () =>
        Effect.succeed(
          (options.hasSession ?? true)
            ? { user: { id: currentUser.id }, session: { id: 'apikey-row-id' } }
            : null
        ),
      userHasPermission: (_principal, requested) =>
        Effect.succeed(
          Object.entries(requested).every(([resource, actions]) =>
            actions.every((action) => (granted[resource] ?? []).includes(action))
          )
        )
    }),
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser),
      listForAdmin: () => Effect.succeed([])
    }),
    makeSessionRepoTest({
      findById: (id) =>
        (options.sessionRow ?? 'present') === 'present'
          ? Effect.succeed(currentSession)
          : Effect.fail(new DBNotFoundError({ entity: 'session', value: id }))
    })
  );
};

// The regression these guard: better-auth throws on a refused API key instead
// of returning null, so every stale key was surfacing as an HTTP 500 and a
// JSON-RPC -32603 ("Unable to verify authentication") rather than a 401.
describe('isCredentialRejection', () => {
  // The api-key plugin genuinely uses all three for a refused credential.
  it.each([
    ['UNAUTHORIZED', 'INVALID_API_KEY'],
    ['FORBIDDEN', 'INVALID_API_KEY'],
    ['NOT_FOUND', 'KEY_NOT_FOUND'],
    ['UNAUTHORIZED', 'USER_BANNED']
  ])('treats %s / %s as a refused credential', (status, code) => {
    const error = APIError.from(status as 'UNAUTHORIZED', { code, message: 'refused' });
    expect(isCredentialRejection(error)).toBe(true);
  });

  it('does NOT fold rate limiting into "unauthenticated"', () => {
    // 429 says nothing about the key. Reporting it as unauthenticated would
    // send the caller off to mint a replacement for a working credential.
    const error = APIError.from('TOO_MANY_REQUESTS', { code: 'RATE_LIMITED', message: 'slow down' });
    expect(isCredentialRejection(error)).toBe(false);
  });

  it('keeps provider failures distinct — a 5xx is not a bad key', () => {
    const error = APIError.from('INTERNAL_SERVER_ERROR', { code: 'BOOM', message: 'provider down' });
    expect(isCredentialRejection(error)).toBe(false);
  });

  it('keeps non-APIError throws distinct — a dropped connection is not a bad key', () => {
    expect(isCredentialRejection(new Error('ECONNREFUSED'))).toBe(false);
    expect(isCredentialRejection(null)).toBe(false);
  });
});

describe('authenticate', () => {
  it('returns the session row for a cookie caller', async () => {
    const result = await Effect.runPromise(
      authenticate(new Headers()).pipe(Effect.provide(makeLayer()))
    );
    expect(Option.isSome(result.session)).toBe(true);
    expect(result.user.id).toBe('user-1');
  });

  /**
   * The regression this whole change exists for. An API-key caller has no row
   * in `session` — treating that as UnauthorizedError 401'd every agent request
   * to the MCP doorway, which is the product's primary path.
   */
  it('authenticates an API-key caller that has no session row', async () => {
    const result = await Effect.runPromise(
      authenticate(new Headers()).pipe(Effect.provide(makeLayer({ sessionRow: 'missing' })))
    );
    expect(Option.isNone(result.session)).toBe(true);
    expect(result.user.id).toBe('user-1');
  });

  it('still rejects a caller with no session at all', async () => {
    const exit = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });
});

describe('requirePermissions with an API-key caller', () => {
  // Authorization must not depend on the session row: the role comes off the
  // user, which is a real row either way.
  it('grants a permission the role holds', async () => {
    const result = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.flatMap(requirePermissions({ record: ['read'] })),
        Effect.provide(makeLayer({ sessionRow: 'missing' }))
      )
    );
    expect(Option.isNone(result.session)).toBe(true);
  });

  it('still refuses a permission the role lacks', async () => {
    const exit = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.flatMap(requirePermissions({ record: ['ingest'] })),
        Effect.provide(makeLayer({ sessionRow: 'missing', granted: { record: ['read'] } })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });

  it('still refuses an unrecognised role', async () => {
    const exit = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.flatMap(requirePermissions({ record: ['read'] })),
        Effect.provide(makeLayer({ sessionRow: 'missing', role: 'curator' })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });
});

describe('requireSessionRow', () => {
  it('hands back the row when one exists', async () => {
    const result = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.flatMap(requireSessionRow),
        Effect.provide(makeLayer())
      )
    );
    expect(result.id).toBe('session-1');
  });

  // What a future session-dependent feature gets: an explicit failure at its
  // own call site, rather than authenticate deciding on its behalf.
  it('fails for an API-key caller, at the site that needs the session', async () => {
    const exit = await Effect.runPromise(
      authenticate(new Headers()).pipe(
        Effect.flatMap(requireSessionRow),
        Effect.provide(makeLayer({ sessionRow: 'missing' })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });
});
