import {
  makeRecordRepoTest,
  makeSessionRepoTest,
  makeUserRepoTest,
  type AdminUserRow,
  type Session,
  type User
} from '@repo/db';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import { makeAuthServiceTest, type Permissions } from '../../lib/effect-auth';
import { listAdminUsersRouteProgram } from './users.handler';

const user = (): User => ({
  id: 'user-1',
  name: 'spryon',
  email: 'admin@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-02-01T00:00:00.000Z'),
  updatedAt: new Date('2026-02-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'admin',
  banned: false,
  banReason: null,
  banExpires: null
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

const row = (overrides: Partial<AdminUserRow> = {}): AdminUserRow => ({
  id: 'user-2',
  name: 'nyx_operator',
  email: 'nyx@example.com',
  role: 'user',
  banned: false,
  banReason: null,
  banExpires: null,
  createdAt: new Date('2026-08-01T00:00:00.000Z'),
  activeSessions: 1,
  apiKeys: 1,
  lastSeen: new Date('2026-08-18T09:37:00.000Z'),
  ...overrides
});

const getFailure = <E>(exit: Exit.Exit<unknown, E>) => {
  if (!Exit.isFailure(exit)) throw new Error('Expected effect to fail');
  const failure = Cause.failureOption(exit.cause);
  if (Option.isNone(failure)) throw new Error('Expected typed failure');
  return failure.value;
};

const grantsEvery = (granted: Permissions, requested: Permissions): boolean =>
  Object.entries(requested).every(([resource, actions]) =>
    actions.every((action) => (granted[resource] ?? []).includes(action))
  );

const makeLayer = (
  options: { granted?: Permissions; hasSession?: boolean; rows?: AdminUserRow[] } = {}
) => {
  const currentUser = user();
  const currentSession = session();
  const granted = options.granted ?? { management: ['access'] };
  const hasSession = options.hasSession ?? true;

  return Layer.mergeAll(
    makeAuthServiceTest({
      getSession: () =>
        Effect.succeed(
          hasSession ? { user: { id: currentUser.id }, session: { id: currentSession.id } } : null
        ),
      userHasPermission: (_principal, requested) => Effect.succeed(grantsEvery(granted, requested))
    }),
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser),
      listForAdmin: () => Effect.succeed(options.rows ?? [row()])
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    makeRecordRepoTest({
      findByHash: () => Effect.succeed(Option.none()),
      addNamespaces: () => Effect.succeed(Option.none()),
      insert: () => Effect.succeed({ id: 'record-1', inserted: true, status: 'staging' }),
      nearest: () => Effect.succeed([]),
      lexical: () => Effect.succeed([]),
      getById: () => Effect.succeed(Option.none()),
      sourcesFor: () => Effect.succeed(new Map()),
      updateStatus: () => Effect.succeed(Option.none()),
      listByStatus: () => Effect.succeed([])
    })
  );
};

describe('admin users route program', () => {
  it('returns the directory for a caller holding management:access', async () => {
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(Effect.provide(makeLayer()))
    );
    expect(result.users).toHaveLength(1);
    expect(result.users[0]).toMatchObject({
      id: 'user-2',
      name: 'nyx_operator',
      role: 'user',
      banned: false,
      activeSessions: 1,
      apiKeys: 1
    });
  });

  // The DTO is curated deliberately — an admin directory must not become the
  // place every account column leaks from.
  it('withholds account fields the screen does not show', async () => {
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(Effect.provide(makeLayer()))
    );
    const dto = result.users[0]!;
    expect(dto).not.toHaveProperty('image');
    expect(dto).not.toHaveProperty('emailVerified');
    expect(dto).not.toHaveProperty('isAnonymous');
    expect(dto).not.toHaveProperty('updatedAt');
  });

  it('collapses a null `banned` column to false', async () => {
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ rows: [row({ banned: null })] }))
      )
    );
    expect(result.users[0]!.banned).toBe(false);
  });

  it('carries a ban through with its reason and expiry', async () => {
    const banExpires = new Date('2026-09-30T00:00:00.000Z');
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(
        Effect.provide(
          makeLayer({
            rows: [row({ banned: true, banReason: 'scripted key churn', banExpires })]
          })
        )
      )
    );
    expect(result.users[0]).toMatchObject({
      banned: true,
      banReason: 'scripted key churn',
      banExpires
    });
  });

  it('surfaces an account that has never used a key as lastSeen null', async () => {
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ rows: [row({ apiKeys: 0, lastSeen: null })] }))
      )
    );
    expect(result.users[0]).toMatchObject({ apiKeys: 0, lastSeen: null });
  });

  it('fails with UnauthorizedError when there is no session', async () => {
    const exit = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });

  // record:read is what a plain user carries — it must not open the directory.
  it('fails with ForbiddenError for a caller without management:access', async () => {
    const exit = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ granted: { record: ['read'] } })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });

  it('returns an empty directory rather than failing when there are no rows', async () => {
    const result = await Effect.runPromise(
      listAdminUsersRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ rows: [] })))
    );
    expect(result.users).toEqual([]);
  });
});
