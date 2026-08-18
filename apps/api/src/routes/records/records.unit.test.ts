import {
  makeRecordRepoTest,
  makeSessionRepoTest,
  makeUserRepoTest,
  type RecordRow,
  type Session,
  type User
} from '@repo/db';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import { makeAuthServiceTest, type Permissions } from '../../lib/effect-auth';
import {
  listRecordsRouteProgram,
  recordByIdRouteProgram,
  updateRecordStatusRouteProgram
} from './records.handler';

const user = (): User => ({
  id: 'user-1',
  name: 'Reg Ular',
  email: 'user@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'user',
  banned: false,
  banReason: null,
  banExpires: null
});

const session = (): Session => ({
  id: 'session-1',
  expiresAt: new Date('2026-07-02T00:00:00.000Z'),
  token: 'token',
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  ipAddress: null,
  userAgent: null,
  userId: 'user-1',
  impersonatedBy: null,
  activeOrganizationId: null
});

const record = (overrides: Partial<RecordRow> = {}): RecordRow => ({
  id: 'record-1',
  namespaces: ['acme'],
  title: 'SQL injection in login form',
  symptom: 'error-based boolean on username',
  whenToUse: null,
  procedure: 'inject a quote and observe the 500',
  confirmationSignal: null,
  preconditions: [],
  appliesTo: [],
  cwe: [],
  vrt: [],
  chainsWith: [],
  qualityTier: 2,
  status: 'active',
  version: 1,
  contentHash: 'hash-1',
  embedding: [],
  fts: '',
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  deletedAt: null,
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
  options: {
    granted?: Permissions;
    hasSession?: boolean;
    found?: RecordRow | null;
    updateFound?: boolean;
    statusRows?: RecordRow[];
  } = {}
) => {
  const currentUser = user();
  const currentSession = session();
  const granted = options.granted ?? { management: ['access'] };
  const hasSession = options.hasSession ?? true;
  const found = options.found === undefined ? record() : options.found;
  const updateFound = options.updateFound ?? true;

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
      // The admin directory is exercised in its own tests; these doubles
      // only need the member to satisfy the repo's shape.
      listForAdmin: () => Effect.succeed([])
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    makeRecordRepoTest({
      findByHash: () => Effect.succeed(Option.none()),
      addNamespaces: () => Effect.succeed(Option.none()),
      insert: () => Effect.succeed({ id: 'record-1', inserted: true, status: 'staging' }),
      nearest: () => Effect.succeed([]),
      lexical: () => Effect.succeed([]),
      getById: () => Effect.succeed(found ? Option.some(found) : Option.none()),
      sourcesFor: () => Effect.succeed(new Map()),
      updateStatus: (id, status) =>
        Effect.succeed(updateFound ? Option.some(record({ id, status })) : Option.none()),
      listByStatus: (status) => Effect.succeed(options.statusRows ?? [record({ status })])
    })
  );
};

const VALID_ID = '11111111-1111-4111-8111-111111111111';

describe('records route program', () => {
  it('returns the record for a caller with record:read', async () => {
    const result = await Effect.runPromise(
      recordByIdRouteProgram(new Headers(), VALID_ID).pipe(Effect.provide(makeLayer()))
    );
    expect(result).toMatchObject({ id: 'record-1', namespaces: ['acme'], status: 'active' });
  });

  it('fails with RecordNotFoundError (404) for a well-formed but unknown id', async () => {
    const exit = await Effect.runPromise(
      recordByIdRouteProgram(new Headers(), VALID_ID).pipe(
        Effect.provide(makeLayer({ found: null })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RecordNotFoundError');
  });

  it('fails with RecordNotFoundError (404) for a malformed (non-uuid) id', async () => {
    const exit = await Effect.runPromise(
      recordByIdRouteProgram(new Headers(), 'not-a-uuid').pipe(
        Effect.provide(makeLayer()),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RecordNotFoundError');
  });

  it('fails with UnauthorizedError (401) when there is no session', async () => {
    const exit = await Effect.runPromise(
      recordByIdRouteProgram(new Headers(), 'record-1').pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });

  it('fails with ForbiddenError (403) when management access is denied', async () => {
    const exit = await Effect.runPromise(
      recordByIdRouteProgram(new Headers(), VALID_ID).pipe(
        Effect.provide(makeLayer({ granted: {} })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });
});

describe('records admin curation', () => {
  it('promotes a record to active for an admin', async () => {
    const result = await Effect.runPromise(
      updateRecordStatusRouteProgram(new Headers(), VALID_ID, { status: 'active' }).pipe(
        Effect.provide(makeLayer())
      )
    );
    expect(result).toMatchObject({ id: VALID_ID, status: 'active' });
  });

  it('rejects an invalid status with a 400 validation error', async () => {
    const exit = await Effect.runPromise(
      updateRecordStatusRouteProgram(new Headers(), VALID_ID, { status: 'bogus' }).pipe(
        Effect.provide(makeLayer()),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RequestValidationError');
  });

  it('404s when promoting an unknown id', async () => {
    const exit = await Effect.runPromise(
      updateRecordStatusRouteProgram(new Headers(), VALID_ID, { status: 'active' }).pipe(
        Effect.provide(makeLayer({ updateFound: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RecordNotFoundError');
  });

  it('forbids status changes without management access', async () => {
    const exit = await Effect.runPromise(
      updateRecordStatusRouteProgram(new Headers(), VALID_ID, { status: 'active' }).pipe(
        Effect.provide(makeLayer({ granted: {} })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });

  it('lists records by status (defaults to staging) for an admin', async () => {
    const result = await Effect.runPromise(
      listRecordsRouteProgram(new Headers(), {}).pipe(Effect.provide(makeLayer()))
    );
    expect(Array.isArray(result)).toBe(true);
    expect(result[0]).toMatchObject({ status: 'staging' });
  });

  it('forbids listing without management access', async () => {
    const exit = await Effect.runPromise(
      listRecordsRouteProgram(new Headers(), {}).pipe(
        Effect.provide(makeLayer({ granted: {} })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });
});
