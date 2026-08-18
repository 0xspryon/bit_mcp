import {
  makeRecordRepoTest,
  makeSessionRepoTest,
  makeSourceRepoTest,
  makeUserRepoTest,
  type Session,
  type User
} from '@repo/db';
import { makeEmbeddingServiceTest, makeIngestServiceTest } from '@repo/rag-core';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import type { HonoContext, HonoEnv } from '../../app-env';
import { makeAuthServiceTest, type Permissions } from '../../lib/effect-auth';
import { ingestRouteProgram } from './ingest.handler';

const user = (overrides: Partial<User> = {}): User => ({
  id: 'user-1',
  name: 'Ad Min',
  email: 'admin@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'admin',
  banned: false,
  banReason: null,
  banExpires: null,
  ...overrides
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

const contextWithJson = (body: unknown) =>
  ({ req: { json: async () => body } }) as HonoContext<HonoEnv>;

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
    currentUser?: User;
  } = {}
) => {
  const currentUser = options.currentUser ?? user();
  const currentSession = session();
  const granted = options.granted ?? { management: ['access'] };
  const hasSession = options.hasSession ?? true;

  const auth = makeAuthServiceTest({
    getSession: () =>
      Effect.succeed(
        hasSession ? { user: { id: currentUser.id }, session: { id: currentSession.id } } : null
      ),
    userHasPermission: (_principal, requested) => Effect.succeed(grantsEvery(granted, requested))
  });

  const ingest = makeIngestServiceTest().pipe(
    Layer.provide(
      Layer.mergeAll(
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
        }),
        makeSourceRepoTest({
          upsertByUrl: () => Effect.succeed('source-1'),
          getById: () => Effect.succeed(Option.none())
        }),
        makeEmbeddingServiceTest()
      )
    )
  );

  return Layer.mergeAll(
    auth,
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser),
      // The admin directory is exercised in its own tests; these doubles
      // only need the member to satisfy the repo's shape.
      listForAdmin: () => Effect.succeed([])
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    ingest
  );
};

const validBody = {
  namespaces: ['acme'],
  title: 'SQL injection in login form',
  symptom: 'error-based boolean on username',
  procedure: 'inject a quote and observe the 500'
};

describe('ingest route program', () => {
  it('ingests a valid record for a caller with record:ingest', async () => {
    const result = await Effect.runPromise(
      ingestRouteProgram(contextWithJson(validBody), new Headers()).pipe(
        Effect.provide(makeLayer())
      )
    );
    expect(result).toEqual({ id: 'record-1', deduped: false, status: 'staging' });
  });

  it('rejects an invalid record body with RecordInputParseError (400)', async () => {
    const exit = await Effect.runPromise(
      ingestRouteProgram(contextWithJson({ namespaces: ['acme'] }), new Headers()).pipe(
        Effect.provide(makeLayer()),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RecordInputParseError');
  });

  it('fails with UnauthorizedError (401) when there is no session', async () => {
    const exit = await Effect.runPromise(
      ingestRouteProgram(contextWithJson(validBody), new Headers()).pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });

  it('fails with ForbiddenError (403) when record:ingest is denied', async () => {
    const exit = await Effect.runPromise(
      ingestRouteProgram(contextWithJson(validBody), new Headers()).pipe(
        Effect.provide(makeLayer({ granted: { record: ['read'] } })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });

  it('requires record:ingest specifically — a read-only grant is forbidden', async () => {
    const exit = await Effect.runPromise(
      ingestRouteProgram(contextWithJson(validBody), new Headers()).pipe(
        Effect.provide(makeLayer({ granted: { record: ['read'] } })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });
});
