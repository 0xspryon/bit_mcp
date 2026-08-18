import {
  makeRecordRepoTest,
  makeSessionRepoTest,
  makeUserRepoTest,
  type RecordRow,
  type Session,
  type User
} from '@repo/db';
import {
  makeEmbeddingServiceTest,
  makeRerankServiceTest,
  makeRetrieverServiceTest
} from '@repo/rag-core';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import type { HonoContext, HonoEnv } from '../../app-env';
import { makeAuthServiceTest, type Permissions } from '../../lib/effect-auth';
import { retrieveRouteProgram } from './retrieve.handler';

const user = (overrides: Partial<User> = {}): User => ({
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
  options: { granted?: Permissions; hasSession?: boolean; records?: Array<RecordRow> } = {}
) => {
  const currentUser = user();
  const currentSession = session();
  const granted = options.granted ?? { management: ['access'] };
  const hasSession = options.hasSession ?? true;
  const records = options.records ?? [record()];

  const auth = makeAuthServiceTest({
    getSession: () =>
      Effect.succeed(
        hasSession ? { user: { id: currentUser.id }, session: { id: currentSession.id } } : null
      ),
    userHasPermission: (_headers, requested) => Effect.succeed(grantsEvery(granted, requested))
  });

  const retriever = makeRetrieverServiceTest().pipe(
    Layer.provide(
      Layer.mergeAll(
        makeRecordRepoTest({
          findByHash: () => Effect.succeed(Option.none()),
      addNamespaces: () => Effect.succeed(Option.none()),
          insert: () => Effect.succeed({ id: 'record-1', inserted: true, status: 'staging' }),
          nearest: () => Effect.succeed(records),
          lexical: () => Effect.succeed([]),
          getById: () => Effect.succeed(Option.none()),
          sourcesFor: () => Effect.succeed(new Map()),
      updateStatus: () => Effect.succeed(Option.none()),
      listByStatus: () => Effect.succeed([])
        }),
        makeEmbeddingServiceTest(),
        makeRerankServiceTest()
      )
    )
  );

  return Layer.mergeAll(
    auth,
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser)
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    retriever
  );
};

const validQuery = { query: 'sql injection login', k: 3 };

describe('retrieve route program', () => {
  it('returns chunks for a caller with record:read', async () => {
    const result = await Effect.runPromise(
      retrieveRouteProgram(contextWithJson(validQuery), new Headers()).pipe(
        Effect.provide(makeLayer())
      )
    );
    expect(result.chunks).toHaveLength(1);
    expect(result.chunks[0]).toMatchObject({
      id: 'record-1',
      namespaces: ['acme'],
      kind: 'methodology',
      quality_tier: 2
    });
  });

  it('returns retrieval diagnostics alongside the chunks', async () => {
    const result = await Effect.runPromise(
      retrieveRouteProgram(contextWithJson(validQuery), new Headers()).pipe(
        Effect.provide(makeLayer())
      )
    );
    // The fake repo yields 1 dense candidate against a CANDIDATE_K of 30, so
    // the response must tell the caller the vector leg came back short.
    expect(result.diagnostics).toEqual({
      semantic_search_k: 30,
      semantic_search_count: 1,
      semantic_search_degraded: true,
      lexical_search_k: 30,
      lexical_search_count: 0
    });
  });

  it('rejects an invalid query body with RetrieveQueryParseError (400)', async () => {
    const exit = await Effect.runPromise(
      retrieveRouteProgram(contextWithJson({}), new Headers()).pipe(
        Effect.provide(makeLayer()),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('RetrieveQueryParseError');
  });

  it('fails with UnauthorizedError (401) when there is no session', async () => {
    const exit = await Effect.runPromise(
      retrieveRouteProgram(contextWithJson(validQuery), new Headers()).pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });

  it('fails with ForbiddenError (403) when record:read is denied', async () => {
    const exit = await Effect.runPromise(
      retrieveRouteProgram(contextWithJson(validQuery), new Headers()).pipe(
        Effect.provide(makeLayer({ granted: {} })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ForbiddenError');
  });
});
