import { makeSessionRepoTest, makeUserRepoTest, type Session, type User } from '@repo/db';
import { Cause, Effect, Exit, Layer, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  ApiKeyProviderError,
  makeApiKeyServiceTest,
  type ApiKeyInfo,
  type CreatedApiKey
} from '../../lib/api-keys';
import { makeAuthServiceTest } from '../../lib/effect-auth';
import { refreshKeyRouteProgram } from './key.handler';

const user = (): User => ({
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

const keyInfo = (overrides: Partial<ApiKeyInfo> = {}): ApiKeyInfo => ({
  id: 'key-old',
  start: 'bit_sk_1111',
  prefix: 'bit_sk_',
  configId: 'default',
  rateLimitMax: 20,
  rateLimitTimeWindow: 60_000,
  requestCount: 6,
  remaining: null,
  lastRequest: new Date('2026-08-18T09:37:00.000Z'),
  createdAt: new Date('2026-08-18T09:41:00.000Z'),
  enabled: true,
  ...overrides
});

const created = (): CreatedApiKey => ({
  ...keyInfo({ id: 'key-new', start: 'bit_sk_7f2c', requestCount: 0 }),
  key: 'bit_sk_7f2c91ae4d0b38e5aa61c7d4f09b2e83'
});

const getFailure = <E>(exit: Exit.Exit<unknown, E>) => {
  if (!Exit.isFailure(exit)) throw new Error('Expected effect to fail');
  const failure = Cause.failureOption(exit.cause);
  if (Option.isNone(failure)) throw new Error('Expected typed failure');
  return failure.value;
};

/** Records the order of api-key operations so the revoke-before-mint contract
 * can be asserted, not just its end state. */
const makeLayer = (
  options: {
    hasSession?: boolean;
    existing?: ApiKeyInfo[];
    createFails?: boolean;
    deleteFails?: boolean;
    trace?: string[];
  } = {}
) => {
  const currentUser = user();
  const currentSession = session();
  const trace = options.trace ?? [];

  return Layer.mergeAll(
    makeAuthServiceTest({
      getSession: () =>
        Effect.succeed(
          (options.hasSession ?? true)
            ? { user: { id: currentUser.id }, session: { id: currentSession.id } }
            : null
        ),
      userHasPermission: () => Effect.succeed(true)
    }),
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser),
      listForAdmin: () => Effect.succeed([])
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    makeApiKeyServiceTest({
      list: () =>
        Effect.sync(() => {
          trace.push('list');
          return options.existing ?? [keyInfo()];
        }),
      delete: (_headers, keyId, configId) =>
        options.deleteFails
          ? Effect.fail(new ApiKeyProviderError({ cause: 'delete failed' }))
          : Effect.sync(() => {
              // configId is recorded because omitting it makes better-auth
              // resolve the DEFAULT configuration and 404 any key stored under
              // another one — an admin-tier key would be unrevokable.
              trace.push(`delete:${keyId}:${configId ?? 'none'}`);
            }),
      create: () =>
        options.createFails
          ? Effect.fail(new ApiKeyProviderError({ cause: 'create failed' }))
          : Effect.sync(() => {
              trace.push('create');
              return created();
            })
    })
  );
};

describe('refresh key route program', () => {
  it('returns the new secret exactly once, with its metadata', async () => {
    const result = await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer()))
    );
    expect(result).toMatchObject({
      id: 'key-new',
      key: 'bit_sk_7f2c91ae4d0b38e5aa61c7d4f09b2e83',
      start: 'bit_sk_7f2c',
      configId: 'default',
      rateLimitMax: 20,
      requestCount: 0
    });
  });

  // The contract that makes this a server route rather than two client calls:
  // the old key must stop authenticating BEFORE a new one exists, so there is
  // never a window with two live credentials on one account.
  it('revokes the existing key before minting the replacement', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ trace })))
    );
    expect(trace).toEqual(['list', 'delete:key-old:default', 'create']);
  });

  it('revokes every enabled key, not just the first', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(
          makeLayer({ trace, existing: [keyInfo({ id: 'k1' }), keyInfo({ id: 'k2' })] })
        )
      )
    );
    expect(trace).toEqual(['list', 'delete:k1:default', 'delete:k2:default', 'create']);
  });

  // Regression: an admin's key is stored with configId 'admin'. Deleting it
  // under the default configuration 404s, which would leave the highest
  // -privilege credential in the system impossible to rotate or revoke.
  it('deletes an admin-tier key under its own configuration', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(
          makeLayer({ trace, existing: [keyInfo({ id: 'k-admin', configId: 'admin' })] })
        )
      )
    );
    expect(trace).toEqual(['list', 'delete:k-admin:admin', 'create']);
  });

  it('leaves an already-disabled key alone', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(
          makeLayer({ trace, existing: [keyInfo({ id: 'k1', enabled: false })] })
        )
      )
    );
    expect(trace).toEqual(['list', 'create']);
  });

  // Refreshing with nothing to refresh is the caller's intent either way —
  // "leave me holding one fresh key" — so it degenerates to a create.
  it('degenerates to a plain create when the account holds no key', async () => {
    const trace: string[] = [];
    const result = await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ trace, existing: [] }))
      )
    );
    expect(trace).toEqual(['list', 'create']);
    expect(result.key).toBe('bit_sk_7f2c91ae4d0b38e5aa61c7d4f09b2e83');
  });

  it('fails with UnauthorizedError when there is no session', async () => {
    const exit = await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ hasSession: false })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });

  it('surfaces a provider failure on mint', async () => {
    const exit = await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ createFails: true })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ApiKeyProviderError');
  });

  // A failed revoke must abort before minting — otherwise the account ends up
  // holding two live keys, which is the exact state this route exists to avoid.
  it('does not mint when the revoke fails', async () => {
    const trace: string[] = [];
    const exit = await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ trace, deleteFails: true })),
        Effect.exit
      )
    );
    expect(getFailure(exit)._tag).toBe('ApiKeyProviderError');
    expect(trace).not.toContain('create');
  });
});
