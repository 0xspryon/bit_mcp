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
import {
  createKeyRouteProgram,
  refreshKeyRouteProgram,
  revokeKeyRouteProgram
} from './key.handler';

const user = (role: User['role'] = 'user'): User => ({
  id: 'user-1',
  name: 'nyx_operator',
  email: 'nyx@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-08-01T00:00:00.000Z'),
  updatedAt: new Date('2026-08-01T00:00:00.000Z'),
  isAnonymous: false,
  role,
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
    role?: User['role'];
  } = {}
) => {
  const currentUser = user(options.role ?? 'user');
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
      delete: (_headers, keyId) =>
        options.deleteFails
          ? Effect.fail(new ApiKeyProviderError({ cause: 'delete failed' }))
          : Effect.sync(() => {
              trace.push(`delete:${keyId}`);
            }),
      // The owner and tier are recorded: with a single api-key configuration
      // these arguments ARE the tiering mechanism, so what the program hands
      // over is the contract worth pinning.
      create: (userId, role) =>
        options.createFails
          ? Effect.fail(new ApiKeyProviderError({ cause: 'create failed' }))
          : Effect.sync(() => {
              trace.push(`create:${userId}:${role ?? 'none'}`);
              return created();
            })
    })
  );
};


describe('create key route program', () => {
  it('mints for an account holding no key, tiered from the stored role', async () => {
    const trace: string[] = [];
    const dto = await Effect.runPromise(
      createKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ trace, existing: [], role: 'admin' }))
      )
    );
    expect(trace).toEqual(['list', 'create:user-1:admin']);
    expect(dto.key).toBe(created().key);
  });

  // The rule better-auth's own hook cannot enforce for us: `ApiKeyService.create`
  // calls it without headers, so the hook sees no session and never fires.
  it('refuses a second key rather than minting one', async () => {
    const trace: string[] = [];
    const exit = await Effect.runPromiseExit(
      createKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ trace })))
    );
    expect(getFailure(exit)._tag).toBe('ApiKeyConflictError');
    // The point of the assertion: it stopped BEFORE minting.
    expect(trace).toEqual(['list']);
  });

  it('treats a disabled key as no key at all', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      createKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ trace, existing: [keyInfo({ enabled: false })] }))
      )
    );
    expect(trace).toEqual(['list', 'create:user-1:user']);
  });

  it('fails with UnauthorizedError when there is no session', async () => {
    const exit = await Effect.runPromiseExit(
      createKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ hasSession: false })))
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });
});

describe('revoke key route program', () => {
  const revoke = (existing: ApiKeyInfo[], trace: string[]) =>
    Effect.runPromise(
      revokeKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ trace, existing })))
    );

  it('revokes every enabled key and reports how many', async () => {
    const trace: string[] = [];
    const result = await revoke([keyInfo({ id: 'k1' }), keyInfo({ id: 'k2' })], trace);
    expect(trace).toEqual(['list', 'delete:k1', 'delete:k2']);
    expect(result).toEqual({ revoked: 2 });
  });

  // A disabled key authenticates nothing, so deleting it would be work the
  // owner did not ask for — and would make the returned count a lie.
  it('leaves a disabled key alone and counts only what it revoked', async () => {
    const trace: string[] = [];
    const result = await revoke([keyInfo({ id: 'k1' }), keyInfo({ id: 'k2', enabled: false })], trace);
    expect(trace).toEqual(['list', 'delete:k1']);
    expect(result).toEqual({ revoked: 1 });
  });

  it('reports zero rather than failing when there is nothing to revoke', async () => {
    const trace: string[] = [];
    expect(await revoke([], trace)).toEqual({ revoked: 0 });
    expect(trace).toEqual(['list']);
  });

  // The whole point of splitting revoke out of refresh: it must NOT mint.
  it('never mints a replacement', async () => {
    const trace: string[] = [];
    await revoke([keyInfo({ id: 'k1' })], trace);
    expect(trace.some((step) => step.startsWith('create'))).toBe(false);
  });

  it('surfaces a provider failure from the delete', async () => {
    const exit = await Effect.runPromiseExit(
      revokeKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ deleteFails: true }))
      )
    );
    expect(getFailure(exit)._tag).toBe('ApiKeyProviderError');
  });

  it('fails with UnauthorizedError when there is no session', async () => {
    const exit = await Effect.runPromiseExit(
      revokeKeyRouteProgram(new Headers()).pipe(Effect.provide(makeLayer({ hasSession: false })))
    );
    expect(getFailure(exit)._tag).toBe('UnauthorizedError');
  });
});

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
    expect(trace).toEqual(['list', 'delete:key-old', 'create:user-1:user']);
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
    expect(trace).toEqual(['list', 'delete:k1', 'delete:k2', 'create:user-1:user']);
  });

  // Replaces an older regression about deleting `configId: 'admin'` keys. That
  // whole class of failure came from tiering by configuration, and collapsing
  // to one configuration retired it: a key minted under the previous scheme is
  // revoked by id like any other, with no tier to name.
  it('revokes a legacy admin-tier key with no configuration to name', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(
          makeLayer({ trace, existing: [keyInfo({ id: 'k-admin', configId: 'admin' })] })
        )
      )
    );
    expect(trace).toEqual(['list', 'delete:k-admin', 'create:user-1:user']);
  });

  // The tier now rides on the key itself, so the role handed to `create` is the
  // whole mechanism. It must come from the user row the server loaded — a
  // caller who could influence it would be setting their own rate limit.
  it('mints an admin a key tiered from their stored role', async () => {
    const trace: string[] = [];
    await Effect.runPromise(
      refreshKeyRouteProgram(new Headers()).pipe(
        Effect.provide(makeLayer({ trace, existing: [], role: 'admin' }))
      )
    );
    expect(trace).toEqual(['list', 'create:user-1:admin']);
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
    expect(trace).toEqual(['list', 'create:user-1:user']);
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
    expect(trace).toEqual(['list', 'create:user-1:user']);
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
