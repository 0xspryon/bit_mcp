import { Cause, Console, Effect, Exit, Logger, LogLevel, Option } from 'effect';
import type { HonoContext, HonoEnv } from '../../app-env';
import { ApiKeyConflictError, ApiKeyService, type CreatedApiKey } from '../../lib/api-keys';
import type { Role } from '../../lib/auth-roles';
import {
  authErrorToResponse,
  authenticate,
  handleNever,
  isAuthError
} from '../../lib/effect-auth';

/** The one-shot response for any route that MINTS a key — create and refresh
 * alike: metadata plus the secret, which is never retrievable again. Dates are
 * serialized by Hono's json(); the client formats them. */
export interface IssuedKeyDto {
  readonly id: string;
  readonly key: string;
  readonly start: string | null;
  readonly configId: string | null;
  readonly rateLimitMax: number | null;
  readonly rateLimitTimeWindow: number | null;
  readonly requestCount: number;
  readonly createdAt: Date;
}

const toIssuedKeyDto = (created: CreatedApiKey): IssuedKeyDto => ({
  id: created.id,
  key: created.key,
  start: created.start,
  configId: created.configId,
  rateLimitMax: created.rateLimitMax,
  rateLimitTimeWindow: created.rateLimitTimeWindow,
  requestCount: created.requestCount,
  createdAt: created.createdAt
});

/**
 * Revoke every usable key the caller holds, and say how many there were.
 *
 * Takes the already-authenticated caller's headers rather than re-authenticating
 * so the three route programs below cost one session lookup each, not two.
 * Disabled keys are left alone: they authenticate nothing, and deleting rows the
 * owner cannot see would make the returned count a lie.
 */
const revokeEnabledKeys = (headers: Headers) =>
  Effect.gen(function*() {
    const keys = yield* ApiKeyService;
    const enabled = (yield* keys.list(headers)).filter((k) => k.enabled);
    yield* Effect.forEach(enabled, (k) => keys.delete(headers, k.id), { discard: true });
    return enabled.length;
  });

/** Mint one key for an already-authenticated owner. */
const mintKeyFor = (userId: string, role: Role | null) =>
  Effect.gen(function*() {
    const keys = yield* ApiKeyService;
    return toIssuedKeyDto(yield* keys.create(userId, role));
  });

/**
 * `POST /api/v1/me/key` — mint the caller's key.
 *
 * Ours rather than better-auth's `/api-key/create` because the tier has to be
 * set server-side: `rateLimitMax` is rejected outright on any call carrying
 * request headers, so the only way to tier a key is to authenticate here, read
 * the role from the caller's own database row, and mint without forwarding
 * their headers. A browser calling better-auth directly still works — it just
 * lands on the configuration's floor limit, which fails safe.
 */
export const createKeyRouteProgram = (headers: Headers) =>
  Effect.gen(function*() {
    const { user } = yield* authenticate(headers);
    const keys = yield* ApiKeyService;

    // One key per account, and this route is the only place that can enforce
    // it. better-auth's own create route has the same guard in the `auth.ts`
    // before-hook, but that hook reads the session off the request and
    // `ApiKeyService.create` calls better-auth WITHOUT headers — so nothing
    // there fires for us. See {@link ApiKeyConflictError}.
    //
    // Deliberately NOT hoisted into a shared step with the mint below: refresh
    // has just deleted every key when it mints, so making this part of minting
    // would cost it a second `list` to re-learn what it already knows.
    const existing = yield* keys.list(headers);
    if (existing.some((k) => k.enabled)) {
      return yield* Effect.fail(new ApiKeyConflictError());
    }

    return yield* mintKeyFor(user.id, user.role);
  });

export type CreateKeyRouteError = Effect.Effect.Error<ReturnType<typeof createKeyRouteProgram>>;

/**
 * `POST /api/v1/me/key/revoke` — revoke the caller's key.
 *
 * Deliberately takes NO key id. bit allows one key per account, better-auth
 * scopes every one of these calls to the session, and an id in the body would
 * be an authorization decision this route would then have to make. "Revoke what
 * I hold" needs no such decision.
 */
export const revokeKeyRouteProgram = (headers: Headers) =>
  Effect.gen(function*() {
    yield* authenticate(headers);
    const revoked = yield* revokeEnabledKeys(headers);
    return { revoked };
  });

export type RevokeKeyRouteError = Effect.Effect.Error<ReturnType<typeof revokeKeyRouteProgram>>;

/**
 * `POST /api/v1/me/key/refresh` — replace the caller's API key in one step.
 *
 * Why this is a route and not two client calls: bit's contract is one key per
 * account, and the console's REFRESH action has to leave the account holding
 * exactly one usable key. Driving create-then-delete from the browser can
 * strand it holding two (if the delete fails) or, worse, leave a stale key
 * authenticating alongside the new one.
 *
 * REVOKE-THEN-MINT, deliberately in that order. Two reasons:
 *
 *  1. Safety. A crash between the steps leaves the account with NO key, which
 *     the owner fixes by pressing create. The reverse ordering would leave two
 *     live keys, one of which nobody is looking at — strictly worse for a
 *     credential.
 *  2. It is the only order that works. The `/api-key/create` before-hook in
 *     auth.ts rejects a second key, and server-side `auth.api.*` calls run
 *     through that same hook pipeline — so minting first would trip our own
 *     guard.
 *
 * With no key to begin with this degenerates to a plain create rather than
 * failing: the caller's intent is "leave me holding one fresh key", and that
 * is the end state either way.
 */
export const refreshKeyRouteProgram = (headers: Headers) =>
  Effect.gen(function*() {
    // Any signed-in caller may rotate their OWN key; better-auth scopes every
    // one of these calls to the session, so there is no id to authorize here.
    // The caller's own row is what tiers the new key, so keep the result: the
    // role must come from the database, never from the request.
    const { user } = yield* authenticate(headers);

    // The same two steps the create and revoke routes run, in the order the
    // docblock above argues for. Composing them rather than restating them is
    // what keeps "refresh" from drifting away from its own halves.
    yield* revokeEnabledKeys(headers);
    return yield* mintKeyFor(user.id, user.role);
  });

export type RefreshKeyRouteError = Effect.Effect.Error<ReturnType<typeof refreshKeyRouteProgram>>;

const createKeyErrorToResponse = (c: HonoContext<HonoEnv>, error: CreateKeyRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);

  switch (error._tag) {
    case 'ApiKeyConflictError':
      // 409, not 500: the account is in a state the caller can resolve, and the
      // message names both ways out rather than leaving them stuck.
      return c.json(
        {
          error: {
            code: 'API_KEY_ALREADY_EXISTS' as const,
            message: 'This account already holds an API key. Refresh or revoke it instead.'
          }
        },
        409
      );
    case 'ApiKeyProviderError':
      return c.json(
        {
          error: {
            code: 'API_KEY_PROVIDER_FAILED' as const,
            // Nothing was revoked on this path, so unlike refresh the caller's
            // existing state is untouched — say that plainly.
            message: 'Could not issue a key. Nothing was changed.'
          }
        },
        500
      );
    default:
      return handleNever(c, error);
  }
};

export async function createKeyHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const exit: Exit.Exit<IssuedKeyDto, CreateKeyRouteError> = await runtime.runPromiseExit(
    createKeyRouteProgram(c.req.raw.headers)
  );

  return Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return createKeyErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });
}

const revokeKeyErrorToResponse = (c: HonoContext<HonoEnv>, error: RevokeKeyRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);

  switch (error._tag) {
    case 'ApiKeyProviderError':
      return c.json(
        {
          error: {
            code: 'API_KEY_PROVIDER_FAILED' as const,
            // Revocation walks the caller's keys one at a time, so a failure
            // partway through can leave some already gone. Do not promise that
            // nothing happened.
            message: 'Could not revoke the key. Some keys may already be revoked.'
          }
        },
        500
      );
    default:
      return handleNever(c, error);
  }
};

export async function revokeKeyHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const exit: Exit.Exit<{ revoked: number }, RevokeKeyRouteError> = await runtime.runPromiseExit(
    revokeKeyRouteProgram(c.req.raw.headers)
  );

  return Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return revokeKeyErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });
}

const refreshKeyErrorToResponse = (c: HonoContext<HonoEnv>, error: RefreshKeyRouteError) => {
  if (isAuthError(error)) return authErrorToResponse(c, error);

  switch (error._tag) {
    case 'ApiKeyProviderError':
      return c.json(
        {
          error: {
            code: 'API_KEY_PROVIDER_FAILED' as const,
            // The old key may already be gone at this point, so say so rather
            // than implying nothing happened — the recovery is to create one.
            message: 'Could not issue a new key. Your previous key may already be revoked.'
          }
        },
        500
      );
    default:
      return handleNever(c, error);
  }
};

export async function refreshKeyHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const exit: Exit.Exit<IssuedKeyDto, RefreshKeyRouteError> = await runtime.runPromiseExit(
    refreshKeyRouteProgram(c.req.raw.headers)
  );

  return Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      const failure = Cause.failureOption(cause);
      if (Option.isSome(failure)) {
        return refreshKeyErrorToResponse(c, failure.value);
      }
      return c.json(
        { error: { code: 'INTERNAL_SERVER_ERROR' as const, message: 'Unexpected server error.' } },
        500
      );
    }
  });
}
