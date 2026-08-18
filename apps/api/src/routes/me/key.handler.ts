import { Cause, Effect, Exit, Option } from 'effect';
import type { HonoContext, HonoEnv } from '../../app-env';
import { ApiKeyService, type CreatedApiKey } from '../../lib/api-keys';
import {
  authErrorToResponse,
  authenticate,
  handleNever,
  isAuthError
} from '../../lib/effect-auth';

/** The one-shot response: metadata plus the secret, which is never retrievable
 * again. Dates are serialized by Hono's json(); the client formats them. */
export interface RefreshedKeyDto {
  readonly id: string;
  readonly key: string;
  readonly start: string | null;
  readonly configId: string | null;
  readonly rateLimitMax: number | null;
  readonly rateLimitTimeWindow: number | null;
  readonly requestCount: number;
  readonly createdAt: Date;
}

const toRefreshedKeyDto = (created: CreatedApiKey): RefreshedKeyDto => ({
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
  Effect.gen(function* () {
    // Any signed-in caller may rotate their OWN key; better-auth scopes every
    // one of these calls to the session, so there is no id to authorize here.
    yield* authenticate(headers);
    const keys = yield* ApiKeyService;

    const existing = yield* keys.list(headers);
    yield* Effect.forEach(
      existing.filter((k) => k.enabled),
      // Pass each key's OWN configId — an admin-tier key cannot be deleted
      // under the default configuration.
      (k) => keys.delete(headers, k.id, k.configId),
      { discard: true }
    );

    const created = yield* keys.create(headers);
    return toRefreshedKeyDto(created);
  });

export type RefreshKeyRouteError = Effect.Effect.Error<ReturnType<typeof refreshKeyRouteProgram>>;

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
  const exit: Exit.Exit<RefreshedKeyDto, RefreshKeyRouteError> = await runtime.runPromiseExit(
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
