import { Context, Data, Effect, Layer } from 'effect';
import {
  API_KEY_ADMIN_TIER_MAX,
  API_KEY_RATE_WINDOW_MS,
  API_KEY_USER_TIER_MAX,
  auth
} from './auth';
import type { Role } from './auth-roles';

/**
 * The api-key metadata the console shows. Mirrors better-auth's `ApiKey` minus
 * the hashed `key` itself, which never leaves the server after creation.
 */
export type ApiKeyInfo = {
  id: string;
  /** First characters of the key, safe to display (`bit_sk_7f2c…`). */
  start: string | null;
  prefix: string | null;
  /** Which rate-limit tier applies — forced from the owner's role. */
  configId: string | null;
  rateLimitMax: number | null;
  rateLimitTimeWindow: number | null;
  requestCount: number;
  remaining: number | null;
  lastRequest: Date | null;
  createdAt: Date;
  enabled: boolean;
};

/** A freshly minted key: the metadata plus the secret, shown exactly once. */
export type CreatedApiKey = ApiKeyInfo & { key: string };

/** better-auth refused or failed the operation. */
export class ApiKeyProviderError extends Data.TaggedError('ApiKeyProviderError')<{
  cause: unknown;
}> { }

/**
 * The account already holds a usable key.
 *
 * bit's one-key-per-account rule is enforced on better-auth's own
 * `/api-key/create` route by the before-hook in `auth.ts` — but that hook reads
 * the session off the request, and `ApiKeyService.create` deliberately calls
 * better-auth with NO headers so it is allowed to set the tier. No headers
 * means no session, which means the hook's guard does not fire for us. The
 * route program owns the invariant instead, and this is how it says so.
 */
export class ApiKeyConflictError extends Data.TaggedError('ApiKeyConflictError')<{}> { }

export class ApiKeyService extends Context.Tag('@api/lib/ApiKeyService')<
  ApiKeyService,
  {
    list: (headers: Headers) => Effect.Effect<ReadonlyArray<ApiKeyInfo>, ApiKeyProviderError>;
    /**
     * Mint a key for `userId`, tiered by `role`. Takes the OWNER rather than the
     * caller's headers on purpose — see the implementation.
     */
    create: (userId: string, role: Role | null) => Effect.Effect<CreatedApiKey, ApiKeyProviderError>;
    delete: (headers: Headers, keyId: string) => Effect.Effect<void, ApiKeyProviderError>;
  }
>() { }

/** Narrow better-auth's loosely-typed row onto {@link ApiKeyInfo}. */
const toInfo = (row: Record<string, unknown>): ApiKeyInfo => ({
  id: String(row.id),
  start: (row.start as string | null) ?? null,
  prefix: (row.prefix as string | null) ?? null,
  configId: (row.configId as string | null) ?? null,
  rateLimitMax: (row.rateLimitMax as number | null) ?? null,
  rateLimitTimeWindow: (row.rateLimitTimeWindow as number | null) ?? null,
  requestCount: (row.requestCount as number | undefined) ?? 0,
  remaining: (row.remaining as number | null) ?? null,
  lastRequest: (row.lastRequest as Date | null) ?? null,
  createdAt: (row.createdAt as Date | undefined) ?? new Date(0),
  enabled: (row.enabled as boolean | undefined) ?? true
});

export const ApiKeyServiceLive = Layer.succeed(ApiKeyService, {
  list: (headers) =>
    Effect.tryPromise({
      try: async () => {
        // The endpoint answers with a page envelope, not a bare array.
        const { apiKeys } = await auth.api.listApiKeys({ headers });
        return (apiKeys as unknown as Array<Record<string, unknown>>).map(toInfo);
      },
      catch: (cause) => new ApiKeyProviderError({ cause })
    }),
  create: (userId, role) =>
    Effect.tryPromise({
      try: async () => {
        // NO `headers`, and that is the entire point. better-auth treats
        // `ctx.request || ctx.headers` as a client request and then rejects
        // `rateLimitMax` with SERVER_ONLY_PROPERTY — forwarding the caller's
        // headers here would make the tier unsettable. Naming the owner via
        // `userId` is the server-side path; the route program authenticated
        // that caller before handing us their id.
        const created = await auth.api.createApiKey({
          body: {
            userId,
            name: 'bit',
            // The tier, and the only thing that carries it now that there is a
            // single configuration. Derived from the role the SERVER resolved,
            // never from anything the caller sent.
            rateLimitMax: role === 'admin' ? API_KEY_ADMIN_TIER_MAX : API_KEY_USER_TIER_MAX,
            rateLimitTimeWindow: API_KEY_RATE_WINDOW_MS
          }
        });
        const row = created as unknown as Record<string, unknown>;
        return { ...toInfo(row), key: String(row.key) };
      },
      catch: (cause) => new ApiKeyProviderError({ cause })
    }),
  delete: (headers, keyId) =>
    Effect.tryPromise({
      try: async () => {
        // No `configId` to pass: one configuration means there is no tier to
        // name. This retires the "admin-tier key cannot be revoked" bug rather
        // than patching it — the argument that used to be dropped is gone.
        await auth.api.deleteApiKey({ headers, body: { keyId } });
      },
      catch: (cause) => new ApiKeyProviderError({ cause })
    })
});

export const makeApiKeyServiceTest = (implementation: Context.Tag.Service<ApiKeyService>) =>
  Layer.succeed(ApiKeyService, implementation);
