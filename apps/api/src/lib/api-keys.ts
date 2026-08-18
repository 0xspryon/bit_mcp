import { Context, Data, Effect, Layer } from 'effect';
import { auth } from './auth';

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
}> {}

export class ApiKeyService extends Context.Tag('@api/lib/ApiKeyService')<
  ApiKeyService,
  {
    list: (headers: Headers) => Effect.Effect<ReadonlyArray<ApiKeyInfo>, ApiKeyProviderError>;
    create: (headers: Headers) => Effect.Effect<CreatedApiKey, ApiKeyProviderError>;
    delete: (
      headers: Headers,
      keyId: string,
      configId?: string | null
    ) => Effect.Effect<void, ApiKeyProviderError>;
  }
>() {}

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
  create: (headers) =>
    Effect.tryPromise({
      try: async () => {
        // `configId` is forced from the caller's role by the before-hook in
        // auth.ts, so nothing tier-related is passed (or trusted) from here.
        const created = await auth.api.createApiKey({ headers, body: { name: 'bit' } });
        const row = created as unknown as Record<string, unknown>;
        return { ...toInfo(row), key: String(row.key) };
      },
      catch: (cause) => new ApiKeyProviderError({ cause })
    }),
  delete: (headers, keyId) =>
    Effect.tryPromise({
      try: async () => {
        await auth.api.deleteApiKey({ headers, body: { keyId } });
      },
      catch: (cause) => new ApiKeyProviderError({ cause })
    })
});

export const makeApiKeyServiceTest = (implementation: Context.Tag.Service<ApiKeyService>) =>
  Layer.succeed(ApiKeyService, implementation);
