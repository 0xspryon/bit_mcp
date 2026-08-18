import { Config, ConfigError, Either, Redacted } from 'effect';

/**
 * `@repo/env` — lazy Effect `Config` descriptions for the whole app.
 *
 * These are *descriptions*, not resolved values: consumers `yield*` them inside
 * an Effect so failures surface as typed `ConfigError`s at the edge that reads
 * them (startup), never as thrown exceptions deep in a request.
 *
 * `DATABASE_URL` is intentionally NOT surfaced here — it is read directly in
 * `@repo/db` (Effect path via `Config.string('DATABASE_URL')`, plain path via
 * `process.env`) so the DB package stays self-contained.
 */

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

export const APP_ENVIRONMENTS = ['dev', 'staging', 'production'] as const;
export type AppEnvironment = (typeof APP_ENVIRONMENTS)[number];

export const isAppEnvironment = (value: string): value is AppEnvironment =>
  (APP_ENVIRONMENTS as readonly string[]).includes(value);

export const environmentConfig: Config.Config<AppEnvironment> = Config.string('ENVIRONMENT').pipe(
  Config.withDefault('dev'),
  Config.mapOrFail((raw) => {
    const value = raw.trim().toLowerCase();
    return isAppEnvironment(value)
      ? Either.right(value)
      : Either.left(
        ConfigError.InvalidData(
          ['ENVIRONMENT'],
          `ENVIRONMENT must be one of: ${APP_ENVIRONMENTS.join(', ')}`
        )
      );
  })
);

// ---------------------------------------------------------------------------
// Embeddings — version-pinned. bge-m3 dense, 1024 dims. A dim other than 1024
// is a startup error (the store column is `vector(1024)`; a mismatch would
// silently corrupt retrieval).
// ---------------------------------------------------------------------------

export const EMBEDDING_DIM = 1024;

export interface EmbeddingConfig {
  readonly model: string;
  readonly dim: number;
  readonly endpoint: string;
}

export const embeddingConfig: Config.Config<EmbeddingConfig> = Config.all({
  model: Config.string('EMBEDDING_MODEL').pipe(Config.withDefault('bge-m3')),
  dim: Config.integer('EMBEDDING_DIM').pipe(
    Config.withDefault(EMBEDDING_DIM),
    Config.mapOrFail((value) =>
      value === EMBEDDING_DIM
        ? Either.right(value)
        : Either.left(
          ConfigError.InvalidData(
            ['EMBEDDING_DIM'],
            `EMBEDDING_DIM must be ${EMBEDDING_DIM} (bge-m3 dense); got ${value}`
          )
        )
    )
  ),
  endpoint: Config.string('EMBEDDING_ENDPOINT')
});

export interface RerankConfig {
  readonly model: string;
  readonly endpoint: string;
}

export const rerankConfig: Config.Config<RerankConfig> = Config.all({
  model: Config.string('RERANK_MODEL').pipe(Config.withDefault('bge-reranker-v2-m3')),
  endpoint: Config.string('RERANK_ENDPOINT')
});

// ---------------------------------------------------------------------------
// HTTP transport
//
// The MCP server is served over Streamable HTTP (mounted on Hono) only — there
// is no stdio transport — so there is no MCP_TRANSPORT switch.
// ---------------------------------------------------------------------------

export const httpPortConfig: Config.Config<number> = Config.integer('HTTP_PORT').pipe(
  Config.withDefault(3000)
);

// ---------------------------------------------------------------------------
// Auth (better-auth)
// ---------------------------------------------------------------------------

export interface AuthConfig {
  readonly secret: Redacted.Redacted<string>;
  readonly baseUrl: string;
  readonly trustedOrigins: ReadonlyArray<string>;
}

const csvConfig = (name: string): Config.Config<ReadonlyArray<string>> =>
  Config.string(name).pipe(
    Config.withDefault(''),
    Config.map((raw) =>
      raw
        .split(',')
        .map((part) => part.trim())
        .filter((part) => part.length > 0)
    )
  );

export const authConfig: Config.Config<AuthConfig> = Config.all({
  secret: Config.redacted('BETTER_AUTH_SECRET'),
  baseUrl: Config.string('BETTER_AUTH_URL').pipe(Config.withDefault('http://localhost:3000')),
  trustedOrigins: csvConfig('TRUSTED_ORIGINS')
});
