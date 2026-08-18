/**
 * Type augmentation for the values the integration `globalSetup` publishes via
 * `provide(...)` and each test file reads back via `inject(...)`.
 *
 * `globalSetup` runs once in the main process, starts the disposable Postgres
 * (and, when requested, TEI) containers, and hands the resulting connection
 * details to the worker processes through this typed channel.
 */
declare module 'vitest' {
  interface ProvidedContext {
    /** True when a pgvector container started successfully. Every integration
     * `describe` is `skipIf(!dockerAvailable)`, so a machine without a running
     * Docker daemon skips the whole suite instead of hard-failing. */
    readonly dockerAvailable: boolean;
    /** Connection URI of the migrated pgvector container (empty when Docker is
     * unavailable). */
    readonly databaseUrl: string;
    /** TEI embedding endpoint (env `EMBEDDING_ENDPOINT`, or a spun container),
     * or `null` when no reranker/embedder is available — the TEI-gated tests
     * skip in that case. */
    readonly embeddingEndpoint: string | null;
    /** TEI reranker endpoint, or `null` when unavailable. */
    readonly rerankEndpoint: string | null;
  }
}

export {};
