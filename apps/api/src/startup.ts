import { embeddingConfig, rerankConfig } from '@repo/env';
import { type ConfigError, Data, Effect } from 'effect';

/**
 * Fail-fast startup probe.
 *
 * `embeddingConfig` already fails (with `ConfigError`) if `EMBEDDING_DIM !== 1024`
 * or a required endpoint is unset — that validation lives in `@repo/env`. On top
 * of that this probe confirms the embedding and rerank inference servers are
 * actually reachable before the process starts accepting traffic, so a
 * misconfigured or down TEI surfaces at boot rather than on the first request.
 */

/** A boot check failed: an inference endpoint was unreachable or unhealthy. */
export class StartupError extends Data.TaggedError('StartupError')<{
  readonly reason: string;
  readonly cause?: unknown;
}> { }

/** How long to wait for a `/health` probe before treating it as unreachable. */
const PROBE_TIMEOUT_MS = 5_000;

const probeHealth = (label: string, endpoint: string): Effect.Effect<void, StartupError> =>
  Effect.tryPromise({
    try: async () => {
      const response = await fetch(`${endpoint}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS)
      });
      if (!response.ok) {
        throw new Error(`${label} /health responded ${response.status} ${response.statusText}`);
      }
    },
    catch: (cause) =>
      new StartupError({ reason: `${label} endpoint (${endpoint}) is unreachable`, cause })
  });

export const ensureInitialAppState: Effect.Effect<
  void,
  StartupError | ConfigError.ConfigError,
  never
> = Effect.gen(
  function*() {
    // `ConfigError` from these reads (e.g. EMBEDDING_DIM !== 1024, or a missing
    // endpoint) fails the effect before any probe runs.
    const embedding = yield* embeddingConfig;
    const rerank = yield* rerankConfig;

    yield* Effect.all(
      [probeHealth('embedding', embedding.endpoint), probeHealth('rerank', rerank.endpoint)],
      { concurrency: 'unbounded' }
    );
  }
);
