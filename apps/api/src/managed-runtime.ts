import {
  RecordRepoDefault,
  SessionRepoDefault,
  SourceRepoDefault,
  UserRepoDefault
} from '@repo/db';
import {
  EmbeddingServiceLive,
  IngestServiceLive,
  RerankServiceLive,
  RetrieverServiceLive
} from '@repo/rag-core';
import { Layer, ManagedRuntime } from 'effect';
import type { AppRuntime } from './app-env';
import { ApiKeyServiceLive } from './lib/api-keys';
import { AuthServiceLive } from './lib/effect-auth';

/**
 * Infrastructure layer: repos (each `*Default` already bakes in `DrizzleLive`)
 * plus the leaf services that read their endpoints/config from env. All of
 * these have `RIn = never`; only their build can fail with `ConfigError`.
 */
const infra = Layer.mergeAll(
  RecordRepoDefault,
  SourceRepoDefault,
  UserRepoDefault,
  SessionRepoDefault,
  EmbeddingServiceLive,
  RerankServiceLive,
  AuthServiceLive,
  ApiKeyServiceLive
);

/**
 * Domain layer: the ingest/retrieve services depend on the repos + embedding +
 * rerank services. `Layer.provide(infra)` satisfies those requirements, so the
 * composed `domain` has no unmet requirements of its own.
 */
const domain = Layer.mergeAll(IngestServiceLive, RetrieverServiceLive).pipe(Layer.provide(infra));

/** Full graph. `RIn` is `never`; the only error channel is `ConfigError`. */
export const AppLive = Layer.merge(infra, domain);

// The cast pins the error channel to `never`; see `AppRuntime` in app-env.ts
// for why the real `ConfigError | SqlError` build-error channel is elided.
export const makeAppRuntime = (): AppRuntime => ManagedRuntime.make(AppLive) as AppRuntime;
