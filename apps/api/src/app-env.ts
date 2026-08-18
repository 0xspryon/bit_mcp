import type { RecordRepo, SessionRepo, SourceRepo, UserRepo } from '@repo/db';
import type {
  EmbeddingService,
  IngestService,
  RerankService,
  RetrieverService
} from '@repo/rag-core';
import type { ManagedRuntime } from 'effect';
import type { Env, Handler } from 'hono';
import type { AuthService } from './lib/effect-auth';

/**
 * Every service tag the app runtime provides. A route program's requirements
 * (`R`) must be a subset of this union for the runtime to run it.
 */
export type AppServices =
  | RecordRepo
  | SourceRepo
  | UserRepo
  | SessionRepo
  | EmbeddingService
  | RerankService
  | AuthService
  | IngestService
  | RetrieverService;

/**
 * The layer build can fail while resolving env `Config` (embedding/rerank
 * endpoints, mail settings) or opening the DB pool — i.e. its real error
 * channel is `ConfigError | SqlError`. We deliberately pin the runtime's error
 * channel to `never` (and cast in `makeAppRuntime`) so those build errors do
 * NOT leak into every route program's `Exit` type and force each handler's
 * exhaustive `_tag` mapper to also handle config/SQL variants. `startup.ts`
 * fails fast before the port binds, so requests only ever see a built runtime;
 * on the vanishingly unlikely post-build failure the handlers' generic 500
 * branch covers it.
 */
export type AppRuntime = ManagedRuntime.ManagedRuntime<AppServices, never>;

export type BaseAppEnv = {
  Variables: {
    runtime: AppRuntime;
    requestId: string;
  };
};

export type HonoEnv = {
  Variables: BaseAppEnv['Variables'];
};

export type HonoContext<T extends Env> = Parameters<Handler<T>>[0];
