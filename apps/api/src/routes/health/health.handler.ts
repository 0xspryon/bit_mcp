import { embeddingConfig } from '@repo/env';
import { Cause, Effect, Exit, Option } from 'effect';
import type { HonoContext, HonoEnv } from '../../app-env';

/**
 * Public liveness/readiness payload. Reads the (already-validated at startup)
 * embedding config so the response advertises the model + dimension the store
 * is pinned to.
 */
export const healthRouteProgram = () =>
  Effect.gen(function* () {
    const embedding = yield* embeddingConfig;
    return {
      ok: true as const,
      embeddingModel: embedding.model,
      embeddingDim: embedding.dim
    };
  });

export type HealthRouteError = Effect.Effect.Error<ReturnType<typeof healthRouteProgram>>;

const exitToResponse = <T>(c: HonoContext<HonoEnv>, exit: Exit.Exit<T, HealthRouteError>) =>
  Exit.match(exit, {
    onSuccess: (value) => c.json(value),
    onFailure: (cause) => {
      // The only modeled failure is a ConfigError, which startup already
      // guards against; treat any failure here as an internal error.
      const failure = Cause.failureOption(cause);
      const message = Option.isSome(failure)
        ? 'Service configuration is unavailable.'
        : 'Unexpected server error.';
      return c.json({ error: { code: 'INTERNAL_SERVER_ERROR' as const, message } }, 500);
    }
  });

export async function healthHandler(c: HonoContext<HonoEnv>) {
  const runtime = c.get('runtime');
  const exit = await runtime.runPromiseExit(healthRouteProgram());
  return exitToResponse(c, exit);
}
