import { Effect, Exit } from 'effect';
import { describe, expect, it } from 'vitest';
import { assertEmbeddingDim, EmbeddingService, EmbedError, makeEmbeddingServiceTest } from './embedding';
import { getFailure } from './test-helpers';

const runExit = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromiseExit(effect);

describe('assertEmbeddingDim', () => {
  it('passes a length-1024 vector through unchanged', async () => {
    const vec = new Float32Array(1024);
    const exit = await runExit(assertEmbeddingDim(vec));
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) expect(exit.value).toBe(vec);
  });

  it('fails with EmbedError for a wrong length', async () => {
    const exit = await runExit(assertEmbeddingDim(new Float32Array(512)));
    const err = getFailure(exit);
    expect(err).toBeInstanceOf(EmbedError);
    expect(err.reason).toContain('1024');
  });
});

describe('makeEmbeddingServiceTest', () => {
  it('default fake yields a deterministic, L2-normalized 1024-vector', async () => {
    const layer = makeEmbeddingServiceTest();
    const program = Effect.gen(function* () {
      const svc = yield* EmbeddingService;
      const a = yield* svc.embed('same text');
      const b = yield* svc.embed('same text');
      return { a, b };
    });
    const { a, b } = await Effect.runPromise(Effect.provide(program, layer));
    expect(a.length).toBe(1024);
    expect(Array.from(a)).toEqual(Array.from(b)); // deterministic
    const norm = Math.sqrt(Array.from(a).reduce((s, v) => s + v * v, 0));
    expect(norm).toBeCloseTo(1, 5);
  });

  it('routes an injected non-1024 vector through the dimension guard', async () => {
    const layer = makeEmbeddingServiceTest({
      embed: () => assertEmbeddingDim(new Float32Array(10))
    });
    const program = Effect.gen(function* () {
      const svc = yield* EmbeddingService;
      return yield* svc.embed('x');
    });
    const exit = await runExit(Effect.provide(program, layer));
    expect(getFailure(exit)).toBeInstanceOf(EmbedError);
  });
});
