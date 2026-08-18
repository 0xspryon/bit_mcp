import type { RecordSourceRow } from '@repo/db';
import { Effect, Exit, Layer } from 'effect';
import { describe, expect, it } from 'vitest';
import { makeEmbeddingServiceTest } from './embedding';
import { makeRerankServiceTest } from './rerank';
import { RetrieverService, RetrieverServiceLive } from './retriever';
import { makeRecord, makeRecordRepoFake } from './test-helpers';

const r1 = makeRecord({
  id: 'r1',
  title: 'SQL injection basics',
  symptom: 'a quote breaks parsing',
  procedure: 'inject a quote',
  confirmationSignal: 'db error surfaced',
  qualityTier: 2,
  namespaces: ['web']
});
const r2 = makeRecord({
  id: 'r2',
  title: 'IDOR',
  symptom: 'object reference',
  procedure: 'swap id',
  namespaces: ['web']
});
const r3 = makeRecord({
  id: 'r3',
  title: 'XSS',
  symptom: 'script reflected',
  procedure: 'alert',
  namespaces: ['web']
});

const sourcesMap = new Map<string, RecordSourceRow[]>([
  ['r1', [{ url: 'https://ref.com', title: 'Ref', tier: 1 }]]
]);

describe('RetrieverService', () => {
  it('fuses, reranks, and shapes Chunks; passes a hard active+namespace filter', async () => {
    const { layer: recordLayer, spy } = makeRecordRepoFake({
      nearest: [r2, r3, r1],
      lexical: [r3, r1, r2],
      sources: sourcesMap
    });
    const deps = Layer.mergeAll(
      recordLayer,
      makeEmbeddingServiceTest(),
      makeRerankServiceTest()
    );
    const layer = RetrieverServiceLive.pipe(Layer.provide(deps));

    const program = Effect.gen(function* () {
      const svc = yield* RetrieverService;
      return yield* svc.retrieve({
        query: 'sql injection quote',
        namespaces: ['web'],
        filters: { cwe: [89] }
      });
    });

    const exit = await Effect.runPromiseExit(Effect.provide(program, layer));
    expect(Exit.isSuccess(exit)).toBe(true);
    if (!Exit.isSuccess(exit)) return;
    const { chunks } = exit.value;

    // Default fake reranker scores by query-token overlap; r1 wins decisively.
    expect(chunks[0]?.id).toBe('r1');
    // Every chunk carries the methodology marker and snake_case keys.
    expect(chunks.every((c) => c.kind === 'methodology')).toBe(true);
    expect(chunks[0]?.confirmation_signal).toBe('db error surfaced');
    expect(chunks[0]?.quality_tier).toBe(2);
    expect(chunks[0]?.sources).toEqual([{ url: 'https://ref.com', title: 'Ref', tier: 1 }]);

    // Hard filter reached both retrieval legs: status:'active' + namespace + cwe.
    const nearestFilter = spy.nearestFilters[0];
    const lexicalFilter = spy.lexicalFilters[0];
    expect(nearestFilter).toMatchObject({ status: 'active', namespaces: ['web'], cwe: [89] });
    expect(lexicalFilter).toMatchObject({ status: 'active', namespaces: ['web'], cwe: [89] });
  });

  it('honours the k limit', async () => {
    const { layer: recordLayer } = makeRecordRepoFake({
      nearest: [r1, r2, r3],
      lexical: [r1, r2, r3]
    });
    const layer = RetrieverServiceLive.pipe(
      Layer.provide(
        Layer.mergeAll(recordLayer, makeEmbeddingServiceTest(), makeRerankServiceTest())
      )
    );
    const program = Effect.gen(function* () {
      const svc = yield* RetrieverService;
      return yield* svc.retrieve({ query: 'anything', k: 1 });
    });
    const { chunks } = await Effect.runPromise(Effect.provide(program, layer));
    expect(chunks).toHaveLength(1);
  });

  it('reports per-leg candidate counts, flagging a short dense leg as degraded', async () => {
    // The fake repo hands back 3 candidates per leg against a CANDIDATE_K of
    // 30 — the same shape a real HNSW walk produces when a selective filter
    // starves it, so the dense leg must be reported as degraded.
    const { layer: recordLayer } = makeRecordRepoFake({
      nearest: [r1, r2, r3],
      lexical: [r1, r2]
    });
    const layer = RetrieverServiceLive.pipe(
      Layer.provide(
        Layer.mergeAll(recordLayer, makeEmbeddingServiceTest(), makeRerankServiceTest())
      )
    );
    const program = Effect.gen(function* () {
      const svc = yield* RetrieverService;
      return yield* svc.retrieve({ query: 'anything' });
    });
    const { diagnostics } = await Effect.runPromise(Effect.provide(program, layer));

    expect(diagnostics.semantic_search_k).toBe(30);
    expect(diagnostics.semantic_search_count).toBe(3);
    expect(diagnostics.semantic_search_degraded).toBe(true);
    expect(diagnostics.lexical_search_k).toBe(30);
    expect(diagnostics.lexical_search_count).toBe(2);
  });
});
