/**
 * Ad-hoc end-to-end retrieval smoke check against a live DB + TEI stack.
 * Runs the REAL RetrieverService (embed → dense+lexical → RRF → rerank).
 *
 *   DATABASE_URL=... EMBEDDING_ENDPOINT=... RERANK_ENDPOINT=... \
 *     bun run src/eval/retrieve-smoke.ts "<query>" [namespace]
 *
 * The optional positional arg is a single namespace; it is passed as a
 * one-element `namespaces` overlap filter.
 */
import { RecordRepoDefault } from '@repo/db';
import {
  EmbeddingServiceLive,
  RerankServiceLive,
  RetrieverService,
  RetrieverServiceLive
} from '@repo/rag-core';
import { Effect, Layer, ManagedRuntime } from 'effect';

const infra = Layer.mergeAll(RecordRepoDefault, EmbeddingServiceLive, RerankServiceLive);
const AppLive = RetrieverServiceLive.pipe(Layer.provide(infra));
const runtime = ManagedRuntime.make(AppLive);

const query = process.argv[2] ?? 'proxy returns 403 for /admin but a trailing byte bypasses the ACL';
const namespace = process.argv[3];

const program = Effect.gen(function*() {
  const retriever = yield* RetrieverService;
  return yield* retriever.retrieve({
    query,
    ...(namespace ? { namespaces: [namespace] } : {}),
    k: 3
  });
});

const { chunks, diagnostics } = await runtime.runPromise(program);
console.log(`\nquery: ${query}${namespace ? `  (namespaces=[${namespace}])` : ''}`);
console.log(`results: ${chunks.length}`);
// A short dense leg means the HNSW walk ran out of candidates under the filter
// rather than the corpus being empty — worth seeing while smoke-testing.
console.log(
  `dense leg: ${diagnostics.semantic_search_count}/${diagnostics.semantic_search_k}` +
  `${diagnostics.semantic_search_degraded ? '  DEGRADED (filter starved the ANN walk)' : ''}`
);
console.log(`lexical leg: ${diagnostics.lexical_search_count}/${diagnostics.lexical_search_k}`);
for (const c of chunks) {
  console.log(
    `  • [${c.namespaces.join(', ')}] ${c.title}\n    score=${c.score.toFixed(4)} tier=${c.quality_tier} kind=${c.kind} sources=${c.sources.map((s) => s.url).join(', ')}`
  );
}
await runtime.dispose();
