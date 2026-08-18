import { records } from '@repo/db/schema';
import { RecordRepoDefault, SourceRepoDefault } from '@repo/db';
import { EmbeddingServiceLive, IngestService, IngestServiceLive } from '@repo/rag-core';
import { eq } from 'drizzle-orm';
import { Effect, Layer, ManagedRuntime } from 'effect';
import type { Seed } from '../types';
import type { CorpusRecord } from './data/types';
import { records as authzObject } from './data/authz-object';
import { records as authzFunction } from './data/authz-function';
import { records as authzIdentity } from './data/authz-identity';
import { records as authzEdge } from './data/authz-edge';
import { records as paywall } from './data/paywall';

/**
 * Seeds the authorization-bypass + paywall-bypass corpus.
 *
 * The records are authored per fundamental technique across five data modules
 * (object-level, function-level, identity/token, edge/proxy, paywall). They are
 * ingested through the real runtime path — validate -> hash -> dedup -> embed
 * -> insert — identically to {@link ../seeds/0001_corpus}, then promoted to
 * `active`. Idempotent: re-runs dedup by content_hash and the promote is a
 * no-op. The embedding index is HNSW (incremental), so no reindex is needed.
 */
const corpus: readonly CorpusRecord[] = [
  ...authzObject,
  ...authzFunction,
  ...authzIdentity,
  ...authzEdge,
  ...paywall
];

const IngestLive = IngestServiceLive.pipe(
  Layer.provide(Layer.mergeAll(RecordRepoDefault, SourceRepoDefault, EmbeddingServiceLive))
);

export const authzPaywallSeed: Seed = {
  name: '0002_authz_paywall',
  run: async (db) => {
    const runtime = ManagedRuntime.make(IngestLive);
    try {
      for (const record of corpus) {
        const result = await runtime.runPromise(
          Effect.flatMap(IngestService, (service) => service.ingest(record))
        );
        await db
          .update(records)
          .set({ status: 'active', updatedAt: new Date() })
          .where(eq(records.id, result.id));
      }
    } finally {
      await runtime.dispose();
    }
  }
};
