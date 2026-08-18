import type { RecordRepo } from '@repo/db';
import { Effect, Exit, Layer } from 'effect';
import { describe, expect, it } from 'vitest';
import { contentHash } from './content-hash';
import { assertEmbeddingDim, EmbedError, type EmbeddingService, makeEmbeddingServiceTest } from './embedding';
import { IngestService, IngestServiceLive } from './ingest';
import { getFailure, makeRecord, makeRecordRepoFake } from './test-helpers';

const validInput = {
  namespaces: ['web'],
  title: 'SQL Injection',
  symptom: 'error leakage',
  procedure: 'inject a quote',
  sources: [
    { url: 'https://a.com', title: 'A', tier: 2 },
    { url: 'https://a.com', title: 'A dup', tier: 2 }, // deduped by url
    { url: 'https://b.com' }
  ]
};

const hashOf = contentHash({
  title: validInput.title,
  symptom: validInput.symptom,
  procedure: validInput.procedure
});

const runIngest = (
  input: unknown,
  deps: { record: Layer.Layer<RecordRepo>; embed: Layer.Layer<EmbeddingService> }
) => {
  const program = Effect.gen(function* () {
    const svc = yield* IngestService;
    return yield* svc.ingest(input);
  });
  const layer = IngestServiceLive.pipe(Layer.provide(Layer.mergeAll(deps.record, deps.embed)));
  return Effect.runPromiseExit(Effect.provide(program, layer));
};

describe('IngestService', () => {
  it('dedupes on an existing content hash without embedding or inserting', async () => {
    const existing = makeRecord({ id: 'existing-1', status: 'active', contentHash: hashOf });
    const { layer: recordLayer, spy } = makeRecordRepoFake({
      byHash: new Map([[hashOf, existing]])
    });

    const exit = await runIngest(validInput, { record: recordLayer, embed: makeEmbeddingServiceTest() });
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value).toEqual({ id: 'existing-1', deduped: true, status: 'active' });
    }
    expect(spy.inserts).toHaveLength(0); // never inserted
  });

  it('inserts a new record (staging) with url-deduped sources', async () => {
    const { layer: recordLayer, spy } = makeRecordRepoFake({ insertId: 'fresh-1' });

    const exit = await runIngest(validInput, { record: recordLayer, embed: makeEmbeddingServiceTest() });
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value).toEqual({ id: 'fresh-1', deduped: false, status: 'staging' });
    }

    expect(spy.inserts).toHaveLength(1);
    const inserted = spy.inserts[0];
    expect(inserted?.row.contentHash).toBe(hashOf);
    expect(Array.isArray(inserted?.row.embedding)).toBe(true);
    expect((inserted?.row.embedding as number[]).length).toBe(1024);
    // Sources passed to the atomic insert, deduped by url.
    expect(inserted?.sources.map((s) => s.url)).toEqual(['https://a.com', 'https://b.com']);
  });

  it('reports deduped:true when the atomic insert hits a race conflict', async () => {
    // findByHash misses, but the insert conflicts on content_hash (a concurrent
    // ingest won the race). The existing row's status is surfaced.
    const { layer: recordLayer, spy } = makeRecordRepoFake({
      insertId: 'raced-1',
      insertConflict: true,
      insertStatus: 'active'
    });

    const exit = await runIngest(validInput, { record: recordLayer, embed: makeEmbeddingServiceTest() });
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value).toEqual({ id: 'raced-1', deduped: true, status: 'active' });
    }
    expect(spy.inserts).toHaveLength(1); // insert was attempted (then conflicted)
  });

  it('fails with EmbedError when the embedding has the wrong length', async () => {
    const { layer: recordLayer } = makeRecordRepoFake({});
    const badEmbed = makeEmbeddingServiceTest({
      embed: () => assertEmbeddingDim(new Float32Array(7))
    });

    const exit = await runIngest(validInput, { record: recordLayer, embed: badEmbed });
    expect(getFailure(exit)).toBeInstanceOf(EmbedError);
  });
});
