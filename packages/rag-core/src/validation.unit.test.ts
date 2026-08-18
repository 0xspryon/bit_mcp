import { Effect, Exit } from 'effect';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EmbeddingService, EmbeddingServiceLive } from './embedding';
import { RerankService, RerankServiceLive } from './rerank';
import { decodeRecordInput, decodeRetrieveQuery, LIMITS } from './schema';
import { getFailure, makeRecord } from './test-helpers';

// Live TEI layers read their endpoint from env at build time.
process.env.EMBEDDING_ENDPOINT = 'http://tei.embed.test';
process.env.RERANK_ENDPOINT = 'http://tei.rerank.test';

const validRecord = {
  namespaces: ['ssrf'],
  title: 'Test',
  symptom: 'observable symptom',
  procedure: 'do the thing'
};

const runExit = <A, E>(eff: Effect.Effect<A, E, never>) => Effect.runPromiseExit(eff);

/** Stub `fetch` to return a 200 whose `.json()` yields `body` verbatim (so we
 * can inject values JSON can't represent, like NaN). */
const stubFetch = (body: unknown) => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, status: 200, statusText: 'OK', json: async () => body }))
  );
};

afterEach(() => vi.unstubAllGlobals());

describe('schema: trimming (#9)', () => {
  it('trims namespaces so " ssrf " is stored as "ssrf"', async () => {
    const out = await Effect.runPromise(
      decodeRecordInput({ ...validRecord, namespaces: ['  ssrf  '] })
    );
    expect(out.namespaces).toEqual(['ssrf']);
  });

  it('rejects a whitespace-only required field', async () => {
    const exit = await runExit(decodeRecordInput({ ...validRecord, title: '   ' }));
    expect(Exit.isFailure(exit)).toBe(true);
    expect(getFailure(exit)._tag).toBe('RecordInputParseError');
  });

  it('trims the retrieve query namespaces', async () => {
    const out = await Effect.runPromise(decodeRetrieveQuery({ query: 'x', namespaces: [' web '] }));
    expect(out.namespaces).toEqual(['web']);
  });
});

describe('schema: bounds & rejection (#8)', () => {
  it('rejects an oversized procedure with a clear message', async () => {
    const exit = await runExit(
      decodeRecordInput({ ...validRecord, procedure: 'a'.repeat(LIMITS.procedure + 1) })
    );
    expect(Exit.isFailure(exit)).toBe(true);
    const err = getFailure(exit) as { issues: ReadonlyArray<{ message: string }> };
    expect(err.issues.some((i) => /procedure must be at most/.test(i.message))).toBe(true);
  });

  it('rejects a non-http(s) source url', async () => {
    const exit = await runExit(
      decodeRecordInput({ ...validRecord, sources: [{ url: 'javascript:alert(1)' }] })
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('accepts a valid https source url', async () => {
    const out = await Effect.runPromise(
      decodeRecordInput({ ...validRecord, sources: [{ url: 'https://example.com/a' }] })
    );
    expect(out.sources[0]?.url).toBe('https://example.com/a');
  });

  it('rejects a cwe outside the sane range', async () => {
    const exit = await runExit(decodeRecordInput({ ...validRecord, cwe: [999999] }));
    expect(Exit.isFailure(exit)).toBe(true);
  });

  it('rejects more than the max array items', async () => {
    const exit = await runExit(
      decodeRecordInput({
        ...validRecord,
        appliesTo: Array.from({ length: LIMITS.arrayItems + 1 }, (_, i) => `t${i}`)
      })
    );
    expect(Exit.isFailure(exit)).toBe(true);
  });
});

describe('embedding response validation (#10)', () => {
  const embed = (text: string) =>
    EmbeddingService.pipe(Effect.flatMap((s) => s.embed(text)), Effect.provide(EmbeddingServiceLive));

  it('accepts a well-formed 1024-vector', async () => {
    stubFetch([new Array(1024).fill(0.01)]);
    const vec = await Effect.runPromise(embed('x'));
    expect(vec.length).toBe(1024);
  });

  it('fails on a non-array body', async () => {
    stubFetch({ error: 'overloaded' });
    expect(getFailure(await runExit(embed('x')))._tag).toBe('EmbedError');
  });

  it('fails on an empty body (no row)', async () => {
    stubFetch([]);
    expect(getFailure(await runExit(embed('x')))._tag).toBe('EmbedError');
  });

  it('fails on a non-finite element (NaN)', async () => {
    stubFetch([[...new Array(1023).fill(0.1), Number.NaN]]);
    expect(getFailure(await runExit(embed('x')))._tag).toBe('EmbedError');
  });

  it('fails on a wrong-length vector', async () => {
    stubFetch([[0.1, 0.2, 0.3]]);
    expect(getFailure(await runExit(embed('x')))._tag).toBe('EmbedError');
  });
});

describe('rerank response validation (#10)', () => {
  const docs = [makeRecord({ id: 'a', title: 'A' }), makeRecord({ id: 'b', title: 'B' })];
  const rerank = () =>
    RerankService.pipe(Effect.flatMap((s) => s.rerank('q', docs)), Effect.provide(RerankServiceLive));

  it('orders by score for a well-formed response', async () => {
    stubFetch([
      { index: 0, score: 0.1 },
      { index: 1, score: 0.9 }
    ]);
    const scored = await Effect.runPromise(rerank());
    expect(scored.map((s) => s.record.id)).toEqual(['b', 'a']);
  });

  it('fails on a non-array body', async () => {
    stubFetch({ error: 'x' });
    expect(getFailure(await runExit(rerank()))._tag).toBe('RerankError');
  });

  it('fails on a length mismatch', async () => {
    stubFetch([{ index: 0, score: 0.5 }]);
    expect(getFailure(await runExit(rerank()))._tag).toBe('RerankError');
  });

  it('fails on a malformed entry (missing score)', async () => {
    stubFetch([{ index: 0 }, { index: 1, score: 0.5 }]);
    expect(getFailure(await runExit(rerank()))._tag).toBe('RerankError');
  });

  it('fails on an out-of-range index', async () => {
    stubFetch([
      { index: 5, score: 0.5 },
      { index: 0, score: 0.9 }
    ]);
    expect(getFailure(await runExit(rerank()))._tag).toBe('RerankError');
  });
});

describe('schema: excess properties fail loudly (#unknown-fields)', () => {
  it('rejects an unknown field on RecordInput', async () => {
    const exit = await runExit(
      decodeRecordInput({
        namespaces: ['ssrf'],
        title: 'T',
        symptom: 's',
        procedure: 'p',
        bogusField: 1
      })
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(getFailure(exit)._tag).toBe('RecordInputParseError');
  });

  it('rejects an unknown field on RetrieveQuery', async () => {
    const exit = await runExit(decodeRetrieveQuery({ query: 'x', bogusField: true }));
    expect(Exit.isFailure(exit)).toBe(true);
    expect(getFailure(exit)._tag).toBe('RetrieveQueryParseError');
  });
});
