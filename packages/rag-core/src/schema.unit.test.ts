import { Effect, Exit } from 'effect';
import { describe, expect, it } from 'vitest';
import {
  decodeRecordInput,
  decodeRetrieveQuery,
  RecordInputParseError,
  RetrieveQueryParseError
} from './schema';
import { getFailure } from './test-helpers';

const runExit = <A, E>(effect: Effect.Effect<A, E>) => Effect.runPromiseExit(effect);

describe('RecordInput schema', () => {
  it('accepts a minimal valid input and applies defaults', async () => {
    const exit = await runExit(
      decodeRecordInput({
        namespaces: ['web'],
        title: 'SQLi',
        symptom: 'error-based leakage',
        procedure: 'inject a quote'
      })
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value.qualityTier).toBe(3);
      expect(exit.value.sources).toEqual([]);
      expect(exit.value.cwe).toEqual([]);
    }
  });

  it('accepts a fully-populated input with sources', async () => {
    const exit = await runExit(
      decodeRecordInput({
        namespaces: ['web'],
        title: 'IDOR',
        symptom: 'object accessible',
        procedure: 'swap id',
        whenToUse: 'when ids are sequential',
        confirmationSignal: 'other user data returned',
        preconditions: ['authenticated'],
        appliesTo: ['rails'],
        cwe: [639],
        vrt: ['idor'],
        chainsWith: ['auth-bypass'],
        qualityTier: 1,
        sources: [{ url: 'https://ex.com', title: 'ref', tier: 2, kind: 'doc' }]
      })
    );
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value.sources[0]?.tier).toBe(2);
      expect(exit.value.cwe).toEqual([639]);
    }
  });

  it('rejects missing required fields', async () => {
    const exit = await runExit(decodeRecordInput({ namespaces: ['web'] }));
    expect(getFailure(exit)).toBeInstanceOf(RecordInputParseError);
  });

  it('rejects an empty required string', async () => {
    const exit = await runExit(
      decodeRecordInput({
        namespaces: ['   '],
        title: 't',
        symptom: 's',
        procedure: 'p'
      })
    );
    expect(getFailure(exit)).toBeInstanceOf(RecordInputParseError);
  });

  it('rejects a wrong-typed field', async () => {
    const exit = await runExit(
      decodeRecordInput({
        namespaces: ['web'],
        title: 't',
        symptom: 's',
        procedure: 'p',
        cwe: ['not-a-number']
      })
    );
    expect(getFailure(exit)).toBeInstanceOf(RecordInputParseError);
  });
});

describe('RetrieveQuery schema', () => {
  it('accepts a minimal query and defaults k to 5', async () => {
    const exit = await runExit(decodeRetrieveQuery({ query: 'sql injection' }));
    expect(Exit.isSuccess(exit)).toBe(true);
    if (Exit.isSuccess(exit)) {
      expect(exit.value.k).toBe(5);
    }
  });

  it('accepts filters and namespace', async () => {
    const exit = await runExit(
      decodeRetrieveQuery({
        query: 'idor',
        namespaces: ['web'],
        k: 10,
        filters: { cwe: [639], product: 'rails', minTier: 2 }
      })
    );
    expect(Exit.isSuccess(exit)).toBe(true);
  });

  it('rejects a missing query', async () => {
    const exit = await runExit(decodeRetrieveQuery({ namespaces: ['web'] }));
    expect(getFailure(exit)).toBeInstanceOf(RetrieveQueryParseError);
  });

  it('rejects k out of range', async () => {
    const exit = await runExit(decodeRetrieveQuery({ query: 'x', k: 999 }));
    expect(getFailure(exit)).toBeInstanceOf(RetrieveQueryParseError);
  });

  it('rejects an unknown filter key', async () => {
    const exit = await runExit(
      decodeRetrieveQuery({ query: 'x', filters: { category: 'authz' } })
    );
    expect(getFailure(exit)).toBeInstanceOf(RetrieveQueryParseError);
  });
});
