import { describe, expect, it } from 'vitest';
import { contentHash } from './content-hash';

const base = { title: 'SQL Injection', symptom: 'Error leakage', procedure: 'Inject a quote' };

describe('contentHash', () => {
  it('is deterministic for identical input', () => {
    expect(contentHash(base)).toBe(contentHash(base));
  });

  it('produces a 64-char sha-256 hex digest', () => {
    expect(contentHash(base)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is insensitive to case and whitespace', () => {
    const noisy = {
      title: '  sql   injection ',
      symptom: 'ERROR    leakage',
      procedure: '\tInject a  quote\n'
    };
    expect(contentHash(noisy)).toBe(contentHash(base));
  });

  it('changes when content changes', () => {
    expect(contentHash({ ...base, procedure: 'inject two quotes' })).not.toBe(contentHash(base));
  });

  it('distinguishes field boundaries', () => {
    const a = { title: 'ab', symptom: 'c', procedure: 'd' };
    const b = { title: 'a', symptom: 'bc', procedure: 'd' };
    expect(contentHash(a)).not.toBe(contentHash(b));
  });
});
