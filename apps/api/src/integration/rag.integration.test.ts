import { RecordRepo } from '@repo/db';
import { contentHash, IngestService, RetrieverService } from '@repo/rag-core';
import { Effect, Exit, Option } from 'effect';
import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, inject, it } from 'vitest';
import type { AppRuntime } from '../app-env';
import {
  buildIntegrationRuntime,
  countRecords,
  countRecordSources,
  countRecordsByHash,
  makeAdminPool,
  makeInsertRow,
  makeRecordInput,
  promoteAllToActive,
  promoteByHash,
  softDeleteByHash,
  truncateCorpus
} from './support/harness';

/**
 * The eight REQUIRED integration cases from the brief, exercised against a real
 * pgvector Postgres (testcontainers) through the real Record/Source repos.
 *
 * Cases 1,2,4,6,7,7b,8 use the DETERMINISTIC fake embedder — they assert SQL/DB
 * behaviour (roundtrip, lexical FTS recall, namespace isolation, dedup, staging
 * visibility, soft-delete visibility, transaction rollback) that needs
 * Postgres+pgvector but NOT TEI.
 *
 * Cases 3 (semantic recall) and 5 (rerank-first) need REAL vectors and live a
 * TEI-gated nested block.
 */

const dockerAvailable = inject('dockerAvailable');
const databaseUrl = inject('databaseUrl');
const embeddingEndpoint = inject('embeddingEndpoint');
const rerankEndpoint = inject('rerankEndpoint');
const hasTei = embeddingEndpoint !== null && rerankEndpoint !== null;

describe.skipIf(!dockerAvailable)('RAG integration (fake embedder, real DB)', () => {
  let runtime: AppRuntime;
  let pool: Pool;

  const ingest = (input: unknown) =>
    runtime.runPromise(Effect.flatMap(IngestService, (s) => s.ingest(input)));
  const retrieve = (query: unknown) =>
    runtime.runPromise(Effect.flatMap(RetrieverService, (s) => s.retrieve(query))).then((r) => r.chunks);

  beforeAll(() => {
    runtime = buildIntegrationRuntime({ databaseUrl, embedding: 'fake', rerank: 'fake' });
    pool = makeAdminPool(databaseUrl);
  });

  afterAll(async () => {
    await pool.end();
    await runtime.dispose();
  });

  beforeEach(async () => {
    await truncateCorpus(pool);
  });

  // 1 -----------------------------------------------------------------------
  it('ingest → promote → retrieve roundtrip', async () => {
    const input = makeRecordInput({
      namespaces: ['acme'],
      title: 'SQL injection in login form',
      symptom: 'error-based boolean on username',
      procedure: 'inject a quote and observe the 500'
    });

    const result = await ingest(input);
    expect(result.deduped).toBe(false);
    expect(result.status).toBe('staging');

    await promoteAllToActive(pool);

    const chunks = await retrieve({ query: 'sql injection login', namespaces: ['acme'], k: 5 });
    expect(chunks.map((c) => c.id)).toContain(result.id);
    const hit = chunks.find((c) => c.id === result.id);
    expect(hit?.kind).toBe('methodology');
    expect(hit?.namespaces).toContain('acme');
  });

  // 2 -----------------------------------------------------------------------
  it('exact-token lexical recall: a token present only in procedure is found', async () => {
    // Decoy with no `X-Forwarded-Host` token anywhere.
    await ingest(
      makeRecordInput({
        namespaces: ['acme'],
        title: 'CSRF on profile update',
        symptom: 'state-changing request without token',
        procedure: 'submit a forged cross-site form'
      })
    );
    // Target: the literal token lives ONLY in `procedure`.
    const target = await ingest(
      makeRecordInput({
        namespaces: ['acme'],
        title: 'Password reset poisoning',
        symptom: 'reset link points at attacker host',
        procedure: 'Set the X-Forwarded-Host header to attacker.example and request a reset link'
      })
    );
    await promoteAllToActive(pool);

    // The fake embedder makes the dense leg semantically meaningless, so a hit
    // here proves the LEXICAL leg (websearch_to_tsquery over the fts column)
    // matched the literal token.
    const chunks = await retrieve({ query: 'X-Forwarded-Host', namespaces: ['acme'], k: 5 });
    expect(chunks.map((c) => c.id)).toContain(target.id);
  });

  // 4 -----------------------------------------------------------------------
  it('namespace isolation: a namespace:A query never returns a namespace:B record', async () => {
    await ingest(
      makeRecordInput({
        namespaces: ['A'],
        title: 'Reflected XSS',
        symptom: 'input reflected without encoding',
        procedure: 'inject a script tag into the search parameter'
      })
    );
    const b = await ingest(
      makeRecordInput({
        namespaces: ['B'],
        title: 'Reflected XSS',
        symptom: 'input reflected without encoding',
        // Different procedure => different content hash => distinct record.
        procedure: 'inject a script tag into the referrer parameter payload'
      })
    );
    await promoteAllToActive(pool);

    const chunks = await retrieve({ query: 'reflected xss script tag', namespaces: ['A'], k: 10 });
    // Structural guarantee: the namespaces overlap filter is a hard correctness
    // filter — every returned record must be tagged with the queried namespace,
    // and the B-only record must never surface under a namespaces:['A'] query.
    expect(chunks.every((c) => c.namespaces.includes('A'))).toBe(true);
    expect(chunks.every((c) => !c.namespaces.includes('B') || c.namespaces.includes('A'))).toBe(
      true
    );
    expect(chunks.map((c) => c.id)).not.toContain(b.id);
  });

  // 4b ----------------------------------------------------------------------
  it('cross-namespace dedup-merge: identical content under a new namespace merges into one row, retrievable under either', async () => {
    const base = {
      title: 'Reflected XSS merge case',
      symptom: 'input reflected without encoding',
      procedure: 'inject a script tag into the merge-case search parameter'
    };

    // Ingest identical content first into ['A'], then into ['B'].
    const first = await ingest(makeRecordInput({ namespaces: ['A'], ...base }));
    expect(first.deduped).toBe(false);
    const second = await ingest(makeRecordInput({ namespaces: ['B'], ...base }));
    // Same content hash → merge, not a second row.
    expect(second.deduped).toBe(true);
    expect(second.id).toBe(first.id);

    const hash = contentHash(base);
    expect(await countRecordsByHash(pool, hash)).toBe(1);

    await promoteAllToActive(pool);

    // The single merged row carries the UNION of namespaces …
    const underA = await retrieve({ query: 'reflected xss merge case', namespaces: ['A'], k: 10 });
    const underB = await retrieve({ query: 'reflected xss merge case', namespaces: ['B'], k: 10 });
    const hitA = underA.find((c) => c.id === first.id);
    const hitB = underB.find((c) => c.id === first.id);
    // … and is retrievable under EITHER namespace.
    expect(hitA?.id).toBe(first.id);
    expect(hitB?.id).toBe(first.id);
    expect([...(hitA?.namespaces ?? [])].sort()).toEqual(['A', 'B']);
    expect([...(hitB?.namespaces ?? [])].sort()).toEqual(['A', 'B']);
  });

  // 6 -----------------------------------------------------------------------
  it('idempotent ingest: the same record twice yields one row + deduped:true', async () => {
    const input = makeRecordInput({
      namespaces: ['acme'],
      title: 'IDOR on invoice endpoint',
      symptom: 'sequential resource ids',
      procedure: 'increment the invoice id and observe another tenant record'
    });
    const hash = contentHash({
      title: input.title,
      symptom: input.symptom,
      procedure: input.procedure
    });

    const first = await ingest(input);
    const second = await ingest(input);

    expect(first.deduped).toBe(false);
    expect(second.deduped).toBe(true);
    expect(second.id).toBe(first.id);
    expect(await countRecordsByHash(pool, hash)).toBe(1);
  });

  // 7 -----------------------------------------------------------------------
  it('staging invisibility: a staging record is hidden while an active one is returned', async () => {
    // Staged (never promoted).
    const staged = await ingest(
      makeRecordInput({
        namespaces: ['acme'],
        title: 'Open redirect',
        symptom: 'unvalidated redirect target',
        procedure: 'set the next parameter to an external url'
      })
    );
    // Active.
    const activeInput = makeRecordInput({
      namespaces: ['acme'],
      title: 'Open redirect variant',
      symptom: 'unvalidated redirect parameter',
      procedure: 'set the returnTo parameter to an external url and follow it'
    });
    const active = await ingest(activeInput);
    const activeHash = contentHash({
      title: activeInput.title,
      symptom: activeInput.symptom,
      procedure: activeInput.procedure
    });
    await promoteByHash(pool, activeHash);

    const chunks = await retrieve({
      query: 'open redirect external url',
      namespaces: ['acme'],
      k: 10
    });
    const ids = chunks.map((c) => c.id);
    expect(ids).toContain(active.id);
    expect(ids).not.toContain(staged.id);
  });

  // 7b ----------------------------------------------------------------------
  it('soft-delete invisibility: a deleted record is hidden from retrieval but still fetchable by id', async () => {
    const deletedInput = makeRecordInput({
      namespaces: ['acme'],
      title: 'Session fixation',
      symptom: 'session id survives the login boundary',
      procedure: 'set a known session cookie then authenticate and reuse it'
    });
    const deleted = await ingest(deletedInput);
    const liveInput = makeRecordInput({
      namespaces: ['acme'],
      title: 'Session fixation variant',
      symptom: 'session identifier is not rotated on privilege change',
      procedure: 'plant a session cookie then escalate and reuse the same identifier'
    });
    const live = await ingest(liveInput);
    await promoteAllToActive(pool);

    // Both are active; only one is soft-deleted.
    await softDeleteByHash(
      pool,
      contentHash({
        title: deletedInput.title,
        symptom: deletedInput.symptom,
        procedure: deletedInput.procedure
      })
    );

    const chunks = await retrieve({
      query: 'session fixation reuse session identifier',
      namespaces: ['acme'],
      k: 10
    });
    const ids = chunks.map((c) => c.id);
    expect(ids).toContain(live.id);
    expect(ids).not.toContain(deleted.id);

    // The fetch-by-id path deliberately does NOT filter on deleted_at.
    const fetched = await runtime.runPromise(
      Effect.flatMap(RecordRepo, (repo) => repo.getById(deleted.id))
    );
    expect(Option.isSome(fetched)).toBe(true);
    if (Option.isSome(fetched)) {
      expect(fetched.value.deletedAt).toBeInstanceOf(Date);
    }
  });

  // 8 -----------------------------------------------------------------------
  it('transaction safety: a failed source write rolls back the whole insert', async () => {
    const row = makeInsertRow({ namespaces: ['acme'] });
    // The record inserts first; then this source (with a NULL url) violates the
    // NOT NULL constraint, so the whole transaction — record + already-written
    // sources — must roll back, leaving no orphan record or source rows.
    const badSource = { url: null as unknown as string, title: null, qualityTier: 3, kind: null };

    const exit = await runtime.runPromiseExit(
      Effect.flatMap(RecordRepo, (repo) => repo.insert(row, [badSource]))
    );

    expect(Exit.isFailure(exit)).toBe(true);
    expect(await countRecordsByHash(pool, row.contentHash)).toBe(0);
    expect(await countRecords(pool)).toBe(0);
    expect(await countRecordSources(pool)).toBe(0);
  });

  // 9 -----------------------------------------------------------------------
  it('concurrent inserts of identical content produce exactly one row (ON CONFLICT)', async () => {
    const row = makeInsertRow({ namespaces: ['acme'], contentHash: 'race-hash' });

    // Fire two inserts of the same content_hash concurrently. Both must succeed
    // (no unique-constraint 500); exactly one wins `inserted:true`.
    const results = await runtime.runPromise(
      Effect.all(
        [
          Effect.flatMap(RecordRepo, (repo) => repo.insert(row, [])),
          Effect.flatMap(RecordRepo, (repo) => repo.insert(row, []))
        ],
        { concurrency: 'unbounded' }
      )
    );

    expect(results.filter((r) => r.inserted)).toHaveLength(1);
    expect(results[0]?.id).toBe(results[1]?.id); // both resolve to the same row
    expect(await countRecordsByHash(pool, 'race-hash')).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// TEI-gated: real vectors + real cross-encoder.
// ---------------------------------------------------------------------------

describe.skipIf(!dockerAvailable || !hasTei)('RAG integration (real TEI)', () => {
  let runtime: AppRuntime;
  let pool: Pool;

  const ingest = (input: unknown) =>
    runtime.runPromise(Effect.flatMap(IngestService, (s) => s.ingest(input)));
  const retrieve = (query: unknown) =>
    runtime.runPromise(Effect.flatMap(RetrieverService, (s) => s.retrieve(query))).then((r) => r.chunks);

  beforeAll(() => {
    runtime = buildIntegrationRuntime({
      databaseUrl,
      embedding: 'live',
      rerank: 'live',
      embeddingEndpoint,
      rerankEndpoint
    });
    pool = makeAdminPool(databaseUrl);
  });

  afterAll(async () => {
    await pool.end();
    await runtime.dispose();
  });

  beforeEach(async () => {
    await truncateCorpus(pool);
  });

  // 3 -----------------------------------------------------------------------
  it('semantic recall: a paraphrased symptom retrieves via the dense leg', async () => {
    const target = await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'Reflected XSS',
        symptom:
          'The application echoes user-supplied query parameters into the HTML response without output encoding',
        procedure: 'Insert a script payload into the vulnerable parameter and confirm execution'
      })
    );
    // Decoys on unrelated topics.
    await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'SQL injection',
        symptom: 'database errors leak on a single quote',
        procedure: 'inject a boolean condition into the where clause'
      })
    );
    await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'SSRF',
        symptom: 'server fetches an attacker-controlled url',
        procedure: 'point the url parameter at the metadata endpoint'
      })
    );
    await promoteAllToActive(pool);

    // Paraphrase that shares almost no exact tokens with the target.
    const chunks = await retrieve({
      query: 'user input is rendered into the page unescaped allowing script injection',
      namespaces: ['sec'],
      k: 5
    });
    expect(chunks.map((c) => c.id)).toContain(target.id);
  });

  // 5 -----------------------------------------------------------------------
  it('rerank-first: the most relevant record ranks first after the cross-encoder', async () => {
    const target = await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'JWT signature not verified',
        symptom: 'the server accepts a token with alg set to none',
        procedure: 'strip the signature and set the alg header to none, then replay the token'
      })
    );
    await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'SQL injection',
        symptom: 'database errors leak on a single quote',
        procedure: 'inject a boolean condition into the where clause'
      })
    );
    await ingest(
      makeRecordInput({
        namespaces: ['sec'],
        title: 'Reflected XSS',
        symptom: 'input reflected without encoding',
        procedure: 'inject a script tag into the search parameter'
      })
    );
    await promoteAllToActive(pool);

    const chunks = await retrieve({
      query: 'jwt alg none signature bypass authentication',
      namespaces: ['sec'],
      k: 3
    });
    expect(chunks[0]?.id).toBe(target.id);
  });
});
