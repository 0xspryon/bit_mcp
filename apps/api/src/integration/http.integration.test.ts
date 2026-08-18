import { IngestService } from '@repo/rag-core';
import { Effect } from 'effect';
import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import type { AppRuntime } from '../app-env';
import { API_BASE_PATH } from '../hc';
import { createApp } from '../index';
import {
  buildIntegrationRuntime,
  makeAdminPool,
  makeRecordInput,
  promoteAllToActive,
  truncateCorpus
} from './support/harness';

/**
 * HTTP e2e over the real Hono app (`createApp(runtime).request(...)`) against a
 * DB-backed runtime (fake embedder, real Record/Source repos).
 *
 * Auth: handled by the test AuthService double granting `record:['read',
 * 'ingest']` with fake User/Session repos (see harness). The retrieve/ingest DB
 * behaviour is fully real — records are embedded, stored, promoted, and read
 * back out of pgvector/FTS.
 */

const dockerAvailable = inject('dockerAvailable');
const databaseUrl = inject('databaseUrl');

describe.skipIf(!dockerAvailable)('HTTP e2e', () => {
  let runtime: AppRuntime;
  let pool: Pool;
  let app: ReturnType<typeof createApp>;

  const post = (path: string, body: unknown) =>
    app.request(`${API_BASE_PATH}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });

  const dedupInput = makeRecordInput({
    namespaces: ['acme'],
    title: 'Path traversal in file download',
    symptom: 'dot-dot-slash in the filename parameter',
    procedure: 'request ../../etc/passwd via the download endpoint'
  });

  beforeAll(async () => {
    runtime = buildIntegrationRuntime({ databaseUrl, embedding: 'fake', rerank: 'fake' });
    pool = makeAdminPool(databaseUrl);
    app = createApp(runtime);

    await truncateCorpus(pool);
    // Seed one ACTIVE record for the retrieve happy-path.
    await runtime.runPromise(
      Effect.flatMap(IngestService, (s) =>
        s.ingest(
          makeRecordInput({
            namespaces: ['acme'],
            title: 'SQL injection in login form',
            symptom: 'error-based boolean on username',
            procedure: 'inject a quote and observe the 500'
          })
        )
      )
    );
    await promoteAllToActive(pool);
  });

  afterAll(async () => {
    await pool.end();
    await runtime.dispose();
  });

  it('GET /health returns 200 and the expected shape', async () => {
    const res = await app.request(`${API_BASE_PATH}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; embeddingModel: string; embeddingDim: number };
    expect(body.ok).toBe(true);
    expect(body.embeddingDim).toBe(1024);
    expect(typeof body.embeddingModel).toBe('string');
  });

  it('POST /retrieve happy path returns chunks for an authenticated caller', async () => {
    const res = await post('/retrieve', { query: 'sql injection login', namespaces: ['acme'], k: 5 });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { chunks: Array<{ kind: string; namespaces: string[] }> };
    expect(body.chunks.length).toBeGreaterThan(0);
    expect(body.chunks[0]?.kind).toBe('methodology');
    expect(body.chunks.every((c) => c.namespaces.includes('acme'))).toBe(true);
  });

  it('POST /retrieve returns 400 on an invalid body', async () => {
    const res = await post('/retrieve', { notquery: true });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('INVALID_RETRIEVE_INPUT');
  });

  it('POST /ingest happy path stores a new staging record', async () => {
    const res = await post('/ingest', dedupInput);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { id: string; deduped: boolean; status: string };
    expect(body.deduped).toBe(false);
    expect(body.status).toBe('staging');
    expect(body.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('POST /ingest is idempotent: re-ingesting the same record dedupes', async () => {
    const res = await post('/ingest', dedupInput);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { deduped: boolean };
    expect(body.deduped).toBe(true);
  });
});
