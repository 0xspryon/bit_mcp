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
 * MCP contract e2e: drive the stateless JSON-RPC doorway over the real HTTP
 * route (`createApp(runtime).request('/api/v1/mcp', …)`) against a DB-backed runtime
 * (fake embedder, real Record/Source repos). Auth is the test double granting
 * `record:['read','ingest']`.
 */

const dockerAvailable = inject('dockerAvailable');
const databaseUrl = inject('databaseUrl');

describe.skipIf(!dockerAvailable)('MCP doorway e2e', () => {
  let runtime: AppRuntime;
  let pool: Pool;
  let app: ReturnType<typeof createApp>;

  const postRpc = async (body: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(`${API_BASE_PATH}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body)
    });
    return (await res.json()) as { result?: Record<string, unknown>; error?: Record<string, unknown> };
  };

  beforeAll(async () => {
    runtime = buildIntegrationRuntime({ databaseUrl, embedding: 'fake', rerank: 'fake' });
    pool = makeAdminPool(databaseUrl);
    app = createApp(runtime);

    await truncateCorpus(pool);
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

  it('server/discover advertises supported versions + capabilities', async () => {
    const { result } = await postRpc({ jsonrpc: '2.0', id: 'd1', method: 'server/discover' });
    expect(result?.resultType).toBe('complete');
    expect(result?.supportedVersions).toContain('2026-07-28');
    expect(result?.capabilities).toEqual({ tools: { listChanged: false } });
    expect(result?.serverInfo).toEqual({ name: 'bit', version: '0.1.0' });
  });

  it('tools/list carries ttlMs, cacheScope:public and a deterministic order', async () => {
    const { result } = await postRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(result?.resultType).toBe('complete');
    expect(result?.ttlMs).toBe(3_600_000);
    expect(result?.cacheScope).toBe('public');
    const tools = result?.tools as Array<{ name: string }>;
    expect(tools.map((t) => t.name)).toEqual(['bit_ingest', 'bit_retrieve']);
  });

  it('tools/call bit_retrieve returns resultType:complete with methodology chunks', async () => {
    const { result } = await postRpc({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'bit_retrieve', arguments: { query: 'sql injection login', namespaces: ['acme'], k: 3 } }
    });
    expect(result?.resultType).toBe('complete');
    expect(result?.isError).toBe(false);
    const structured = result?.structuredContent as { chunks: Array<{ kind: string }> };
    expect(structured.chunks.length).toBeGreaterThan(0);
    for (const chunk of structured.chunks) {
      expect(chunk.kind).toBe('methodology');
    }
  });

  it('is stateless: two independent POSTs succeed with no handshake and no session header', async () => {
    const first = await postRpc({ jsonrpc: '2.0', id: 'a', method: 'tools/list' });
    const second = await postRpc({
      jsonrpc: '2.0',
      id: 'b',
      method: 'tools/call',
      params: { name: 'bit_retrieve', arguments: { query: 'sql injection', namespaces: ['acme'], k: 1 } }
    });
    expect(first.result?.resultType).toBe('complete');
    expect(second.result?.isError).toBe(false);
  });
});
