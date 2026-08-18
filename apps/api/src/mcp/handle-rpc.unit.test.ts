import {
  makeRecordRepoTest,
  makeSessionRepoTest,
  makeSourceRepoTest,
  makeUserRepoTest,
  type RecordRow,
  type Session,
  type User
} from '@repo/db';
import {
  makeEmbeddingServiceTest,
  makeIngestServiceTest,
  makeRerankServiceTest,
  makeRetrieverServiceTest
} from '@repo/rag-core';
import { Effect, Layer, ManagedRuntime, Option } from 'effect';
import { describe, expect, it } from 'vitest';
import type { AppRuntime } from '../app-env';
import { makeApiKeyServiceTest } from '../lib/api-keys';
import { makeAuthServiceTest, type Permissions } from '../lib/effect-auth';
import { handleRpc, type McpContext } from './handle-rpc';
import type { JsonRpcErrorResponse, JsonRpcResultResponse } from './protocol';

// ---------------------------------------------------------------------------
// Fixtures — mirror the route unit tests' test doubles.
// ---------------------------------------------------------------------------

const user = (overrides: Partial<User> = {}): User => ({
  id: 'user-1',
  name: 'Reg Ular',
  email: 'user@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'user',
  banned: false,
  banReason: null,
  banExpires: null,
  ...overrides
});

const session = (): Session => ({
  id: 'session-1',
  expiresAt: new Date('2026-07-02T00:00:00.000Z'),
  token: 'token',
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  ipAddress: null,
  userAgent: null,
  userId: 'user-1',
  impersonatedBy: null,
  activeOrganizationId: null
});

const record = (overrides: Partial<RecordRow> = {}): RecordRow => ({
  id: 'record-1',
  namespaces: ['acme'],
  title: 'SQL injection in login form',
  symptom: 'error-based boolean on username',
  whenToUse: null,
  procedure: 'inject a quote and observe the 500',
  confirmationSignal: null,
  preconditions: [],
  appliesTo: [],
  cwe: [],
  vrt: [],
  chainsWith: [],
  qualityTier: 2,
  status: 'active',
  version: 1,
  contentHash: 'hash-1',
  embedding: [],
  fts: '',
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  deletedAt: null,
  ...overrides
});

const grantsEvery = (granted: Permissions, requested: Permissions): boolean =>
  Object.entries(requested).every(([resource, actions]) =>
    actions.every((action) => (granted[resource] ?? []).includes(action))
  );

/**
 * Build a full `AppServices` runtime from test doubles so `ManagedRuntime.make`
 * yields exactly an `AppRuntime` (no cast). The retriever/ingest services are
 * the real rag-core pipelines fed by the fake repos, so their output is the
 * genuine `Chunk`/`IngestResult` contract.
 */
const makeTestRuntime = (
  options: { granted?: Permissions; hasSession?: boolean; records?: Array<RecordRow> } = {}
): AppRuntime => {
  const currentUser = user();
  const currentSession = session();
  const granted = options.granted ?? { record: ['read', 'ingest'] };
  const hasSession = options.hasSession ?? true;
  const records = options.records ?? [record()];

  const auth = makeAuthServiceTest({
    getSession: () =>
      Effect.succeed(
        hasSession ? { user: { id: currentUser.id }, session: { id: currentSession.id } } : null
      ),
    userHasPermission: (_principal, requested) => Effect.succeed(grantsEvery(granted, requested))
  });

  const recordRepo = makeRecordRepoTest({
    findByHash: () => Effect.succeed(Option.none()),
      addNamespaces: () => Effect.succeed(Option.none()),
    insert: () => Effect.succeed({ id: 'record-1', inserted: true, status: 'staging' }),
    nearest: () => Effect.succeed(records),
    lexical: () => Effect.succeed([]),
    getById: () => Effect.succeed(Option.none()),
    sourcesFor: () => Effect.succeed(new Map()),
      updateStatus: () => Effect.succeed(Option.none()),
      listByStatus: () => Effect.succeed([])
  });
  const sourceRepo = makeSourceRepoTest({
    upsertByUrl: () => Effect.succeed('source-1'),
    getById: () => Effect.succeed(Option.none())
  });
  const embedding = makeEmbeddingServiceTest();
  const rerank = makeRerankServiceTest();

  const deps = Layer.mergeAll(recordRepo, sourceRepo, embedding, rerank);
  const retriever = makeRetrieverServiceTest().pipe(Layer.provide(deps));
  const ingest = makeIngestServiceTest().pipe(Layer.provide(deps));

  const layer = Layer.mergeAll(
    auth,
    makeUserRepoTest({
      findById: () => Effect.succeed(currentUser),
      findByEmail: () => Effect.succeed(currentUser),
      // The admin directory is exercised in its own tests; these doubles
      // only need the member to satisfy the repo's shape.
      listForAdmin: () => Effect.succeed([])
    }),
    makeSessionRepoTest({ findById: () => Effect.succeed(currentSession) }),
    recordRepo,
    sourceRepo,
    embedding,
    rerank,
    retriever,
    ingest,
    // The MCP doorway never touches api keys; the runtime just has to satisfy
    // the full AppServices union.
    makeApiKeyServiceTest({
      list: () => Effect.succeed([]),
      create: () => Effect.die('unused'),
      delete: () => Effect.void
    })
  );

  return ManagedRuntime.make(layer);
};

const ctxFor = (runtime: AppRuntime, headers: Headers = new Headers()): McpContext => ({
  headers,
  runtime
});

const asResult = (response: unknown): JsonRpcResultResponse => {
  const r = response as JsonRpcResultResponse;
  if (!('result' in r)) throw new Error('Expected a JSON-RPC result response');
  return r;
};

const asError = (response: unknown): JsonRpcErrorResponse => {
  const r = response as JsonRpcErrorResponse;
  if (!('error' in r)) throw new Error('Expected a JSON-RPC error response');
  return r;
};

// ---------------------------------------------------------------------------
// Contract tests.
// ---------------------------------------------------------------------------

describe('handleRpc — server/discover', () => {
  it('advertises supported versions, capabilities, and serverInfo', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 'd1', method: 'server/discover' },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    expect(result.resultType).toBe('complete');
    expect(result.supportedVersions).toContain('2026-07-28');
    expect(result.capabilities).toEqual({ tools: { listChanged: false } });
    expect(result.serverInfo).toEqual({ name: 'bit', version: '0.1.0' });
  });
});

// ---- REMOVE BY DECEMBER 2026 (with the `initialize` arm in handle-rpc.ts) ----
describe('handleRpc — legacy initialize bridge', () => {
  it('answers the pre-2026-07-28 handshake so shipping clients can connect', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 0,
        method: 'initialize',
        params: { protocolVersion: '2025-11-25', clientInfo: { name: 'claude-code' } }
      },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    // Echo the revision the client opened with, not the one we actually speak —
    // it hangs up on a version it did not ask for.
    expect(result.protocolVersion).toBe('2025-11-25');
    expect(result.serverInfo).toEqual({ name: 'bit', version: '0.1.0' });
  });

  it('keeps the handshake out of the advertised revisions', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 'd2', method: 'server/discover' },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    expect(result.supportedVersions).toEqual(['2026-07-28']);
  });
});
// ---- end removal block ------------------------------------------------------

describe('handleRpc — tools/list', () => {
  it('returns cache hints, deterministic order, and resultType complete', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    expect(result.resultType).toBe('complete');
    expect(result.ttlMs).toBe(3_600_000);
    expect(result.cacheScope).toBe('public');
    const tools = result.tools as Array<{ name: string; inputSchema: { $schema?: string } }>;
    expect(tools.map((t) => t.name)).toEqual(['bit_ingest', 'bit_retrieve']);
    // inputSchema is derived from the rag-core Effect Schema (draft-07).
    expect(tools[0]?.inputSchema.$schema).toBe('http://json-schema.org/draft-07/schema#');
  });
});

describe('handleRpc — tools/call bit_retrieve', () => {
  it('returns a complete envelope whose chunks carry kind:methodology', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'bit_retrieve', arguments: { query: 'sql injection login', k: 3 } }
      },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    expect(result.resultType).toBe('complete');
    expect(result.isError).toBe(false);
    const structured = result.structuredContent as { chunks: Array<{ kind: string; id: string }> };
    expect(structured.chunks).toHaveLength(1);
    expect(structured.chunks[0]?.kind).toBe('methodology');
    expect(structured.chunks[0]?.id).toBe('record-1');
    // Backward-compat: the JSON is also serialized into a text content block.
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0]?.type).toBe('text');
    expect(JSON.parse(content[0]?.text ?? '{}').chunks[0].kind).toBe('methodology');
  });

  it('reports retrieval diagnostics to the MCP client in both content blocks', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'bit_retrieve', arguments: { query: 'sql injection login', k: 3 } }
      },
      ctxFor(runtime)
    );
    const { result } = asResult(response);
    // An agent must be able to see that the vector leg came back short (1 of
    // 30 candidates here) rather than trusting a thin result set as complete.
    const expected = {
      semantic_search_k: 30,
      semantic_search_count: 1,
      semantic_search_degraded: true,
      lexical_search_k: 30,
      lexical_search_count: 0
    };
    const structured = result.structuredContent as { diagnostics: typeof expected };
    expect(structured.diagnostics).toEqual(expected);
    // …and in the serialized text block, which is what most clients read.
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content[0]?.text ?? '{}').diagnostics).toEqual(expected);
  });
});

describe('handleRpc — statelessness', () => {
  it('processes two independent calls with no initialize and no session header', async () => {
    const runtime = makeTestRuntime();
    const first = await handleRpc(
      { jsonrpc: '2.0', id: 'a', method: 'tools/list' },
      ctxFor(runtime)
    );
    const second = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 'b',
        method: 'tools/call',
        params: { name: 'bit_retrieve', arguments: { query: 'sql injection', k: 1 } }
      },
      ctxFor(runtime)
    );
    expect(asResult(first).result.resultType).toBe('complete');
    expect(asResult(second).result.isError).toBe(false);
  });
});

describe('handleRpc — protocol errors', () => {
  it('rejects an unknown method with -32601', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 9, method: 'does/not-exist' },
      ctxFor(runtime)
    );
    expect(asError(response).error.code).toBe(-32601);
  });

  it('rejects an unsupported protocolVersion in _meta with -32022', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/list',
        params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } }
      },
      ctxFor(runtime)
    );
    const { error } = asError(response);
    expect(error.code).toBe(-32022);
    expect((error.data as { supported: string[] }).supported).toEqual(['2026-07-28']);
  });

  it('rejects an unknown tool name with -32602', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'bit_nope', arguments: {} } },
      ctxFor(runtime)
    );
    expect(asError(response).error.code).toBe(-32602);
  });

  it('returns no response for a notification (id-less request)', async () => {
    const runtime = makeTestRuntime();
    // No `id` member -> JSON-RPC notification -> the server must not respond.
    const response = await handleRpc({ jsonrpc: '2.0', method: 'tools/list' }, ctxFor(runtime));
    expect(response).toBeNull();
  });
});

describe('handleRpc — auth is a protocol error, not a tool-execution result', () => {
  it('returns 40300/forbidden when bit_ingest is called with a read-only permission double', async () => {
    const runtime = makeTestRuntime({ granted: { record: ['read'] } });
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/call',
        params: {
          name: 'bit_ingest',
          arguments: {
            namespaces: ['acme'],
            title: 'SQL injection in login form',
            symptom: 'error-based boolean on username',
            procedure: 'inject a quote and observe the 500'
          }
        }
      },
      ctxFor(runtime)
    );
    const { error } = asError(response);
    expect(error.code).toBe(40300);
    expect((error.data as { httpStatus: number }).httpStatus).toBe(403);
  });

  it('returns 40100/unauthorized when there is no session', async () => {
    const runtime = makeTestRuntime({ hasSession: false });
    const response = await handleRpc(
      {
        jsonrpc: '2.0',
        id: 13,
        method: 'tools/call',
        params: { name: 'bit_retrieve', arguments: { query: 'sql injection', k: 1 } }
      },
      ctxFor(runtime)
    );
    expect(asError(response).error.code).toBe(40100);
  });
});

describe('handleRpc — request strictness', () => {
  it('rejects a null id with -32600 (id must be string or integer)', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc({ jsonrpc: '2.0', id: null, method: 'tools/list' }, ctxFor(runtime));
    expect(asError(response).error.code).toBe(-32600);
  });

  it('rejects a non-integer id with -32600', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc({ jsonrpc: '2.0', id: 1.5, method: 'tools/list' }, ctxFor(runtime));
    expect(asError(response).error.code).toBe(-32600);
  });

  it('rejects non-object tool arguments with -32602', async () => {
    const runtime = makeTestRuntime();
    const response = await handleRpc(
      { jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'bit_retrieve', arguments: 'nope' } },
      ctxFor(runtime)
    );
    expect(asError(response).error.code).toBe(-32602);
  });
});
