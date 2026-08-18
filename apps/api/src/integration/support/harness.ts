import {
  makeSessionRepoTest,
  makeUserRepoTest,
  RecordRepoDefault,
  type RecordInsert,
  type Session,
  SourceRepoDefault,
  type User
} from '@repo/db';
import {
  EmbeddingService,
  EmbeddingServiceLive,
  IngestServiceLive,
  makeEmbeddingServiceTest,
  makeRerankServiceTest,
  type RecordInput,
  RerankService,
  RerankServiceLive,
  RetrieverServiceLive
} from '@repo/rag-core';
import { Effect, Layer, ManagedRuntime } from 'effect';
import { Pool } from 'pg';
import type { AppRuntime } from '../../app-env';
import { makeAuthServiceTest, type Permissions } from '../../lib/effect-auth';

/**
 * Shared harness for the integration tests. Builds an `AppRuntime` whose
 * Record/Source repos are the REAL Drizzle-over-Postgres implementations
 * (pointed at the testcontainers DB) while auth is a test double.
 *
 * Auth strategy (documented per the brief): we DO NOT mint real better-auth
 * session tokens. Instead we supply a `makeAuthServiceTest` layer that grants
 * the requested permissions and fake User/Session repos returning a fixed
 * admin principal. Everything on the retrieve/ingest DB path — embedding
 * storage, pgvector ANN, lexical FTS, dedup, transactions — is real.
 */

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

export const adminUser: User = {
  id: 'user-1',
  name: 'Ad Min',
  email: 'admin@example.com',
  emailVerified: true,
  image: null,
  createdAt: new Date('2026-07-01T00:00:00.000Z'),
  updatedAt: new Date('2026-07-01T00:00:00.000Z'),
  isAnonymous: false,
  role: 'admin',
  banned: false,
  banReason: null,
  banExpires: null
};

export const adminSession: Session = {
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
};

const grantsEvery = (granted: Permissions, requested: Permissions): boolean =>
  Object.entries(requested).every(([resource, actions]) =>
    actions.every((action) => (granted[resource] ?? []).includes(action))
  );

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

export interface RuntimeOptions {
  /** testcontainers Postgres connection URI. */
  readonly databaseUrl: string;
  /** `fake` (deterministic, no TEI) or `live` (real TEI). Default `fake`. */
  readonly embedding?: 'fake' | 'live';
  /** `fake` (lexical overlap) or `live` (TEI cross-encoder). Default `fake`. */
  readonly rerank?: 'fake' | 'live';
  /** Required when `embedding: 'live'`. */
  readonly embeddingEndpoint?: string | null;
  /** Required when `rerank: 'live'`. */
  readonly rerankEndpoint?: string | null;
  /** Permissions the auth double grants. Default `{ record: ['read','ingest'] }`. */
  readonly granted?: Permissions;
  /** Whether the auth double reports an active session. Default `true`. */
  readonly hasSession?: boolean;
  /** Role stamped on the returned principal. Default `admin`. */
  readonly role?: 'admin' | 'user';
}

/**
 * Build a DB-backed `AppRuntime`. The build-error channel (`ConfigError |
 * SqlError` from the real Drizzle layers) is elided to `never` with a cast —
 * exactly as production `makeAppRuntime` does — because `AppRuntime` pins the
 * error channel to `never`.
 */
export const buildIntegrationRuntime = (opts: RuntimeOptions): AppRuntime => {
  process.env.DATABASE_URL = opts.databaseUrl;

  const wantsLive = opts.embedding === 'live' || opts.rerank === 'live';
  if (wantsLive) {
    if (opts.embeddingEndpoint) process.env.EMBEDDING_ENDPOINT = opts.embeddingEndpoint;
    if (opts.rerankEndpoint) process.env.RERANK_ENDPOINT = opts.rerankEndpoint;
    process.env.EMBEDDING_DIM = '1024';
  }

  // The live layers carry a `ConfigError` build-error channel while the test
  // doubles carry `never`; widen both to `unknown` so the ternary is one type.
  const embedding: Layer.Layer<EmbeddingService, unknown, never> =
    opts.embedding === 'live' ? EmbeddingServiceLive : makeEmbeddingServiceTest();
  const rerank: Layer.Layer<RerankService, unknown, never> =
    opts.rerank === 'live' ? RerankServiceLive : makeRerankServiceTest();

  const currentUser: User = { ...adminUser, role: opts.role ?? 'admin' };
  const currentSession = adminSession;
  // Superset so both doorways pass: HTTP routes require `management:['access']`,
  // MCP tools require `record:['read'|'ingest']`.
  const granted = opts.granted ?? { management: ['access'], record: ['read', 'ingest'] };
  const hasSession = opts.hasSession ?? true;

  const auth = makeAuthServiceTest({
    getSession: () =>
      Effect.succeed(
        hasSession ? { user: { id: currentUser.id }, session: { id: currentSession.id } } : null
      ),
    userHasPermission: (_principal, requested) => Effect.succeed(grantsEvery(granted, requested))
  });

  // Real repos. Each `*Default` bakes in its own DrizzleLive; Effect's layer
  // memoization builds each referenced layer exactly once for the whole graph,
  // so both `deps` (for the domain services) and the top-level merge share one
  // pool per repo.
  const dbInfra = Layer.mergeAll(RecordRepoDefault, SourceRepoDefault);
  const deps = Layer.mergeAll(dbInfra, embedding, rerank);
  const retriever = RetrieverServiceLive.pipe(Layer.provide(deps));
  const ingest = IngestServiceLive.pipe(Layer.provide(deps));

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
    dbInfra,
    embedding,
    rerank,
    retriever,
    ingest
  );

  return ManagedRuntime.make(layer) as unknown as AppRuntime;
};

// ---------------------------------------------------------------------------
// Admin SQL — a plain `pg` pool used to promote/inspect/reset the corpus. It
// bypasses the repos deliberately (there is no repo method to flip status).
// ---------------------------------------------------------------------------

export const makeAdminPool = (databaseUrl: string): Pool =>
  new Pool({ connectionString: databaseUrl });

/** Flip every record to `active` (records land as `staging` by DB default). */
export const promoteAllToActive = async (pool: Pool): Promise<void> => {
  await pool.query(`UPDATE "bit"."records" SET status = 'active'`);
};

/** Promote a single record identified by its content hash. */
export const promoteByHash = async (pool: Pool, hash: string): Promise<void> => {
  await pool.query(`UPDATE "bit"."records" SET status = 'active' WHERE content_hash = $1`, [hash]);
};

/** Soft-delete a single record identified by its content hash. */
export const softDeleteByHash = async (pool: Pool, hash: string): Promise<void> => {
  await pool.query(`UPDATE "bit"."records" SET deleted_at = now() WHERE content_hash = $1`, [hash]);
};

/** Count records with the given content hash (dedup assertions). */
export const countRecordsByHash = async (pool: Pool, hash: string): Promise<number> => {
  const res = await pool.query<{ n: string }>(
    `SELECT count(*)::text AS n FROM "bit"."records" WHERE content_hash = $1`,
    [hash]
  );
  return Number(res.rows[0]?.n ?? '0');
};

/** Total record rows (transaction-rollback assertions). */
export const countRecords = async (pool: Pool): Promise<number> => {
  const res = await pool.query<{ n: string }>(`SELECT count(*)::text AS n FROM "bit"."records"`);
  return Number(res.rows[0]?.n ?? '0');
};

/** Total record_sources rows (transaction-rollback assertions). */
export const countRecordSources = async (pool: Pool): Promise<number> => {
  const res = await pool.query<{ n: string }>(
    `SELECT count(*)::text AS n FROM "bit"."record_sources"`
  );
  return Number(res.rows[0]?.n ?? '0');
};

/** Reset the corpus between tests. */
export const truncateCorpus = async (pool: Pool): Promise<void> => {
  await pool.query(
    `TRUNCATE "bit"."record_sources", "bit"."records", "bit"."sources" RESTART IDENTITY CASCADE`
  );
};

// ---------------------------------------------------------------------------
// Input factories
// ---------------------------------------------------------------------------

let seq = 0;

/** A valid `RecordInput` with unique title/symptom/procedure by default (so
 * distinct calls produce distinct content hashes). Override any field. */
export const makeRecordInput = (overrides: Partial<RecordInput> = {}): RecordInput => {
  seq += 1;
  return {
    namespaces: ['default'],
    title: `Record ${seq}`,
    symptom: `symptom ${seq}`,
    procedure: `procedure ${seq}`,
    whenToUse: undefined,
    confirmationSignal: undefined,
    preconditions: [],
    appliesTo: [],
    cwe: [],
    vrt: [],
    chainsWith: [],
    qualityTier: 3,
    sources: [],
    ...overrides
  } as RecordInput;
};

/** A bare `RecordInsert` row (zero vector + unique hash) for exercising
 * `RecordRepo.insert` directly, e.g. the transaction-rollback test. */
export const makeInsertRow = (overrides: Partial<RecordInsert> = {}): RecordInsert => {
  seq += 1;
  return {
    namespaces: ['default'],
    title: `Direct ${seq}`,
    symptom: `direct symptom ${seq}`,
    procedure: `direct procedure ${seq}`,
    whenToUse: null,
    confirmationSignal: null,
    preconditions: [],
    appliesTo: [],
    cwe: [],
    vrt: [],
    chainsWith: [],
    qualityTier: 3,
    contentHash: `direct-hash-${seq}`,
    embedding: Array.from({ length: 1024 }, () => 0),
    ...overrides
  } as RecordInsert;
};
