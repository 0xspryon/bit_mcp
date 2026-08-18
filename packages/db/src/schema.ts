import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  customType,
  index,
  integer,
  pgSchema,
  primaryKey,
  smallint,
  text,
  timestamp,
  uuid,
  vector
} from 'drizzle-orm/pg-core';

export const bit = pgSchema('bit');

// drizzle has no native tsvector column type. This custom type keeps the
// generated `fts` column selectable; the value is produced by Postgres (a
// GENERATED ALWAYS ... STORED column) so it is never inserted or updated.
const tsvector = customType<{ data: string; driverData: string }>({
  dataType() {
    return 'tsvector';
  }
});

export const sources = bit.table(
  'sources',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    url: text('url').notNull().unique(),
    title: text('title'),
    qualityTier: smallint('quality_tier').notNull().default(3),
    kind: text('kind'),
    addedAt: timestamp('added_at', { withTimezone: true }).notNull().defaultNow()
  },
  (table) => [check('sources_quality_tier_check', sql`${table.qualityTier} between 1 and 5`)]
);

export const records = bit.table(
  'records',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    // A record can belong to several vuln-classes; retrieval filters by array
    // overlap, and ingest-dedup merges new memberships onto the existing row.
    namespaces: text('namespaces').array().notNull(),
    title: text('title').notNull(),
    symptom: text('symptom').notNull(),
    whenToUse: text('when_to_use'),
    procedure: text('procedure').notNull(),
    confirmationSignal: text('confirmation_signal'),
    preconditions: text('preconditions')
      .array()
      .notNull()
      .default(sql`'{}'`),
    appliesTo: text('applies_to')
      .array()
      .notNull()
      .default(sql`'{}'`),
    cwe: integer('cwe')
      .array()
      .notNull()
      .default(sql`'{}'`),
    vrt: text('vrt')
      .array()
      .notNull()
      .default(sql`'{}'`),
    chainsWith: text('chains_with')
      .array()
      .notNull()
      .default(sql`'{}'`),
    qualityTier: smallint('quality_tier').notNull().default(3),
    status: text('status').notNull().default('staging'),
    version: integer('version').notNull().default(1),
    contentHash: text('content_hash').notNull().unique(),
    embedding: vector('embedding', { dimensions: 1024 }).notNull(),
    // STORED generated tsvector over the human-readable fields. Postgres owns
    // the value, so this column is excluded from the insert type by drizzle.
    fts: tsvector('fts').generatedAlwaysAs(
      sql`to_tsvector('english', coalesce(title, '') || ' ' || coalesce(symptom, '') || ' ' || coalesce(when_to_use, '') || ' ' || coalesce(procedure, '') || ' ' || coalesce(confirmation_signal, ''))`
    ),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    // Soft delete. NULL means live. Every retrieval path filters
    // `deleted_at is null`; the admin fetch-by-id path deliberately does NOT,
    // so a curator can still inspect a deleted record.
    deletedAt: timestamp('deleted_at', { withTimezone: true })
  },
  (table) => [
    // HNSW: a navigable-graph ANN index built incrementally as rows are
    // inserted, so it adapts continuously and has no data-at-build-time
    // (empty-table / stale-centroid) problem. `vector_cosine_ops` matches the
    // cosine distance the retriever orders by. Build params left at pgvector
    // defaults (m=16, ef_construction=64); recall/speed is tuned per query via
    // `hnsw.ef_search` (see record-repo `nearest`).
    //
    // Being an APPROXIMATE index has a consequence beyond ranking quality: a
    // query that combines this index with a WHERE clause post-filters the rows
    // the graph walk emits, so a selective filter can yield fewer rows than the
    // query's LIMIT asked for. `RecordRepo.nearest` documents the mechanism and
    // the measured numbers; the read path reports it to clients as
    // `RetrievalDiagnostics`.
    index('records_embedding_idx').using('hnsw', table.embedding.op('vector_cosine_ops')),
    index('records_fts_idx').using('gin', table.fts),
    index('records_namespaces_idx').using('gin', table.namespaces),
    index('records_cwe_idx').using('gin', table.cwe),
    // Domain invariants enforced at the DB, so a direct write / bad migration
    // can't create rows the application assumes impossible.
    check('records_status_check', sql`${table.status} in ('staging', 'active')`),
    check('records_quality_tier_check', sql`${table.qualityTier} between 1 and 5`),
    check('records_version_check', sql`${table.version} >= 1`),
    check('records_cwe_range_check', sql`1 <= all(${table.cwe}) and 2000 >= all(${table.cwe})`),
    // A record must belong to at least one vuln-class namespace.
    check('records_namespaces_nonempty_check', sql`array_length(${table.namespaces}, 1) >= 1`)
  ]
);

export const recordSources = bit.table(
  'record_sources',
  {
    recordId: uuid('record_id')
      .notNull()
      .references(() => records.id, { onDelete: 'cascade' }),
    sourceId: uuid('source_id')
      .notNull()
      .references(() => sources.id, { onDelete: 'cascade' })
  },
  (table) => [primaryKey({ columns: [table.recordId, table.sourceId] })]
);

// ---------------------------------------------------------------------------
// better-auth tables (column names/shapes are dictated by better-auth). These
// live in the same `bit` schema; ids are text (better-auth manages them).
// ---------------------------------------------------------------------------

export const user = bit.table('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerified: boolean('email_verified').default(false).notNull(),
  image: text('image'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at')
    .defaultNow()
    .$onUpdate(() => /* @__PURE__ */ new Date())
    .notNull(),
  isAnonymous: boolean('is_anonymous').default(false),
  role: text('role'),
  banned: boolean('banned').default(false),
  banReason: text('ban_reason'),
  banExpires: timestamp('ban_expires')
});

export const session = bit.table(
  'session',
  {
    id: text('id').primaryKey(),
    expiresAt: timestamp('expires_at').notNull(),
    token: text('token').notNull().unique(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at')
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    userId: text('user_id')
      .notNull()
      .references(() => user.id, { onDelete: 'cascade' }),
    impersonatedBy: text('impersonated_by'),
    activeOrganizationId: text('active_organization_id')
  },
  (table) => [index('session_userId_idx').on(table.userId)]
);

export const account = bit.table(
  'account',
  {
    id: text('id').primaryKey(),
    accountId: text('account_id').notNull(),
    providerId: text('provider_id').notNull(),
    userId: text('user_id')
      .notNull()
      .references(() => user.id, { onDelete: 'cascade' }),
    accessToken: text('access_token'),
    refreshToken: text('refresh_token'),
    idToken: text('id_token'),
    accessTokenExpiresAt: timestamp('access_token_expires_at'),
    refreshTokenExpiresAt: timestamp('refresh_token_expires_at'),
    scope: text('scope'),
    password: text('password'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at')
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull()
  },
  (table) => [index('account_userId_idx').on(table.userId)]
);

export const verification = bit.table(
  'verification',
  {
    id: text('id').primaryKey(),
    identifier: text('identifier').notNull(),
    value: text('value').notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at')
      .defaultNow()
      .$onUpdate(() => /* @__PURE__ */ new Date())
      .notNull()
  },
  (table) => [index('verification_identifier_idx').on(table.identifier)]
);

export const apikey = bit.table(
  'apikey',
  {
    id: text('id').primaryKey(),
    configId: text('config_id').default('default').notNull(),
    name: text('name'),
    start: text('start'),
    referenceId: text('reference_id').notNull(),
    prefix: text('prefix'),
    key: text('key').notNull(),
    refillInterval: integer('refill_interval'),
    refillAmount: integer('refill_amount'),
    lastRefillAt: timestamp('last_refill_at'),
    enabled: boolean('enabled').default(true),
    rateLimitEnabled: boolean('rate_limit_enabled').default(true),
    rateLimitTimeWindow: integer('rate_limit_time_window').default(86400000),
    rateLimitMax: integer('rate_limit_max').default(10),
    requestCount: integer('request_count').default(0),
    remaining: integer('remaining'),
    lastRequest: timestamp('last_request'),
    expiresAt: timestamp('expires_at'),
    createdAt: timestamp('created_at').notNull(),
    updatedAt: timestamp('updated_at').notNull(),
    permissions: text('permissions'),
    metadata: text('metadata')
  },
  (table) => [
    index('apikey_configId_idx').on(table.configId),
    index('apikey_referenceId_idx').on(table.referenceId),
    index('apikey_key_idx').on(table.key)
  ]
);
