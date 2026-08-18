import {
  type IngestError,
  IngestService,
  RecordInput,
  type RetrievalError,
  RetrieverService,
  RetrieveQuery
} from '@repo/rag-core';
import { Effect, JSONSchema } from 'effect';
import type { AppServices } from '../app-env';
import {
  type AuthError,
  authenticate,
  requirePermissions
} from '../lib/effect-auth';

/**
 * The two tools this doorway exposes, mirroring the HTTP `/retrieve` and
 * `/ingest` payloads over the SAME rag-core services. Nothing in
 * `@repo/rag-core` changes: the tool programs are the identical validate ->
 * authenticate -> authorize -> service pipeline the HTTP handlers run.
 */

/** A single MCP tool definition (subset of the `2026-07-28` `Tool` shape). */
export interface McpTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: ReturnType<typeof JSONSchema.make>;
}

/**
 * `inputSchema` is generated straight from the rag-core Effect `Schema` via
 * `JSONSchema.make`, so the wire contract can never drift from the schema the
 * service actually validates against. `JSONSchema.make` emits draft-07 with an
 * explicit `$schema`, which `2026-07-28` permits (the spec defaults to 2020-12
 * only when `$schema` is absent).
 */
const bitRetrieveTool: McpTool = {
  name: 'bit_retrieve',
  description:
    'Retrieve ranked vulnerability methodology chunks for a natural-language query. Requires the record:read permission.',
  inputSchema: JSONSchema.make(RetrieveQuery)
};

const bitIngestTool: McpTool = {
  name: 'bit_ingest',
  description:
    'Ingest a structured vulnerability methodology record. Requires the record:ingest permission (admin only).',
  inputSchema: JSONSchema.make(RecordInput)
};

/**
 * Static tool list in a DETERMINISTIC order (sorted by name), so clients can
 * cache the list and prompt-cache hit rates stay stable. Sorting yields
 * `bit_ingest` before `bit_retrieve`.
 */
export const TOOLS: ReadonlyArray<McpTool> = [bitIngestTool, bitRetrieveTool].sort((a, b) =>
  a.name.localeCompare(b.name)
);

/** Union of every modeled error a tool program can fail with. */
export type ToolProgramError = AuthError | RetrievalError | IngestError;

/**
 * A tool runner turns validated call arguments + the request `Headers` into an
 * Effect over the shared app services. Its requirements are a subset of
 * `AppServices` (assignable as-is) and its errors a subset of
 * `ToolProgramError`; both are widened here so the runners share one type.
 */
export type ToolRunner = (
  args: unknown,
  headers: Headers
) => Effect.Effect<unknown, ToolProgramError, AppServices>;

/**
 * `bit_retrieve`: authenticate -> require record:read -> RetrieverService. The
 * service validates `args` against `RetrieveQuery` itself, exactly as the HTTP
 * read path does.
 */
const retrieveRunner: ToolRunner = (args, headers) =>
  authenticate(headers).pipe(
    Effect.flatMap(requirePermissions(headers, { record: ['read'] })),
    Effect.flatMap(() => RetrieverService),
    // Resolves `{ chunks, diagnostics }` and both are handed to the client
    // verbatim. `diagnostics.semantic_search_degraded` tells an agent that the
    // vector leg returned fewer candidates than it asked for — the ranking it
    // is reading came from a smaller pool than intended, so a thin or
    // off-target result set is worth a broader retry rather than trusting.
    Effect.flatMap((retriever) => retriever.retrieve(args))
  );

/**
 * `bit_ingest`: authenticate -> require record:ingest -> IngestService. The
 * service validates `args` against `RecordInput` itself, exactly as the HTTP
 * write path does.
 */
const ingestRunner: ToolRunner = (args, headers) =>
  authenticate(headers).pipe(
    Effect.flatMap(requirePermissions(headers, { record: ['ingest'] })),
    Effect.flatMap(() => IngestService),
    Effect.flatMap((ingest) => ingest.ingest(args)),
    Effect.map((result) => ({ id: result.id, deduped: result.deduped, status: result.status }))
  );

/** Tool name -> runner. Unknown names are rejected by the dispatcher. */
export const TOOL_RUNNERS: Readonly<Record<string, ToolRunner>> = {
  bit_retrieve: retrieveRunner,
  bit_ingest: ingestRunner
};
