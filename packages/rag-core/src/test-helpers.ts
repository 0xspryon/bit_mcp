import type {
  Filter,
  RecordInsert,
  RecordRow,
  RecordSourceRow,
  RecordSourceUpsert
} from '@repo/db';
import { RecordRepo, SourceRepo } from '@repo/db';
import { Cause, Context, Effect, Exit, Layer, Option } from 'effect';

/**
 * Shared in-memory fakes for unit tests. Not part of the public barrel — these
 * exist only to build `Layer.mergeAll` stacks for `Effect.provide`.
 */

let recordSeq = 0;

/** Build a full `RecordRow` with sensible defaults; override any field. */
export const makeRecord = (overrides: Partial<RecordRow> = {}): RecordRow => {
  recordSeq += 1;
  const id = overrides.id ?? `rec-${recordSeq}`;
  return {
    id,
    namespaces: ['acme'],
    title: `Record ${id}`,
    symptom: 'a symptom',
    whenToUse: null,
    procedure: 'a procedure',
    confirmationSignal: null,
    preconditions: [],
    appliesTo: [],
    cwe: [],
    vrt: [],
    chainsWith: [],
    qualityTier: 3,
    status: 'active',
    version: 1,
    contentHash: `hash-${id}`,
    embedding: [],
    fts: null,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    deletedAt: null,
    ...overrides
  } as RecordRow;
};

/** Records for a captured RecordRepo interaction (for spies/assertions). */
export interface RecordRepoSpy {
  readonly inserts: Array<{ row: RecordInsert; sources: readonly RecordSourceUpsert[] }>;
  readonly nearestFilters: Array<Filter>;
  readonly lexicalFilters: Array<Filter>;
}

export interface RecordRepoTestOptions {
  readonly byHash?: ReadonlyMap<string, RecordRow>;
  readonly nearest?: readonly RecordRow[];
  readonly lexical?: readonly RecordRow[];
  readonly sources?: ReadonlyMap<string, RecordSourceRow[]>;
  readonly insertId?: string;
  /** Simulate a dedup conflict on insert (inserted:false). */
  readonly insertConflict?: boolean;
  readonly insertStatus?: string;
}

/** Build a fake `RecordRepo` layer plus a `spy` capturing calls. */
export const makeRecordRepoFake = (
  options: RecordRepoTestOptions = {}
): { layer: Layer.Layer<RecordRepo>; spy: RecordRepoSpy } => {
  const spy: RecordRepoSpy = {
    inserts: [],
    nearestFilters: [],
    lexicalFilters: []
  };
  const impl: Context.Tag.Service<RecordRepo> = {
    insert: (row, sources) => {
      spy.inserts.push({ row, sources });
      return Effect.succeed({
        id: options.insertId ?? 'new-id',
        inserted: options.insertConflict !== true,
        status: options.insertStatus ?? 'staging'
      });
    },
    findByHash: (hash) => Effect.succeed(Option.fromNullable(options.byHash?.get(hash))),
    addNamespaces: (id, namespaces) => {
      const existing = options.byHash?.get(id);
      if (!existing) return Effect.succeed(Option.none());
      const merged = [...new Set([...existing.namespaces, ...namespaces])];
      return Effect.succeed(Option.some({ ...existing, namespaces: merged }));
    },
    nearest: (_vec, f, _k) => {
      spy.nearestFilters.push(f);
      return Effect.succeed([...(options.nearest ?? [])]);
    },
    lexical: (_query, f, _k) => {
      spy.lexicalFilters.push(f);
      return Effect.succeed([...(options.lexical ?? [])]);
    },
    getById: (id) =>
      Effect.succeed(Option.fromNullable([...(options.nearest ?? [])].find((r) => r.id === id))),
    sourcesFor: (_ids) =>
      Effect.succeed(options.sources ?? new Map<string, RecordSourceRow[]>()),
    updateStatus: (id, status) => Effect.succeed(Option.some(makeRecord({ id, status }))),
    listByStatus: (_status, _limit) => Effect.succeed([])
  };
  return { layer: Layer.succeed(RecordRepo, impl), spy };
};

export interface SourceRepoSpy {
  readonly upserts: Array<{ url: string; title: string | null; tier: number; kind: string | null }>;
}

/** Build a fake `SourceRepo` layer that returns `source:<url>` ids. */
export const makeSourceRepoFake = (): { layer: Layer.Layer<SourceRepo>; spy: SourceRepoSpy } => {
  const spy: SourceRepoSpy = { upserts: [] };
  const impl: Context.Tag.Service<SourceRepo> = {
    upsertByUrl: (url, title, qualityTier, kind) => {
      spy.upserts.push({ url, title, tier: qualityTier, kind });
      return Effect.succeed(`source:${url}`);
    },
    getById: () => Effect.succeed(Option.none())
  };
  return { layer: Layer.succeed(SourceRepo, impl), spy };
};

/** Extract the typed failure from a failed `Exit`, or throw. */
export const getFailure = <E>(exit: Exit.Exit<unknown, E>): E => {
  if (!Exit.isFailure(exit)) throw new Error('Expected effect to fail');
  const failure = Cause.failureOption(exit.cause);
  if (Option.isNone(failure)) throw new Error('Expected a typed failure');
  return failure.value;
};
