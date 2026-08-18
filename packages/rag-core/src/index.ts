// Schemas, derived types, tagged parse errors, decode helpers.
export {
  Chunk,
  ChunkSource,
  decodeRecordInput,
  decodeRetrieveQuery,
  RecordInput,
  RecordInputParseError,
  RetrievalDiagnostics,
  RetrievalResult,
  RetrieveFilters,
  RetrieveQuery,
  RetrieveQueryParseError,
  SourceInput,
  type ValidationIssue
} from './schema';

// Pure helpers.
export { contentHash, normalize } from './content-hash';
export { reciprocalRankFusion } from './rrf';

// Embedding service.
export {
  assertEmbeddingDim,
  EmbeddingService,
  EmbeddingServiceLive,
  EmbedError,
  makeEmbeddingServiceTest
} from './embedding';

// Rerank service.
export {
  makeRerankServiceTest,
  RerankError,
  RerankService,
  RerankServiceLive,
  type Scored
} from './rerank';

// Ingest service (write path).
export {
  IngestRepoError,
  IngestService,
  IngestServiceLive,
  makeIngestServiceTest,
  type IngestError,
  type IngestResult
} from './ingest';

// Retriever service (read path).
export {
  makeRetrieverServiceTest,
  RetrievalRepoError,
  RetrieverService,
  RetrieverServiceLive,
  type RetrievalError
} from './retriever';
