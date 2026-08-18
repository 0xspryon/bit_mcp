/**
 * Authoring shape for a corpus record — the encoded input that
 * `IngestService.ingest` validates against the rag-core `RecordInput` schema.
 * Data modules under `data/` export `readonly CorpusRecord[]` arrays that the
 * corpus seeds ingest.
 */
export interface CorpusRecord {
  readonly namespaces: readonly string[];
  readonly title: string;
  readonly symptom: string;
  readonly procedure: string;
  readonly whenToUse?: string;
  readonly confirmationSignal?: string;
  readonly preconditions?: readonly string[];
  readonly appliesTo?: readonly string[];
  readonly cwe?: readonly number[];
  readonly vrt?: readonly string[];
  readonly chainsWith?: readonly string[];
  readonly qualityTier?: number;
  readonly sources?: ReadonlyArray<{
    readonly url: string;
    readonly title?: string;
    readonly tier?: number;
    readonly kind?: string;
  }>;
}
