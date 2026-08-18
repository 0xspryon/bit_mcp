/**
 * The record body is validated by `IngestService.ingest` itself (Effect Schema
 * → `RecordInputParseError`); the only thing the route validates up front is
 * that the request body is JSON at all. This config labels that parse failure.
 */
export const ingestJsonError = {
  code: 'INVALID_INGEST_INPUT',
  message: 'Ingest input contains invalid or unsupported fields.'
} as const;
