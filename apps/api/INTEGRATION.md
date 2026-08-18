# Integration & e2e tests

The integration suite exercises the **real** DB path (Drizzle → Postgres + pgvector)
and the HTTP / MCP doorways end-to-end. It is kept separate from the fast unit
suite so `bun run test` never needs Docker.

- **Unit** (`bun run test`, `vitest.config.ts`): matches `src/**/*.unit.test.ts`,
  all test doubles, no Docker.
- **Integration** (`bun run test:integration`, `vitest.integration.config.ts`):
  matches `src/**/*.integration.test.ts`, boots a disposable Postgres via
  testcontainers.

## Prerequisites

- A running **Docker daemon** (testcontainers uses it to start
  `pgvector/pgvector:pg17`).
- Optional, only for the TEI-gated tests: a reachable
  [text-embeddings-inference](https://github.com/huggingface/text-embeddings-inference)
  embedder **and** reranker.

The migration (`packages/db/src/migrations/0000_*.sql`, which begins with
`CREATE EXTENSION vector;`) is applied to the fresh container at suite start by a
one-shot `pg` client that splits the file on drizzle's `--> statement-breakpoint`
markers.

## Running

```bash
# All integration + e2e tests (DB-only tests run; TEI-gated tests skip).
bun run --filter api test:integration
```

If Docker is not running the whole suite **skips** (it does not fail): the
`globalSetup` catches the container-start error, logs a clear message, and every
`describe` is `skipIf(!dockerAvailable)`.

### Enabling the TEI-gated tests

Two tests need real vectors: **semantic recall** and **rerank-first**. Provide a
TEI embedder + reranker one of two ways:

```bash
# (a) Point at already-running TEI servers:
EMBEDDING_ENDPOINT=http://localhost:8085 \
RERANK_ENDPOINT=http://localhost:8086 \
bun run --filter api test:integration

# (b) Let testcontainers spin the CPU TEI image (slow first run — downloads
#     BAAI/bge-m3 + BAAI/bge-reranker-v2-m3):
BIT_IT_START_TEI=1 bun run --filter api test:integration
```

Without either, those two tests skip with the rest of the DB tests still running.

## recall@k harness

`src/eval/recall-at-k.ts` seeds a ~20-record corpus into namespace `eval`,
promotes it, and prints `recall@5` over 20 `(query → expected id)` pairs through
the live embed + rerank pipeline. It needs **Postgres AND TEI** and re-seeds
(deletes) every `namespace = 'eval'` row — point it at a scratch DB.

```bash
DATABASE_URL=postgres://bit:bit@localhost:5432/bit_dev \
EMBEDDING_ENDPOINT=http://localhost:8085 \
RERANK_ENDPOINT=http://localhost:8086 \
bun run --filter api eval:recall
```

## What each test covers

`src/integration/rag.integration.test.ts` — the 8 required cases:

| # | Case | Embedder |
|---|------|----------|
| 1 | ingest → promote → retrieve roundtrip | fake |
| 2 | exact-token lexical recall (`X-Forwarded-Host` in `procedure`) | fake |
| 3 | semantic recall (paraphrase → dense leg) | **live TEI** |
| 4 | namespace isolation (A never returns B) | fake |
| 5 | rerank-first (most relevant ranks #1) | **live TEI** |
| 6 | idempotent ingest (one row, `deduped:true`) | fake |
| 7 | staging invisibility | fake |
| 8 | transaction safety (source-FK violation rolls back) | fake |

`src/integration/mcp.integration.test.ts` — MCP JSON-RPC doorway over
`POST /api/v1/mcp`: `server/discover`, `tools/list` (cache hints + deterministic order),
`bit_retrieve` `tools/call` (complete envelope, `kind:'methodology'` chunks),
statelessness.

`src/integration/http.integration.test.ts` — `/api/v1/health`, `/api/v1/retrieve`
(happy + 400), `/api/v1/ingest` (happy + dedup).

### Auth in the e2e tests

The HTTP/MCP e2e tests use the **test `AuthService`** double (granting
`record:['read','ingest']`) plus fake User/Session repos — no real better-auth
session tokens are minted. The **retrieve/ingest DB behaviour is fully real**:
records are embedded, stored, promoted, and read back out of pgvector + FTS.
