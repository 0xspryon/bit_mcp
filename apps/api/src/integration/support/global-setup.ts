import type { GlobalSetupContext } from 'vitest/node';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { GenericContainer, Wait, type StartedTestContainer } from 'testcontainers';
import { Client } from 'pg';
import { applyMigration } from './migrate';

/**
 * Vitest `globalSetup` for the integration suite. Runs ONCE in the main process
 * (never in a worker), so it is the right place to boot Docker containers.
 *
 * Responsibilities:
 *  1. Start a disposable `pgvector/pgvector:pg17` Postgres and apply the schema
 *     migration to it, then publish its URI to every worker via `provide`.
 *  2. Optionally resolve a TEI embedding + reranker endpoint (from env, or by
 *     spinning the CPU TEI image when `BIT_IT_START_TEI=1`). When neither is
 *     available the TEI-gated tests skip.
 *  3. Degrade gracefully: if Docker is unreachable, publish
 *     `dockerAvailable: false` (instead of throwing) so the whole integration
 *     suite SKIPS rather than hard-failing on a machine without a daemon.
 */

const PG_IMAGE = 'pgvector/pgvector:pg17';
const TEI_IMAGE = 'ghcr.io/huggingface/text-embeddings-inference:cpu-1.5';
const EMBED_MODEL = 'BAAI/bge-m3';
const RERANK_MODEL = 'BAAI/bge-reranker-v2-m3';

// Downloading + loading the TEI models can take minutes on first run.
const TEI_STARTUP_MS = 600_000;

let pgContainer: StartedPostgreSqlContainer | undefined;
let embedContainer: StartedTestContainer | undefined;
let rerankContainer: StartedTestContainer | undefined;

/** Start one TEI container for the given model, returning its base URL. */
const startTei = async (model: string): Promise<{ url: string; container: StartedTestContainer }> => {
  const container = await new GenericContainer(TEI_IMAGE)
    .withCommand(['--model-id', model, '--port', '80'])
    .withExposedPorts(80)
    .withWaitStrategy(Wait.forHttp('/health', 80))
    .withStartupTimeout(TEI_STARTUP_MS)
    .start();
  return { url: `http://${container.getHost()}:${container.getMappedPort(80)}`, container };
};

/** Resolve TEI endpoints: prefer env, then an opt-in container spin, else null. */
const resolveTei = async (): Promise<{
  embeddingEndpoint: string | null;
  rerankEndpoint: string | null;
}> => {
  const envEmbed = process.env.EMBEDDING_ENDPOINT;
  const envRerank = process.env.RERANK_ENDPOINT;
  if (envEmbed && envRerank) {
    return { embeddingEndpoint: envEmbed, rerankEndpoint: envRerank };
  }
  if (process.env.BIT_IT_START_TEI === '1') {
    const [embed, rerank] = await Promise.all([startTei(EMBED_MODEL), startTei(RERANK_MODEL)]);
    embedContainer = embed.container;
    rerankContainer = rerank.container;
    return { embeddingEndpoint: embed.url, rerankEndpoint: rerank.url };
  }
  return { embeddingEndpoint: null, rerankEndpoint: null };
};

export default async function setup({ provide }: GlobalSetupContext): Promise<() => Promise<void>> {
  try {
    pgContainer = await new PostgreSqlContainer(PG_IMAGE).start();
    const databaseUrl = pgContainer.getConnectionUri();

    // Apply the migration through a one-shot pg client.
    const client = new Client({ connectionString: databaseUrl });
    await client.connect();
    try {
      await applyMigration(client);
    } finally {
      await client.end();
    }

    const { embeddingEndpoint, rerankEndpoint } = await resolveTei();

    provide('dockerAvailable', true);
    provide('databaseUrl', databaseUrl);
    provide('embeddingEndpoint', embeddingEndpoint);
    provide('rerankEndpoint', rerankEndpoint);

    if (embeddingEndpoint === null) {
      console.warn(
        '[integration] No TEI endpoint (set EMBEDDING_ENDPOINT+RERANK_ENDPOINT or BIT_IT_START_TEI=1). Semantic/rerank tests will skip.'
      );
    }
  } catch (error) {
    console.warn(
      `[integration] Docker is unavailable — skipping the integration suite. Reason: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
    provide('dockerAvailable', false);
    provide('databaseUrl', '');
    provide('embeddingEndpoint', null);
    provide('rerankEndpoint', null);
  }

  return async () => {
    await Promise.allSettled([
      embedContainer?.stop(),
      rerankContainer?.stop(),
      pgContainer?.stop()
    ]);
  };
}
