import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { Client } from 'pg';

/**
 * Apply the drizzle-generated schema migrations to a fresh database.
 *
 * Every migration under `packages/db/src/migrations/<tag>.sql` is a file whose
 * statements are separated by drizzle's `--> statement-breakpoint` markers. We
 * apply the migrations in the order recorded in `meta/_journal.json` (0000,
 * 0001, …) so the testcontainers schema always matches the real migration
 * chain — not just the initial `0000` snapshot. The first statement of `0000`
 * is `CREATE EXTENSION IF NOT EXISTS vector`, which requires the pgvector image
 * (`pgvector/pgvector:pg17`) and a superuser — the testcontainers Postgres
 * default user is a superuser, so it succeeds.
 */

const STATEMENT_BREAKPOINT = '--> statement-breakpoint';

/** Absolute path to `packages/db/src/migrations`, resolved from this file. */
const migrationsDir = (): string => {
  const here = dirname(fileURLToPath(import.meta.url));
  // here = <repo>/apps/api/src/integration/support
  return join(here, '..', '..', '..', '..', '..', 'packages', 'db', 'src', 'migrations');
};

interface JournalEntry {
  readonly idx: number;
  readonly tag: string;
}

/** Ordered migration tags, read from drizzle's `meta/_journal.json`. */
const orderedMigrationTags = (): string[] => {
  const journalPath = join(migrationsDir(), 'meta', '_journal.json');
  const journal = JSON.parse(readFileSync(journalPath, 'utf8')) as {
    entries?: ReadonlyArray<JournalEntry>;
  };
  const entries = [...(journal.entries ?? [])].sort((a, b) => a.idx - b.idx);
  if (entries.length === 0) {
    throw new Error(`No migration entries found in ${journalPath}`);
  }
  return entries.map((entry) => entry.tag);
};

/** Read the ordered list of SQL statements across ALL migrations in journal
 * order (0000, 0001, …), so the applied schema matches the full chain. */
export const readMigrationStatements = (): string[] => {
  const dir = migrationsDir();
  return orderedMigrationTags().flatMap((tag) =>
    readFileSync(join(dir, `${tag}.sql`), 'utf8')
      .split(STATEMENT_BREAKPOINT)
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0)
  );
};

/** Execute the migration statements sequentially on an open `pg` client. */
export const applyMigration = async (client: Client): Promise<void> => {
  for (const statement of readMigrationStatements()) {
    await client.query(statement);
  }
};
