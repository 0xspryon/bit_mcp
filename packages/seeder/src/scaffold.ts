// Pure helpers behind `seed:new` (src/new.ts) — kept side-effect free so they
// are unit-testable.

const IMPORTS_MARKER = '// <seed:new-imports>';
const ENTRIES_MARKER = '// <seed:new-entries>';

/** "Default document-types" -> "default_document_types"; throws on garbage. */
export const normalizeDescription = (raw: string): string => {
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
    .replace(/_+/g, '_');
  if (!/^[a-z][a-z0-9_]*$/.test(normalized)) {
    throw new Error(
      `Invalid seed description "${raw}" — use letters, digits, spaces, "-" or "_", starting with a letter`
    );
  }
  return normalized;
};

/** Next NNNN prefix given existing seed file names (e.g. "0000_admin_user.ts"). */
export const nextSeedNumber = (existingFileNames: ReadonlyArray<string>): string => {
  const numbers = existingFileNames
    .map((name) => /^(\d{4})_/.exec(name)?.[1])
    .filter((prefix): prefix is string => prefix !== undefined)
    .map(Number);
  const next = numbers.length === 0 ? 0 : Math.max(...numbers) + 1;
  return String(next).padStart(4, '0');
};

/** "default_document_types" -> "defaultDocumentTypes" */
export const toIdentifier = (description: string): string =>
  description.replace(/_([a-z0-9])/g, (_, char: string) => char.toUpperCase());

export const seedFileTemplate = (seedName: string, identifier: string): string =>
  `import type { Seed } from '../types';

export const ${identifier}: Seed = {
  name: '${seedName}',
  run: async (db) => {
    // TODO: implement. Runs once per database inside a transaction; make the
    // writes safe to replay on a fresh database (e.g. onConflictDo*).
    void db;
    throw new Error('Seed ${seedName} is not implemented yet');
  }
};
`;

/** Registers the new seed in seeds/index.ts via the two marker comments. */
export const registerInIndex = (
  indexSource: string,
  identifier: string,
  fileBaseName: string
): string => {
  if (!indexSource.includes(IMPORTS_MARKER) || !indexSource.includes(ENTRIES_MARKER)) {
    throw new Error('seeds/index.ts is missing the seed:new marker comments');
  }
  return indexSource
    .replace(IMPORTS_MARKER, `import { ${identifier} } from './${fileBaseName}';\n${IMPORTS_MARKER}`)
    .replace(ENTRIES_MARKER, `${identifier},\n  ${ENTRIES_MARKER}`);
};
