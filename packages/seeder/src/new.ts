// Scaffolds a seed file and registers it: `bun run seed:new <description>`
// e.g. `bun run seed:new default document types` -> src/seeds/0002_default_document_types.ts
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  nextSeedNumber,
  normalizeDescription,
  registerInIndex,
  seedFileTemplate,
  toIdentifier
} from './scaffold';

const seedsDir = fileURLToPath(new URL('./seeds', import.meta.url));
const indexPath = `${seedsDir}/index.ts`;

const rawDescription = process.argv.slice(2).join(' ');
if (!rawDescription.trim()) {
  console.error(
    'Usage: bun run seed:new <description>   e.g. bun run seed:new default document types'
  );
  process.exit(1);
}

const description = normalizeDescription(rawDescription);
const number = nextSeedNumber(readdirSync(seedsDir));
const fileBaseName = `${number}_${description}`;
const seedName = fileBaseName;
const identifier = toIdentifier(description);
const filePath = `${seedsDir}/${fileBaseName}.ts`;

writeFileSync(filePath, seedFileTemplate(seedName, identifier), { flag: 'wx' });
writeFileSync(indexPath, registerInIndex(readFileSync(indexPath, 'utf8'), identifier, fileBaseName));

console.log(`Created src/seeds/${fileBaseName}.ts and registered it in src/seeds/index.ts`);
console.log(`Implement its run(db) — it throws until you do, so it can't be applied by accident.`);
