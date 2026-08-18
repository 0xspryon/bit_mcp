import type { Seed } from './types';

/**
 * The seeds that still need to run, in registry order. Throws on duplicate
 * names — a renamed or copy-pasted seed would otherwise silently re-run.
 */
export const selectPending = (
  seeds: ReadonlyArray<Seed>,
  applied: ReadonlySet<string>
): ReadonlyArray<Seed> => {
  const names = new Set<string>();
  for (const seed of seeds) {
    if (names.has(seed.name)) {
      throw new Error(`Duplicate seed name: ${seed.name}`);
    }
    names.add(seed.name);
  }
  return seeds.filter((seed) => !applied.has(seed.name));
};
