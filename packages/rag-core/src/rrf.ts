/**
 * Reciprocal Rank Fusion (RRF).
 *
 * Fuses several independently-ranked lists (e.g. dense-vector and lexical
 * results) into one ordering without needing comparable raw scores. For each
 * list, the first element has rank 1; a document's fused score is the sum over
 * all lists in which it appears of `1 / (k + rank)`.
 *
 * Pure and deterministic: dedupes by id (keeping the first-seen item object)
 * and breaks score ties by id ascending so the output order is reproducible.
 */
export const reciprocalRankFusion = <T>(
  lists: ReadonlyArray<ReadonlyArray<T>>,
  idOf: (t: T) => string,
  k = 60
): Array<{ item: T; score: number }> => {
  const scores = new Map<string, number>();
  const items = new Map<string, T>();

  for (const list of lists) {
    for (let i = 0; i < list.length; i++) {
      const entry = list[i];
      if (entry === undefined) continue;
      const id = idOf(entry);
      const rank = i + 1;
      scores.set(id, (scores.get(id) ?? 0) + 1 / (k + rank));
      if (!items.has(id)) {
        items.set(id, entry);
      }
    }
  }

  return [...items.entries()]
    .map(([id, item]) => ({ id, item, score: scores.get(id) ?? 0 }))
    .sort((a, b) => (b.score !== a.score ? b.score - a.score : a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map(({ item, score }) => ({ item, score }));
};
