import { describe, expect, it } from 'vitest';
import { reciprocalRankFusion } from './rrf';

interface Item {
  id: string;
}
const item = (id: string): Item => ({ id });
const idOf = (i: Item) => i.id;

describe('reciprocalRankFusion', () => {
  it('produces the expected fused order and scores for two ranked lists', () => {
    const listA = [item('a'), item('b'), item('c')]; // ranks 1,2,3
    const listB = [item('b'), item('c'), item('d')]; // ranks 1,2,3

    const fused = reciprocalRankFusion([listA, listB], idOf);
    expect(fused.map((f) => f.item.id)).toEqual(['b', 'c', 'a', 'd']);

    const k = 60;
    const byId = new Map(fused.map((f) => [f.item.id, f.score]));
    expect(byId.get('b')).toBeCloseTo(1 / (k + 1) + 1 / (k + 2), 10);
    expect(byId.get('c')).toBeCloseTo(1 / (k + 2) + 1 / (k + 3), 10);
    expect(byId.get('a')).toBeCloseTo(1 / (k + 1), 10);
    expect(byId.get('d')).toBeCloseTo(1 / (k + 3), 10);
  });

  it('dedupes by id, keeping the first-seen item object', () => {
    const first = item('x');
    const second = item('x');
    const fused = reciprocalRankFusion([[first], [second]], idOf);
    expect(fused).toHaveLength(1);
    expect(fused[0]?.item).toBe(first);
  });

  it('breaks score ties by id ascending for determinism', () => {
    const fused = reciprocalRankFusion([[item('b')], [item('a')]], idOf);
    expect(fused.map((f) => f.item.id)).toEqual(['a', 'b']);
  });

  it('honours a custom k', () => {
    const fused = reciprocalRankFusion([[item('a')]], idOf, 1);
    expect(fused[0]?.score).toBeCloseTo(1 / (1 + 1), 10);
  });
});
