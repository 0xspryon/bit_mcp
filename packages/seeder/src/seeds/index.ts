import type { Seed } from '../types';
import { corpusSeed } from './0001_corpus';
import { authzPaywallSeed } from './0002_authz_paywall';
// <seed:new-imports> — `bun run seed:new` inserts above; keep this marker.

/**
 * Append-only, ordered registry. Scaffold a new seed with
 * `bun run seed:new <description>` — it creates `src/seeds/NNNN_description.ts`
 * and registers it here. Applied seeds are tracked per-database and never
 * re-run, so never rename or delete one that has run anywhere.
 *
 * Note: the former `0000_admin_user` seed was removed — the admin is now
 * bootstrapped by the auth layer's first-user-create hook (the first account to
 * sign in becomes admin), so a seeded admin would consume that slot.
 */
export const seeds: ReadonlyArray<Seed> = [
  corpusSeed,
  authzPaywallSeed
  // <seed:new-entries> — `bun run seed:new` inserts above; keep this marker.
];
