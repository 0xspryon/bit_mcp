import { hc } from 'hono/client';
import type { appRoutes } from './routes/index';

/** Where index.ts mounts appRoutes and what RPC clients use as their base URL. */
export const API_BASE_PATH = '/api/v1';

// Instantiated once so `bun run build` materializes the fully-computed client
// type into dist/hc.d.ts. Consumers import the pre-built types instead of
// re-inferring them from the API source graph on every typecheck.
//
// Typed on the appRoutes sub-app (paths without the /api/v1 prefix), so
// clients pass API_BASE_PATH as the base URL and skip the `.api.v1` chain.
const client = hc<typeof appRoutes>('');
export type Client = typeof client;

export const hcWithType = (...args: Parameters<typeof hc>): Client => hc<typeof appRoutes>(...args);
