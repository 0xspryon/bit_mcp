import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { createKeyHandler, refreshKeyHandler, revokeKeyHandler } from './key.handler';

/**
 * The caller's own API key: mint, revoke, and the two-in-one rotate.
 *
 * All three are ours rather than better-auth's `/api-key/*` routes because
 * every one of them needs something the plugin cannot do on a request carrying
 * the caller's headers — set the tier from the owner's stored role, enforce one
 * key per account on the server-side mint, or sequence revoke-then-mint so the
 * account is never left holding two live credentials.
 */
export const meKeyRoute = new Hono<HonoEnv>()
  .post('/', (c) => createKeyHandler(c))
  .post('/revoke', (c) => revokeKeyHandler(c))
  .post('/refresh', (c) => refreshKeyHandler(c));
