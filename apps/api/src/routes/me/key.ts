import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { refreshKeyHandler } from './key.handler';

export const meKeyRoute = new Hono<HonoEnv>().post('/refresh', (c) => refreshKeyHandler(c));
