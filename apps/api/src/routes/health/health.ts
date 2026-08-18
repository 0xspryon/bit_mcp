import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { healthHandler } from './health.handler';

export const healthRoute = new Hono<HonoEnv>().get('/health', (c) => healthHandler(c));
