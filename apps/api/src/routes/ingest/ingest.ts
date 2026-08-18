import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { ingestHandler } from './ingest.handler';

export const ingestRoute = new Hono<HonoEnv>().post('/ingest', (c) => ingestHandler(c));
