import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { retrieveHandler } from './retrieve.handler';

export const retrieveRoute = new Hono<HonoEnv>().post('/retrieve', (c) => retrieveHandler(c));
