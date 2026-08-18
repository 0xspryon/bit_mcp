import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { listAdminUsersHandler } from './users.handler';

export const adminUsersRoute = new Hono<HonoEnv>().get('/', (c) => listAdminUsersHandler(c));
