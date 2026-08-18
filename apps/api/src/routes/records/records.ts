import { Hono } from 'hono';
import type { HonoEnv } from '../../app-env';
import { listRecordsHandler, recordByIdHandler, updateRecordStatusHandler } from './records.handler';

export const recordsRoute = new Hono<HonoEnv>()
  // Admin list-by-status (review queue), defaults to staging.
  .get('/records', (c) => listRecordsHandler(c))
  .get('/records/:id', (c) => recordByIdHandler(c))
  // Admin curation: promote/demote a record between staging and active.
  .patch('/records/:id/status', (c) => updateRecordStatusHandler(c));
