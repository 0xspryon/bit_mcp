import { Schema } from 'effect';
import { validateInput } from '../../lib/schema-validator';

/** The lifecycle statuses an admin can set a record to. Retiring a record is a
 * soft delete (`deleted_at`), not a status. */
export const RECORD_STATUSES = ['staging', 'active'] as const;
const StatusLiteral = Schema.Literal(...RECORD_STATUSES);

/** Body of `PATCH /records/:id/status`. */
export const StatusUpdateBody = Schema.Struct({ status: StatusLiteral });
export type StatusUpdateBody = Schema.Schema.Type<typeof StatusUpdateBody>;

export const validateStatusUpdate = validateInput(StatusUpdateBody, {
  code: 'INVALID_STATUS_UPDATE' as const,
  message: 'Invalid record status update.'
});

/** Query of `GET /records` (admin list-by-status). Defaults to staging. */
export const ListQuery = Schema.Struct({
  status: Schema.optionalWith(StatusLiteral, { default: () => 'staging' as const }),
  limit: Schema.optionalWith(Schema.NumberFromString.pipe(Schema.int(), Schema.between(1, 100)), {
    default: () => 50
  })
});
export type ListQuery = Schema.Schema.Type<typeof ListQuery>;

export const validateListQuery = validateInput(ListQuery, {
  code: 'INVALID_LIST_QUERY' as const,
  message: 'Invalid record list query.'
});
