-- bit's contract is one usable API key per account, which nothing enforced
-- before: the `/api-key/create` before-hook is a check-then-insert, so two
-- concurrent creates can both succeed. Because the rate limit is stored and
-- counted PER KEY ROW, a surplus key multiplies an account's allowance — and
-- the console only ever displays one key, so the extra would be invisible
-- while still authenticating.
--
-- Disable any pre-existing surplus first, newest kept, or the unique index
-- below cannot be created on a populated database. Rows are retained (not
-- deleted) so the history stays auditable; a disabled key stops authenticating,
-- which is what the one-key rule implies anyway.
UPDATE "bit"."apikey" AS a
SET "enabled" = false
WHERE a."enabled"
  AND EXISTS (
    SELECT 1 FROM "bit"."apikey" AS newer
    WHERE newer."reference_id" = a."reference_id"
      AND newer."enabled"
      AND (newer."created_at", newer."id") > (a."created_at", a."id")
  );--> statement-breakpoint
CREATE UNIQUE INDEX "apikey_one_enabled_per_reference_idx" ON "bit"."apikey" USING btree ("reference_id") WHERE "bit"."apikey"."enabled";
