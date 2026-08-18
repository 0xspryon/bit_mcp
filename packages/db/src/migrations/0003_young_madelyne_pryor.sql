ALTER TABLE "bit"."records" DROP CONSTRAINT "records_category_check";--> statement-breakpoint
ALTER TABLE "bit"."records" DROP CONSTRAINT "records_status_check";--> statement-breakpoint
ALTER TABLE "bit"."records" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "bit"."records" DROP COLUMN "category";--> statement-breakpoint
--> `deprecated` is no longer a status. A deprecated record is exactly a record
--> that retrieval must not see but a curator can still fetch by id, which is
--> what the new soft delete expresses — so carry those rows over to
--> `deleted_at` instead of dropping them. Must run BEFORE the narrowed check
--> constraint is added, or that constraint fails on any populated database.
UPDATE "bit"."records" SET "status" = 'staging', "deleted_at" = now() WHERE "status" = 'deprecated';--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_status_check" CHECK ("bit"."records"."status" in ('staging', 'active'));