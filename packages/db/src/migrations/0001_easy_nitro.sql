ALTER TABLE "bit"."records" ADD CONSTRAINT "records_status_check" CHECK ("bit"."records"."status" in ('staging', 'active', 'deprecated'));--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_category_check" CHECK ("bit"."records"."category" in ('injection', 'authz', 'client-side', 'logic', 'infra', 'disclosure'));--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_quality_tier_check" CHECK ("bit"."records"."quality_tier" between 1 and 5);--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_version_check" CHECK ("bit"."records"."version" >= 1);--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_cwe_range_check" CHECK (1 <= all("bit"."records"."cwe") and 2000 >= all("bit"."records"."cwe"));--> statement-breakpoint
ALTER TABLE "bit"."sources" ADD CONSTRAINT "sources_quality_tier_check" CHECK ("bit"."sources"."quality_tier" between 1 and 5);