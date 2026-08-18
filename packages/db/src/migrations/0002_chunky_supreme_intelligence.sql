DROP INDEX "bit"."records_namespace_idx";--> statement-breakpoint
ALTER TABLE "bit"."records" ADD COLUMN "namespaces" text[] NOT NULL;--> statement-breakpoint
CREATE INDEX "records_namespaces_idx" ON "bit"."records" USING gin ("namespaces");--> statement-breakpoint
ALTER TABLE "bit"."records" DROP COLUMN "namespace";--> statement-breakpoint
ALTER TABLE "bit"."records" ADD CONSTRAINT "records_namespaces_nonempty_check" CHECK (array_length("bit"."records"."namespaces", 1) >= 1);