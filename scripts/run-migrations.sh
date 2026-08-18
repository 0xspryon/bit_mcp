#!/bin/sh
set -eu

max_attempts="${MIGRATION_MAX_ATTEMPTS:-20}"
retry_delay_seconds="${MIGRATION_RETRY_DELAY_SECONDS:-3}"
attempt=1

run_migrations() {
	printf 'Running bit db migrations\n'
	bun --filter @repo/db db:migrate
}

while [ "$attempt" -le "$max_attempts" ]; do
	if run_migrations; then
		printf 'Migrations completed successfully\n'
		exit 0
	fi

	if [ "$attempt" -eq "$max_attempts" ]; then
		printf 'Migration failed after %s attempts\n' "$attempt" >&2
		exit 1
	fi

	printf 'Migration attempt %s failed, retrying in %s seconds\n' "$attempt" "$retry_delay_seconds" >&2
	attempt=$((attempt + 1))
	sleep "$retry_delay_seconds"
done
