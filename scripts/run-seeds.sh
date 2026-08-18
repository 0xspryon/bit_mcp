#!/bin/sh
set -eu

max_attempts="${SEED_MAX_ATTEMPTS:-20}"
retry_delay_seconds="${SEED_RETRY_DELAY_SECONDS:-3}"
attempt=1

run_seeds() {
	printf 'Running bit db seeds\n'
	bun --filter @repo/seeder seed:run
}

while [ "$attempt" -le "$max_attempts" ]; do
	if run_seeds; then
		printf 'Seeds completed successfully\n'
		exit 0
	fi

	if [ "$attempt" -eq "$max_attempts" ]; then
		printf 'Seeding failed after %s attempts\n' "$attempt" >&2
		exit 1
	fi

	printf 'Seed attempt %s failed, retrying in %s seconds\n' "$attempt" "$retry_delay_seconds" >&2
	attempt=$((attempt + 1))
	sleep "$retry_delay_seconds"
done
