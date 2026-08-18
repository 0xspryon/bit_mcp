/** Formatting for the console's technical timestamps. */

/** `2026-08-18 09:41Z` — the design's CREATED format. UTC so it reads the same
 * for everyone looking at the same account. */
export function formatStamp(value: string | Date | null | undefined): string {
	if (!value) return '—';
	const date = value instanceof Date ? value : new Date(value);
	if (Number.isNaN(date.getTime())) return '—';
	const pad = (n: number) => String(n).padStart(2, '0');
	return (
		`${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
		`${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}Z`
	);
}

/** `2026-09-30` — a bare date, for ban expiries. */
export function formatDate(value: string | Date | null | undefined): string {
	if (!value) return '—';
	const date = value instanceof Date ? value : new Date(value);
	if (Number.isNaN(date.getTime())) return '—';
	const pad = (n: number) => String(n).padStart(2, '0');
	return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

/** `4 min ago` — the design's LAST_USED format. Coarse on purpose: this answers
 * "is anything using this key", not "exactly when". */
export function formatRelative(value: string | Date | null | undefined, now = Date.now()): string {
	if (!value) return 'never';
	const date = value instanceof Date ? value : new Date(value);
	if (Number.isNaN(date.getTime())) return 'never';

	const seconds = Math.round((now - date.getTime()) / 1000);
	// A clock skew between server and browser can put a timestamp slightly in
	// the future; read that as "just now" rather than a negative age.
	if (seconds < 60) return 'just now';
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes} min ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours} hr ago`;
	const days = Math.floor(hours / 24);
	if (days < 30) return `${days} d ago`;
	return formatDate(date);
}
