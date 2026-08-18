/**
 * The admin user directory and the actions on it.
 *
 * The listing comes from our API (better-auth's `list-users` cannot join the
 * session/key aggregates the screen shows); ban, unban, impersonate, stop and
 * session revocation go straight to the better-auth admin plugin under
 * /api/auth/admin/*.
 */
import { apiClient, call, type ApiResult, type ErrorsOf, type UnexpectedError } from './client';

const listEndpoint = apiClient.admin.users.$get;

export type AdminUserList = Extract<
	Awaited<ReturnType<typeof listAdminUsers>>,
	{ ok: true }
>['data'];
export type AdminUser = AdminUserList['users'][number];
export type AdminUserListError = ErrorsOf<typeof listEndpoint>;

export async function listAdminUsers() {
	return call(listEndpoint());
}

/** better-auth admin endpoints answer with a bare JSON body (no `error`
 * envelope); failures carry `{ code?, message? }`. Lift both into ApiResult. */
async function authAdminPost<TData>(
	path: string,
	body: Record<string, unknown>
): Promise<ApiResult<TData, UnexpectedError>> {
	let res: Response;
	try {
		res = await fetch(`/api/auth/admin/${path}`, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(body)
		});
	} catch {
		return {
			ok: false,
			error: { code: 'UNEXPECTED', message: 'The request could not be sent.', status: null }
		};
	}
	let parsed: unknown = null;
	try {
		parsed = await res.json();
	} catch {
		// non-JSON body — handled below
	}
	if (!res.ok) {
		const message =
			typeof parsed === 'object' && parsed !== null && 'message' in parsed
				? String((parsed as { message: unknown }).message)
				: 'The server sent an unexpected response.';
		return { ok: false, error: { code: 'UNEXPECTED', message, status: res.status } };
	}
	return { ok: true, data: parsed as TData };
}

/**
 * Ban an account. A blank `banExpiresIn` means indefinite, matching the
 * dialog's "blank means indefinite" hint. better-auth revokes the account's
 * sessions as part of the ban, and its api keys stop authenticating with it.
 */
export async function banUser(userId: string, banReason?: string, banExpiresIn?: number) {
	return authAdminPost<{ user: unknown }>('ban-user', {
		userId,
		...(banReason ? { banReason } : {}),
		...(banExpiresIn !== undefined ? { banExpiresIn } : {})
	});
}

export async function unbanUser(userId: string) {
	return authAdminPost<{ user: unknown }>('unban-user', { userId });
}

export async function setRole(userId: string, role: 'admin' | 'user') {
	return authAdminPost<{ user: unknown }>('set-role', { userId, role });
}

/** Revoke every session an account holds, without banning it. */
export async function revokeUserSessions(userId: string) {
	return authAdminPost<{ success?: boolean }>('revoke-user-sessions', { userId });
}

/** Swaps the admin's session for one as the target user; the admin session is
 * parked in better-auth's admin_session cookie until `stopImpersonating`. */
export async function impersonateUser(userId: string) {
	return authAdminPost<{ session: unknown; user: unknown }>('impersonate-user', { userId });
}

/** Ends impersonation and restores the parked admin session. */
export async function stopImpersonating() {
	return authAdminPost<{ session: unknown }>('stop-impersonating', {});
}

/**
 * Resolve a `yyyy-mm-dd` expiry into better-auth's `banExpiresIn` (seconds).
 *
 * A blank date genuinely means indefinite. A date that is today or already
 * past does NOT — collapsing it to `undefined` would silently turn "ban until
 * the end of today" into a PERMANENT ban, which is the opposite of what the
 * admin asked for. Those return an error instead so the dialog can say so.
 *
 * The date is anchored to the END of the chosen day in UTC, so picking today
 * means "until today is over" rather than "since midnight, i.e. the past".
 */
export type BanExpiry =
	| { ok: true; seconds: number | undefined }
	| { ok: false; message: string };

export function resolveBanExpiry(date: string, now = Date.now()): BanExpiry {
	if (!date) return { ok: true, seconds: undefined };
	const endOfDay = Date.parse(`${date}T23:59:59Z`);
	if (Number.isNaN(endOfDay)) {
		return { ok: false, message: 'That expiry date could not be read. Use YYYY-MM-DD.' };
	}
	const seconds = Math.floor((endOfDay - now) / 1000);
	if (seconds <= 0) {
		return {
			ok: false,
			message: 'That expiry is already in the past. Pick a later date, or leave it blank for an indefinite ban.'
		};
	}
	return { ok: true, seconds };
}
