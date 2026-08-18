/**
 * Client session store. The better-auth cookie is the source of truth;
 * `fetchSession()` reads it via /api/auth/get-session and caches the result in
 * localStorage so `getSession()` stays synchronous for guards and UI.
 *
 * Note this deliberately caches an IDENTITY, never an authorization: every
 * privileged call is still gated server-side. A tampered cache can only make
 * the UI draw the wrong chrome, never grant access.
 */
import { browser } from '$app/environment';

/** Roles a bit session can carry — mirrors `roles` in the API's auth-roles.ts. */
export type SessionRole = 'admin' | 'user';

export interface Session {
	userId: string;
	/** Discord username, stored on `user.name` by the API's mapProfileToUser. */
	name: string;
	email: string;
	role: SessionRole;
	/** Admin user id driving this session, when it is an impersonation. */
	impersonatedBy: string | null;
	/** ISO expiry of the better-auth session — the impersonation countdown. */
	sessionExpiresAt: string | null;
}

const SESSION_KEY = 'bit:session';

/**
 * The live session, shared by every component that needs it.
 *
 * A single reactive holder rather than per-component state: impersonation both
 * starts (from /admin/users) and stops (from the banner) mid-session, and the
 * root layout has to notice either without polling. Every `fetchSession()`
 * writes here, so a component only ever reads.
 */
export const sessionStore = $state<{ current: Session | null; loaded: boolean }>({
	current: null,
	loaded: false
});

const isSessionRole = (value: unknown): value is SessionRole =>
	value === 'admin' || value === 'user';

/**
 * Ask the API who is signed in and refresh the local cache. Returns null — and
 * clears the cache — when there is no session.
 *
 * An unrecognised or absent role falls back to `user`, never `admin`: an
 * unknown value must not be able to draw admin chrome.
 */
export async function fetchSession(): Promise<Session | null> {
	if (!browser) return null;
	let res: Response;
	try {
		res = await fetch('/api/auth/get-session', { credentials: 'same-origin' });
	} catch {
		// Network hiccup: keep whatever we knew last rather than signing out.
		return publish(getSession());
	}
	if (!res.ok) return publish(getSession());

	let body: {
		user?: { id?: string; name?: string; email?: string; role?: string | null } | null;
		session?: { impersonatedBy?: string | null; expiresAt?: string | null } | null;
	} | null = null;
	try {
		body = await res.json();
	} catch {
		return publish(getSession());
	}

	const userId = body?.user?.id;
	if (!userId) {
		endSession();
		return publish(null);
	}
	const session: Session = {
		userId,
		name: body?.user?.name ?? '',
		email: body?.user?.email ?? '',
		role: isSessionRole(body?.user?.role) ? body.user.role : 'user',
		impersonatedBy: body?.session?.impersonatedBy ?? null,
		sessionExpiresAt: body?.session?.expiresAt ?? null
	};
	localStorage.setItem(SESSION_KEY, JSON.stringify(session));
	return publish(session);
}

/** Write through to the shared store and hand the value back. */
function publish(session: Session | null): Session | null {
	sessionStore.current = session;
	sessionStore.loaded = true;
	return session;
}

export function getSession(): Session | null {
	if (!browser) return null;
	const raw = localStorage.getItem(SESSION_KEY);
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as Session;
		// Re-validate the role on read: a cache written by an older build (or
		// edited by hand) must not smuggle an unknown role into the UI.
		if (!isSessionRole(parsed.role)) parsed.role = 'user';
		parsed.impersonatedBy ??= null;
		parsed.sessionExpiresAt ??= null;
		return parsed;
	} catch {
		return null;
	}
}

export function endSession(): void {
	if (!browser) return;
	localStorage.removeItem(SESSION_KEY);
	sessionStore.current = null;
	sessionStore.loaded = true;
}

/**
 * Where a signed-in caller belongs. Mirrors `resolvePostAuthDestination` in
 * the API's lib/post-auth.ts — the after-hook normally lands the caller here
 * directly, and /auth/callback re-derives it client-side when it does not.
 */
export function homeFor(role: SessionRole): '/admin/users' | '/connect' {
	return role === 'admin' ? '/admin/users' : '/connect';
}

export async function signOut(): Promise<void> {
	if (!browser) return;
	try {
		await fetch('/api/auth/sign-out', {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'content-type': 'application/json' },
			body: '{}'
		});
	} catch {
		// The server session may outlive a failed request; the local session
		// still ends so the UI signs out either way.
	}
	endSession();
}

/** Start a Discord sign-in. The API's after-hook rewrites the OAuth callback's
 * redirect to the role's real home, so `callbackURL` is only the fallback. */
export async function signInWithDiscord(): Promise<{ ok: true } | { ok: false; message: string }> {
	try {
		const res = await fetch('/api/auth/sign-in/social', {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ provider: 'discord', callbackURL: '/auth/callback' })
		});
		const body = (await res.json()) as { url?: string; message?: string };
		if (!res.ok || !body.url) {
			return { ok: false, message: body.message ?? 'Could not reach Discord. Please try again.' };
		}
		window.location.href = body.url;
		return { ok: true };
	} catch {
		return { ok: false, message: 'Could not reach Discord. Please try again.' };
	}
}
