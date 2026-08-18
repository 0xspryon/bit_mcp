import { isSupportedRole, type Role } from './auth-roles';

/**
 * Where a caller lands once a sign-in has produced a session.
 *
 * Admins go to the curation console; everyone else goes to the connect-an-agent
 * screen, which IS the whole user-facing application. Anything unrecognised
 * (a role added to the DB but not to `roles`, or a null role on a partially
 * migrated row) is treated as a plain user — the least-privileged landing.
 */
export const POST_AUTH_DESTINATIONS = {
  admin: '/admin/users',
  user: '/connect'
} as const satisfies Record<Role, string>;

export const resolvePostAuthDestination = (role: string | null | undefined): string =>
  typeof role === 'string' && isSupportedRole(role)
    ? POST_AUTH_DESTINATIONS[role]
    : POST_AUTH_DESTINATIONS.user;

/**
 * Fallback the UI passes as `callbackURL` when it starts a social sign-in.
 *
 * The after-hook below rewrites the OAuth callback's 302 to the role's real
 * home, so this page is normally never rendered. It exists so the flow
 * degrades gracefully rather than breaking if a better-auth upgrade changes
 * the hook internals: the page re-reads the session client-side and routes
 * itself, costing one extra hop instead of stranding the user.
 */
export const AUTH_CALLBACK_PATH = '/auth/callback';

/**
 * Session shape the OAuth callback leaves on `ctx.context.newSession`.
 *
 * Deliberately loose: better-auth types its user as the base columns plus an
 * index signature, so pinning `role` here would either fail the weak-type
 * check or drift the day a plugin reshapes the session. We narrow at the use
 * site instead.
 */
type NewSessionLike = { user?: unknown } | null | undefined;

/**
 * Decide whether an in-flight better-auth request is the OAuth callback whose
 * redirect we want to override, and to where.
 *
 * `ctx.path` carries the ROUTE PATTERN (`/callback/:id`) when better-call
 * builds the endpoint context, but the router may substitute the concrete path
 * (`/callback/discord`). Matching on the prefix covers both without depending
 * on which one we get.
 *
 * Returns `null` when this is not the callback, or when no session was created
 * (the callback also redirects on error, and those must pass through
 * untouched so the UI still sees the error URL).
 */
export const resolveCallbackRedirect = (path: string, newSession: NewSessionLike): string | null => {
  if (!path.startsWith('/callback')) {
    return null;
  }
  // Gate on the session's existence, NOT on the role being set: a signed-in
  // user whose role is null/absent is still a signed-in user and belongs on
  // the user home, whereas no session at all means the callback failed.
  const sessionUser = newSession?.user;
  if (sessionUser === null || typeof sessionUser !== 'object') {
    return null;
  }
  const role = 'role' in sessionUser ? sessionUser.role : null;
  return resolvePostAuthDestination(typeof role === 'string' ? role : null);
};
