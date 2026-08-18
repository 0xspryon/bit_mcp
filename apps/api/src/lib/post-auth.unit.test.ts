import { describe, expect, it } from 'vitest';
import {
  POST_AUTH_DESTINATIONS,
  resolveCallbackRedirect,
  resolvePostAuthDestination
} from './post-auth';

describe('resolvePostAuthDestination', () => {
  it('sends an admin to the curation console', () => {
    expect(resolvePostAuthDestination('admin')).toBe(POST_AUTH_DESTINATIONS.admin);
  });

  it('sends a plain user to connect-an-agent', () => {
    expect(resolvePostAuthDestination('user')).toBe(POST_AUTH_DESTINATIONS.user);
  });

  // A role present in the DB but absent from `roles` must never inherit the
  // admin landing — least privilege on an unknown value.
  it.each([['curator'], ['ADMIN'], ['']])('treats the unknown role %j as a user', (role) => {
    expect(resolvePostAuthDestination(role)).toBe(POST_AUTH_DESTINATIONS.user);
  });

  it.each([[null], [undefined]])('treats a %s role as a user', (role) => {
    expect(resolvePostAuthDestination(role)).toBe(POST_AUTH_DESTINATIONS.user);
  });
});

describe('resolveCallbackRedirect', () => {
  const session = (role: unknown) => ({ user: { id: 'u1', email: 'a@b.c', role } });

  // `ctx.path` may arrive as the route pattern or the concrete path depending
  // on whether the router substituted params — both must match.
  it.each([['/callback/:id'], ['/callback/discord']])('overrides the redirect on %s', (path) => {
    expect(resolveCallbackRedirect(path, session('admin'))).toBe(POST_AUTH_DESTINATIONS.admin);
    expect(resolveCallbackRedirect(path, session('user'))).toBe(POST_AUTH_DESTINATIONS.user);
  });

  it.each([['/sign-in/social'], ['/api-key/create'], ['/get-session'], ['/']])(
    'leaves %s alone',
    (path) => {
      expect(resolveCallbackRedirect(path, session('admin'))).toBeNull();
    }
  );

  // The callback also redirects on OAuth failure, with no session created.
  // Those must pass through so the UI still reaches its error URL.
  it.each([[null], [undefined], [{}], [{ user: null }]])(
    'passes the redirect through when no session was created (%j)',
    (newSession) => {
      expect(resolveCallbackRedirect('/callback/discord', newSession)).toBeNull();
    }
  );

  // A session whose role is missing or non-string is still a signed-in user.
  it.each([[null], [undefined], [42]])('lands a session with role %j on the user home', (role) => {
    expect(resolveCallbackRedirect('/callback/discord', session(role))).toBe(
      POST_AUTH_DESTINATIONS.user
    );
  });
});
