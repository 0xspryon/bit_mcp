import { apiKey } from '@better-auth/api-key';
import { betterAuth } from 'better-auth';
import { APIError, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { admin, openAPI } from 'better-auth/plugins';
import { db, account, apikey, hasEnabledApiKey, session, user, verification } from '@repo/db';
import { environmentConfig } from '@repo/env';
import { Effect } from 'effect';
import { appAc, roles } from './auth-roles';
import { resolveCallbackRedirect } from './post-auth';

// Module-scoped env reads keep the `auth` export synchronous.
//
// BETTER_AUTH_SECRET is REQUIRED and has no fallback: if it is omitted,
// better-auth silently signs sessions with a publicly-known built-in constant,
// which would let anyone forge an admin session and reach `record:['ingest']`.
// Fail fast at startup instead. (`.env.example` ships a dev placeholder.)
const secret = process.env.BETTER_AUTH_SECRET;
if (secret === undefined || secret.trim().length === 0) {
  throw new Error(
    'BETTER_AUTH_SECRET is required (set it to a strong random value, e.g. `openssl rand -base64 32`). ' +
    'Refusing to start: an unset secret makes better-auth fall back to a well-known default, ' +
    'which makes session tokens forgeable.'
  );
}
export const baseURL = process.env.BETTER_AUTH_URL ?? 'http://localhost:3000';
export const trustedOrigins = (process.env.TRUSTED_ORIGINS ?? '')
  .split(',')
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);

// Discord is the sole sign-in method in production. Email + password is enabled
// only in dev/staging so tests and manual use can create an admin without a
// Discord OAuth app. Resolve the environment through the shared, NORMALIZING +
// VALIDATING parser (trims, lowercases, rejects anything outside dev|staging|
// production at startup) so a casing/typo like `Production` or `prod` can never
// silently leave email/password enabled in a production deployment.
const isProduction = Effect.runSync(environmentConfig) === 'production';

// API-key rate-limit tiers (per 60s window). `default` is what every caller
// gets; `admin` is granted server-side by the api-key create hook below. The
// rate-limit fields on the create endpoint are server-only (better-auth rejects
// them on client requests), so a caller cannot self-assign a higher tier by
// passing rateLimitMax; the only knob that varies the applied limit per request
// is `configId`, and the hook forces that from the session role.
export const API_KEY_USER_TIER_MAX = 20;
export const API_KEY_ADMIN_TIER_MAX = 100;
export const API_KEY_RATE_WINDOW_MS = 60_000;

export const auth = betterAuth({
  appName: 'bit',
  secret,
  baseURL,
  // Allows Discord OAuth callback URLs to point back at the calling UI/MCP app.
  trustedOrigins,
  // Dev/staging only: lets tests/manual use create an admin without a Discord
  // app. Disabled in production (Discord-only). No email delivery is wired, so
  // verification MUST stay off — there is no way to deliver a verification mail.
  emailAndPassword: {
    enabled: !isProduction,
    requireEmailVerification: false
  },
  socialProviders: {
    discord: {
      clientId: process.env.DISCORD_CLIENT_ID ?? '',
      clientSecret: process.env.DISCORD_CLIENT_SECRET ?? '',
      // Request username + email from Discord.
      scope: ['identify', 'email'],
      // Store the Discord username in `user.name` and the email (falling back to
      // a synthetic `${id}@discord.invalid` when Discord returns none) so both
      // fields are always populated for a future dashboard.
      mapProfileToUser: (profile) => ({
        name: profile.global_name ?? profile.username,
        email: profile.email ?? `${profile.id}@discord.invalid`
      })
    }
  },
  // First user created on a fresh install becomes `admin`; everyone after is a
  // plain `user`. The `before` hook runs prior to the insert, so an empty `user`
  // table means this is the very first account. A benign race between two
  // simultaneous first signups is acceptable — a simple emptiness check is fine.
  databaseHooks: {
    user: {
      create: {
        before: async (userData) => {
          const existing = await db.select({ id: user.id }).from(user).limit(1);
          const role = existing.length === 0 ? 'admin' : userData.role ?? 'user';
          return { data: { ...userData, role } };
        }
      }
    }
  },
  plugins: [
    admin({
      ac: appAc,
      roles,
      // Fallback if the create hook above does not set a role; the hook always
      // does, but keep the plugin default aligned with the non-first-user case.
      defaultRole: 'user',
      adminRoles: ['admin']
    }),
    // Lets an `x-api-key` header resolve to a session (used by the MCP doorway).
    // `enableSessionForAPIKeys` is REQUIRED for that: it lets an `x-api-key`
    // header resolve to a session via `auth.api.getSession`, carrying the key
    // owner's role so `requirePermissions` still gates each tool.
    //
    // EXACTLY ONE configuration, deliberately. Tiering used to be two named
    // configurations picked per role, which could never work: the plugin binds
    // an inbound header to the FIRST configuration declaring it and validates
    // against that one alone (`findApiKeyAndConfig` returns on first match,
    // then passes `expectedConfigId: config.configId`). Both tiers listened on
    // `x-api-key`, so every request was checked against `default` and every
    // admin-tier key failed `configIdMatches` with a flat `INVALID_API_KEY`.
    //
    // The rate limit below is therefore a FLOOR, not the whole story:
    // `ApiKeyService.create` sets `rateLimitMax` per key from the owner's role,
    // which is what actually tiers an account. `configId` is left unset so the
    // plugin skips the match check entirely, which also keeps keys minted under
    // the old two-config scheme working.
    // Passed as a bare object, not a one-element array: the array form demands a
    // `configId` on every entry, and naming this one would re-introduce the
    // exact comparison that broke admin keys. Unnamed, `expectedConfigId` is
    // undefined and the plugin skips the check.
    apiKey({
      enableSessionForAPIKeys: true,
      apiKeyHeaders: "x-api-key",
      defaultPrefix: 'bit_',
      rateLimit: {
        enabled: true,
        timeWindow: API_KEY_RATE_WINDOW_MS,
        maxRequests: API_KEY_USER_TIER_MAX
      }
    }),
    openAPI()
  ],
  // Enforce ONE key per account on better-auth's own create route.
  //
  // The tier is no longer decided here. `rateLimitMax` and friends are rejected
  // outright whenever `ctx.request || ctx.headers` is set, which covers both a
  // browser hitting `/api/auth/api-key/create` and any server-side call that
  // forwards the caller's headers — so a hook cannot raise a caller's limit no
  // matter how it rewrites the body. Tiering lives in `ApiKeyService.create`,
  // which calls better-auth WITHOUT headers and is therefore allowed to set it.
  //
  // A key minted directly through this route still works; it just lands on the
  // configuration's floor rate limit. That fails safe — the worst a caller can
  // do by going around our route is give themselves the LOWER limit.
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path !== '/api-key/create') {
        return;
      }
      const authSession = await getSessionFromCtx<{ role?: string | null }>(ctx, {
        disableCookieCache: true
      });
      // One key per account. better-auth happily mints a second, so reject it
      // here — the UI's "refresh" path goes through /api/v1/me/key/refresh,
      // which revokes the old key in the same step.
      if (authSession?.user.id && (await hasEnabledApiKey(authSession.user.id))) {
        throw new APIError('CONFLICT', {
          code: 'API_KEY_ALREADY_EXISTS',
          message: 'This account already holds an API key. Refresh or revoke it instead.'
        });
      }
      return;
    }),
    // Send a freshly signed-in caller to the home their role actually has,
    // instead of the single `callbackURL` the UI had to commit to before it
    // knew who was signing in.
    //
    // The OAuth callback sets the session cookie (which populates
    // `newSession`) BEFORE it throws its redirect, and an after-hook that
    // throws an APIError replaces the returned response — so re-throwing
    // `ctx.redirect` here swaps the Location while leaving the Set-Cookie
    // headers, which are merged from the shared response headers, intact.
    //
    // Anything that is not a completed callback (an OAuth error redirect, any
    // other route) falls through untouched.
    after: createAuthMiddleware(async (ctx) => {
      const destination = resolveCallbackRedirect(ctx.path, ctx.context.newSession);
      if (destination === null) {
        return;
      }
      throw ctx.redirect(new URL(destination, baseURL).toString());
    })
  },
  database: drizzleAdapter(db, {
    provider: 'pg',
    // Our better-auth tables live in the `bit` pgSchema; map each model name to
    // its drizzle table so better-auth reads/writes the existing tables instead
    // of trying to auto-resolve differently-named ones.
    schema: { user, session, account, verification, apikey }
  })
});
