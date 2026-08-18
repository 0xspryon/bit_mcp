# web

The bit console: sign in with Discord, mint an API key, wire an agent up to the
MCP doorway. Admins additionally get user management.

## Shape

A **single-page app**. There is no server: `src/routes/+layout.ts` sets
`ssr = false`, and `@sveltejs/adapter-static` compiles the whole thing to a
directory of static files under `build/` — one `index.html` shell plus
fingerprinted assets in `_app/immutable/`.

Everything dynamic comes from the api at runtime over `fetch`. The RPC client is
built on the api's own exported types (`api/hc`), so the console cannot drift
from the contract it calls.

## Same-origin, always

The console and the api MUST be served from one origin. Three things depend on
it, and they all break together:

- the RPC client calls **relative** `/api/v1/*` URLs (`src/lib/api/client.ts`)
- better-auth issues a **first-party** session cookie
- OAuth completion redirects to `/connect` and `/admin/users` — SPA routes

In dev, `vite.config.ts` proxies `/api` to the local api. In production, Traefik
routes `/api` to the api container and everything else to this one.

## Development

```bash
bun run dev            # vite, with /api proxied to localhost:3000
bun run check          # svelte-check
bun run test:unit      # vitest
bun run test:integration  # playwright
```

## Production

```bash
docker build -f apps/web/Dockerfile.production -t bit-web .   # from the REPO ROOT
```

Two stages: bun builds the bundle, then it is copied into `caddy:2-alpine`. The
runtime image carries no bun, no `node_modules`, and no source — Caddy plus
roughly 2 MB of static files, ~92 MB all in.

`Caddyfile` serves it on `:80` inside the compose network, behind Dokploy's
Traefik, which owns the hostname and terminates TLS. It handles the three things
a static SPA host has to get right:

| Concern | Behaviour |
| --- | --- |
| Deep links | `/admin/users` has no file on disk → falls back to the shell |
| Missing assets | `/_app/*` 404s instead of returning HTML a browser would parse as JS |
| Cache correctness | hashed assets `immutable` for a year; the shell `no-cache` |

The bundle takes **no runtime configuration**. Anything environment-specific
would have to be baked in at build time — which is why the api base URL is a
relative path instead.
