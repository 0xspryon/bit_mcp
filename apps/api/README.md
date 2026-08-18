To install dependencies:
```sh
bun install
```

To run:
```sh
bun run dev
```

open http://localhost:3000

## Path contract

| Prefix | Owner |
| --- | --- |
| `/api/auth/*` | better-auth — unversioned, handled by `auth.handler` |
| `/api/v1/*` | every other route (`appRoutes` in `src/routes/index.ts`) |

Under `/api/v1`: `GET /health`, `POST /ingest`, `POST /retrieve`,
`GET /records`, `GET /records/:id`, `PATCH /records/:id/status`, and the MCP
JSON-RPC doorway at `POST /mcp`.

## Typed RPC client

`src/hc.ts` exports a Hono RPC client typed on `appRoutes`, published from this
package as `api/hc`. Build it first so consumers read the pre-built types out of
`dist/` instead of re-inferring them from the API source graph:

```sh
bun run build
```

Then, from any app that depends on `"api": "*"`:

```ts
import { API_BASE_PATH, hcWithType } from 'api/hc';

export const apiClient = hcWithType(API_BASE_PATH);

const res = await apiClient.retrieve.$post({
  json: { query: 'sql injection login', namespaces: ['acme'], k: 5 }
});
```

The client is typed on the sub-app, so paths are prefix-free (`apiClient.health`,
not `apiClient.api.v1.health`) — the `/api/v1` prefix comes from the base URL.
Pass a full origin when the client runs outside the API's own host:

```ts
const apiClient = hcWithType(new URL(API_BASE_PATH, apiOrigin).toString());
```
