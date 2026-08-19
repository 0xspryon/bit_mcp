/**
 * The caller's own API key.
 *
 * Creating, revoking and refreshing are OURS, under /api/v1/me/key/*. None of
 * them can go through better-auth's own /api/auth/api-key/* routes: minting
 * needs the tier applied server-side (a client-side mint silently lands on the
 * floor limit), revoking and refreshing need the one-key-per-account rule
 * enforced where it can actually see the caller. Only listing still goes
 * straight to the plugin, the way admin actions go to /api/auth/admin/*.
 */
import { apiClient, call, type ApiResult, type ErrorsOf, type UnexpectedError } from './client';

export interface ApiKeyInfo {
	id: string;
	/** First characters of the key — the only part ever redisplayed. */
	start: string | null;
	configId: string | null;
	rateLimitMax: number | null;
	rateLimitTimeWindow: number | null;
	requestCount: number;
	lastRequest: string | null;
	createdAt: string;
	enabled: boolean;
}

/** A key plus its secret. Only ever returned by create and refresh. */
export type CreatedApiKey = ApiKeyInfo & { key: string };

const createEndpoint = apiClient.me.key.$post;
const revokeEndpoint = apiClient.me.key.revoke.$post;
const refreshEndpoint = apiClient.me.key.refresh.$post;
export type CreateKeyError = ErrorsOf<typeof createEndpoint>;
export type RevokeKeyError = ErrorsOf<typeof revokeEndpoint>;
export type RefreshKeyError = ErrorsOf<typeof refreshEndpoint>;

/** better-auth endpoints answer with a bare JSON body (no `error` envelope);
 * failures carry `{ code?, message? }`. Lift both into an ApiResult. */
async function authPost<TData>(
	path: string,
	body: Record<string, unknown>
): Promise<ApiResult<TData, UnexpectedError>> {
	return authFetch<TData>(path, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body)
	});
}

async function authFetch<TData>(
	path: string,
	init: RequestInit = {}
): Promise<ApiResult<TData, UnexpectedError>> {
	let res: Response;
	try {
		res = await fetch(`/api/auth/${path}`, { credentials: 'same-origin', ...init });
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

/** The account's usable key, or null. bit caps this at one per account, so the
 * list is collapsed to a single value here rather than exposed as a table. */
export async function fetchCurrentKey(): Promise<ApiResult<ApiKeyInfo | null, UnexpectedError>> {
	const result = await authFetch<{ apiKeys?: ApiKeyInfo[] }>('api-key/list');
	if (!result.ok) return result;
	const enabled = (result.data.apiKeys ?? []).filter((k) => k.enabled);
	return { ok: true, data: enabled[0] ?? null };
}

/**
 * Mint the account's key.
 *
 * Deliberately NOT better-auth's own `api-key/create`: the per-key rate limit is
 * a server-only field, rejected on any request carrying headers, so a key minted
 * straight from the browser lands on the floor tier whatever the account's role.
 * Ours mints server-side with the tier applied, and answers 409 rather than a
 * second key if the account already holds one.
 */
export async function createKey() {
	return call(createEndpoint());
}

/**
 * Revoke the account's key.
 *
 * Takes no id: bit allows one key per account and the server revokes whatever
 * the session holds, so there is nothing for the browser to name — and no
 * chance of it naming someone else's. Answers `{ revoked }` so the UI can tell
 * "revoked it" from "there was nothing to revoke".
 */
export async function revokeKey() {
	return call(revokeEndpoint());
}

/** Revoke-and-mint in one server-side step. */
export async function refreshKey() {
	return call(refreshEndpoint());
}

/**
 * `100/60s` — the design's TIER cell.
 *
 * Reads the limit off the KEY. It used to print `configId`, which no longer
 * carries the tier and would now label every key `default` however generous its
 * allowance actually is.
 */
export function formatTier(key: Pick<ApiKeyInfo, 'rateLimitMax' | 'rateLimitTimeWindow'>): string {
	if (key.rateLimitMax === null) return 'unlimited';
	const windowSeconds = Math.round((key.rateLimitTimeWindow ?? 60_000) / 1000);
	return `${key.rateLimitMax}/${windowSeconds}s`;
}

/** `6 / 20` — the design's CALLS_60S cell. */
export function formatCalls(key: Pick<ApiKeyInfo, 'requestCount' | 'rateLimitMax'>): string {
	return key.rateLimitMax === null
		? String(key.requestCount)
		: `${key.requestCount} / ${key.rateLimitMax}`;
}

/**
 * The opencode MCP config block, with the caller's key filled in.
 *
 * Shaped for `opencode.json` specifically: the server list lives under `mcp`
 * (not the `mcpServers` key Claude Desktop and friends use), and a server
 * reached over HTTP must declare `type: 'remote'` — without it opencode reads
 * the entry as a local stdio server and looks for a command to spawn.
 *
 * `$schema` is included so editors offer completion and validation on the file.
 * `enabled` is optional, and stated anyway: it is the switch a user reaches for
 * to park the server without deleting their key.
 */
export function mcpClientConfig(keyDisplay: string, origin: string): string {
	return JSON.stringify(
		{
			$schema: 'https://opencode.ai/config.json',
			mcp: {
				bit: {
					type: 'remote',
					url: `${origin}/api/v1/mcp`,
					enabled: true,
					headers: { 'x-api-key': keyDisplay }
				}
			}
		},
		null,
		2
	);
}
