/**
 * The caller's own API key.
 *
 * Listing, creating and revoking go straight to the better-auth api-key plugin
 * under /api/auth/api-key/*, the same way admin actions go straight to
 * /api/auth/admin/*. Refresh is ours (/api/v1/me/key/refresh) because it has
 * to revoke and mint as one server-side step — see that route's handler for
 * why the ordering matters.
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

const refreshEndpoint = apiClient.me.key.refresh.$post;
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

export async function createKey(): Promise<ApiResult<CreatedApiKey, UnexpectedError>> {
	// The tier (`configId`) is forced server-side from the caller's role, and
	// the one-key-per-account rule is enforced by the same hook — so there is
	// nothing to send but a name.
	return authPost<CreatedApiKey>('api-key/create', { name: 'bit' });
}

/**
 * `configId` is required, not decorative: with it omitted the plugin resolves
 * the `default` configuration and then 404s any key stored under a different
 * one — so an admin-tier key would be impossible to revoke from the UI.
 */
export async function revokeKey(
	keyId: string,
	configId?: string | null
): Promise<ApiResult<unknown, UnexpectedError>> {
	return authPost('api-key/delete', { keyId, ...(configId ? { configId } : {}) });
}

/** Revoke-and-mint in one server-side step. */
export async function refreshKey() {
	return call(refreshEndpoint());
}

/** `default · 20/60s` — the design's TIER cell. */
export function formatTier(key: Pick<ApiKeyInfo, 'configId' | 'rateLimitMax' | 'rateLimitTimeWindow'>): string {
	const tier = key.configId ?? 'default';
	if (key.rateLimitMax === null) return tier;
	const windowSeconds = Math.round((key.rateLimitTimeWindow ?? 60_000) / 1000);
	return `${tier} · ${key.rateLimitMax}/${windowSeconds}s`;
}

/** `6 / 20` — the design's CALLS_60S cell. */
export function formatCalls(key: Pick<ApiKeyInfo, 'requestCount' | 'rateLimitMax'>): string {
	return key.rateLimitMax === null
		? String(key.requestCount)
		: `${key.requestCount} / ${key.rateLimitMax}`;
}

/** The MCP client config block, with the caller's key prefix filled in. */
export function mcpClientConfig(keyDisplay: string, origin: string): string {
	return JSON.stringify(
		{
			mcpServers: {
				bit: {
					url: `${origin}/api/v1/mcp`,
					headers: { 'x-api-key': keyDisplay }
				}
			}
		},
		null,
		2
	);
}
