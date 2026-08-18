import { API_BASE_PATH, hcWithType } from 'api/hc';

export const apiClient = hcWithType(API_BASE_PATH);
export type ApiClient = typeof apiClient;

/** Shape every typed API error response shares. */
type ApiErrorBody = { error: { code: string; message: string } };

/** Failures outside the API's typed contract: network down, unschema'd 5xx, non-JSON bodies. */
export interface UnexpectedError {
	code: 'UNEXPECTED';
	message: string;
	/** HTTP status when a response arrived; null when the request itself failed. */
	status: number | null;
}

export type ApiResult<TData, TError> = { ok: true; data: TData } | { ok: false; error: TError };

type ResponseBody<TRes> = TRes extends { json(): Promise<infer TBody> } ? TBody : never;
type KnownErrorOf<TRes> = Extract<ResponseBody<TRes>, ApiErrorBody>['error'];
type SuccessOf<TRes> = Exclude<ResponseBody<TRes>, ApiErrorBody>;

/** The typed error union of an endpoint method, e.g. `ErrorsOf<typeof apiClient.foo.$post>`. */
export type ErrorsOf<TEndpoint extends (...args: never[]) => Promise<unknown>> =
	| KnownErrorOf<Awaited<ReturnType<TEndpoint>>>
	| UnexpectedError;
const unexpected = (message: string, status: number | null): UnexpectedError => ({
	code: 'UNEXPECTED',
	message,
	status
});

const isApiErrorBody = (body: unknown): body is ApiErrorBody =>
	typeof body === 'object' &&
	body !== null &&
	'error' in body &&
	typeof (body as ApiErrorBody).error === 'object' &&
	(body as ApiErrorBody).error !== null &&
	typeof (body as ApiErrorBody).error.code === 'string';

/**
 * Execute an RPC request and lift the response into an `ApiResult`.
 * Never throws; transport failures and unrecognized bodies become
 * `UnexpectedError`.
 */
export async function call<TRes extends { ok: boolean; status: number; json(): Promise<unknown> }>(
	request: Promise<TRes>
): Promise<ApiResult<SuccessOf<TRes>, KnownErrorOf<TRes> | UnexpectedError>> {
	let res: TRes;
	try {
		res = await request;
	} catch {
		return { ok: false, error: unexpected('The request could not be sent.', null) };
	}

	let body: unknown = null;
	try {
		body = await res.json();
	} catch {
		// non-JSON body (proxy error page, empty response) — handled below
	}

	if (res.ok) {
		return { ok: true, data: body as SuccessOf<TRes> };
	}
	if (isApiErrorBody(body)) {
		return { ok: false, error: body.error as KnownErrorOf<TRes> };
	}
	return { ok: false, error: unexpected('The server sent an unexpected response.', res.status) };
}

/**
 * Exhaustively match on an API error's code. The handlers object must cover
 * every code in the union — when the API grows a new error code, every call
 * site fails to typecheck until it handles it. At runtime, a code outside
 * the typed contract (schema drift) falls back to the UNEXPECTED handler.
 */
export function matchError<TError extends { code: string }, TOut>(
	error: TError,
	handlers: { [TCode in TError['code']]: (error: Extract<TError, { code: TCode }>) => TOut }
): TOut {
	const table = handlers as unknown as Partial<Record<string, (error: TError) => TOut>>;
	const handler = table[error.code] ?? table['UNEXPECTED'];
	if (!handler) {
		throw new Error(`Unhandled API error code: ${error.code}`);
	}
	return handler(error);
}
