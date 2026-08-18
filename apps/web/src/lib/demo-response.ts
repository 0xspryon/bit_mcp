/**
 * The canned retrieve response the landing pages through.
 *
 * Static on purpose, per the hand-off's own note: the 1/5 pager is
 * "client-side only, no request". It has to be — the landing is
 * unauthenticated and `/api/v1/retrieve` requires an API key, so there is
 * nothing to call and nothing to rate-limit. These are illustrative records in
 * the corpus's real shape, not a live query.
 */

export interface DemoChunk {
	namespaces: string[];
	title: string;
	symptom: string;
	procedure: string;
	whenToUse: string;
	confirmationSignal: string;
	preconditions: string[];
	appliesTo: string[];
	cwe: number[];
	chainsWith: string[];
	qualityTier: number;
	sources: Array<{ url: string; title: string; tier: number; kind: string }>;
	score: number;
}

/** The question the demo answers — shown in the "what an agent asks" panel. */
export const DEMO_QUERY =
	"/admin returns 403 but only from the edge — how do I tell the proxy's refusal from the app's, and get through it?";

export const DEMO_QUERY_PARAMS = 'k=5 · namespaces=[authz, proxy] · min_tier=2';

/** Shorter form for the 390 companion, where the full question wraps badly. */
export const DEMO_QUERY_MOBILE =
	"/admin returns 403 but only from the edge — how do I tell the proxy's refusal from the app's?";

export const DEMO_QUERY_PARAMS_MOBILE = 'namespaces=[authz, proxy] · min_tier=2';

export const DEMO_CHUNKS: DemoChunk[] = [
	{
		namespaces: ['403-bypass'],
		title: 'HTTP parser desync: proxy ACL (403) bypass via trailing trim byte',
		symptom:
			'A reverse proxy (nginx) returns 403 for a path such as /admin, but appending a trailing byte the backend trims — while the proxy keeps it in the path — yields a response that materially differs from the same request without the byte (a non-403 status, a different body/headers/cookies, or a noticeably higher latency). Proxy and backend disagree on the normalized path.',
		procedure:
			'Identify the proxy path ACL (e.g. nginx `location = /admin { deny all; }`). Fingerprint the backend framework, then append the framework-specific trailing byte the backend trims but the proxy keeps. Send a raw request line so nginx sees the byte (no exact ACL match) and forwards it, and the backend strips the byte and serves /admin.',
		whenToUse:
			'Proxy enforces an exact-match path ACL (e.g. nginx `location = /admin { deny all; }`) in front of a different-language backend (Node/Flask/Spring) that strips trailing bytes.',
		confirmationSignal:
			'Compare the bypass request against a baseline request WITHOUT the trailing byte; a successful desync is a DIVERGENCE from that baseline, not a guaranteed 200 (the backend may still enforce its own auth and answer 401/302/404). Any of the following indicates the proxy ACL was bypassed: (1) a status other than the proxy 403; (2) a response whose body, headers, or cookies differ from the un-bypassed request; (3) a noticeably higher response latency.',
		preconditions: [
			'reverse proxy with exact-match path ACL',
			'backend parser differs from the proxy (different language)',
			'ability to send raw bytes in the request line'
		],
		appliesTo: ['nginx', 'Node.js', 'Express', 'Flask', 'Spring Boot', 'PHP-FPM'],
		cwe: [862, 436, 444, 20],
		chainsWith: ['cache-poisoning', 'ssrf'],
		qualityTier: 1,
		sources: [
			{
				url: 'https://blog.bugport.net/exploiting-http-parsers-inconsistencies',
				title: 'Exploiting HTTP Parsers Inconsistencies',
				tier: 1,
				kind: 'writeup'
			}
		],
		score: 0.938
	},
	{
		namespaces: ['403-bypass', 'authz'],
		title: 'Path traversal normalization gap: proxy ACL bypass via encoded dot-segments',
		symptom:
			'The proxy denies /admin but permits a longer path that resolves back to it after the backend decodes percent-encoded dot-segments — the proxy matches on the raw path while the backend matches on the decoded one.',
		procedure:
			'Request a permitted prefix followed by an encoded traversal that walks back to the denied path. Vary the encoding (single, double, mixed-case) because proxy and backend often normalize at different stages.',
		whenToUse:
			'The proxy performs prefix or exact matching on a raw path and the backend decodes before routing.',
		confirmationSignal:
			'The traversal request returns the denied resource while the direct request still returns 403 — compare bodies, not just status.',
		preconditions: ['proxy matches on the raw path', 'backend decodes before routing'],
		appliesTo: ['nginx', 'Apache', 'Traefik', 'Spring Boot'],
		cwe: [22, 862, 436],
		chainsWith: ['403-bypass', 'cache-poisoning'],
		qualityTier: 1,
		sources: [
			{
				url: 'https://portswigger.net/research/url-parsing-confusion',
				title: 'URL parsing confusion',
				tier: 1,
				kind: 'research'
			}
		],
		score: 0.902
	},
	{
		namespaces: ['authz', 'proxy'],
		title: 'Header-trust bypass: forged X-Forwarded-For / X-Real-IP on an internal ACL',
		symptom:
			'An endpoint is restricted to internal addresses, but the application reads a client-controlled forwarding header the proxy neither strips nor overwrites.',
		procedure:
			'Send the request with a forwarding header claiming an allowed source address, then vary the header name across the set the framework consults.',
		whenToUse:
			'The app enforces an IP allowlist from a header rather than the transport peer address.',
		confirmationSignal:
			'The same request succeeds with the forged header and fails without it, with no other change.',
		preconditions: ['app trusts a forwarding header', 'proxy does not overwrite it'],
		appliesTo: ['nginx', 'Express', 'Flask', 'Rails'],
		cwe: [290, 348, 862],
		chainsWith: ['ssrf', 'rate-limit-bypass'],
		qualityTier: 2,
		sources: [
			{
				url: 'https://owasp.org/www-project-web-security-testing-guide/',
				title: 'WSTG: testing for authorization bypass',
				tier: 2,
				kind: 'guide'
			}
		],
		score: 0.871
	},
	{
		namespaces: ['403-bypass', 'method'],
		title: 'Verb-scoped ACL bypass: denied path reachable under an unmatched HTTP method',
		symptom:
			'The proxy rule constrains one method, so the same path answers differently under HEAD, POST or an extension method the rule never enumerated.',
		procedure:
			'Replay the denied request across the method set, including the override headers some frameworks honour, and diff each response against the 403 baseline.',
		whenToUse: 'The ACL names methods explicitly rather than denying all of them.',
		confirmationSignal:
			'A method other than the denied one returns non-403 content for the same path.',
		preconditions: ['method-scoped ACL', 'backend routes the path for several methods'],
		appliesTo: ['nginx', 'HAProxy', 'Express', 'Django'],
		cwe: [862, 436],
		chainsWith: ['403-bypass'],
		qualityTier: 2,
		sources: [
			{
				url: 'https://portswigger.net/web-security/access-control',
				title: 'Access control vulnerabilities',
				tier: 1,
				kind: 'guide'
			}
		],
		score: 0.844
	},
	{
		namespaces: ['proxy', 'cache'],
		title: 'Edge-only refusal: distinguishing a CDN denial from an application denial',
		symptom:
			'A 403 arrives too fast and lacks the application response headers — the refusal comes from the edge, not the origin, so application-layer probing is measuring the wrong thing.',
		procedure:
			'Compare timing, header set and error body against a known-origin response. Request a cache-busting variant and re-measure; an origin-served refusal carries the application fingerprint.',
		whenToUse: 'Before spending effort on an app-layer bypass, to establish which tier is refusing.',
		confirmationSignal:
			'Edge refusals hold latency near the edge RTT and omit origin headers; origin refusals carry the application fingerprint.',
		preconditions: ['a CDN or edge proxy in front of the origin'],
		appliesTo: ['Cloudflare', 'Fastly', 'Akamai', 'nginx'],
		cwe: [436],
		chainsWith: ['403-bypass', 'cache-poisoning'],
		qualityTier: 2,
		sources: [
			{
				url: 'https://blog.cloudflare.com/tag/security/',
				title: 'Edge security behaviour',
				tier: 2,
				kind: 'writeup'
			}
		],
		score: 0.817
	}
];
