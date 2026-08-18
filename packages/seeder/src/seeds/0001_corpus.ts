import { records } from '@repo/db/schema';
import { RecordRepoDefault, SourceRepoDefault } from '@repo/db';
import { EmbeddingServiceLive, IngestService, IngestServiceLive } from '@repo/rag-core';
import { eq } from 'drizzle-orm';
import { Effect, Layer, ManagedRuntime } from 'effect';
import type { Seed } from '../types';

/**
 * Seeds the vulnerability-methodology corpus.
 *
 * Records need a real 1024-dim embedding, which only the embedding endpoint can
 * produce, so this reuses the runtime ingest path verbatim: a `ManagedRuntime`
 * built from the real repos + `EmbeddingServiceLive` provided to
 * `IngestServiceLive`. `ingest` computes the content_hash + embedding exactly as
 * at runtime and dedups by hash, which makes re-runs cheap and idempotent.
 *
 * Freshly ingested records land in `status = 'staging'`; each is then promoted
 * to `'active'` (a no-op on re-run). The embedding index is HNSW, which builds
 * incrementally on insert, so no post-load reindex is needed.
 */

/** Authoring shape — the encoded input `IngestService.ingest` validates. */
interface CorpusRecord {
  readonly namespaces: readonly string[];
  readonly title: string;
  readonly symptom: string;
  readonly procedure: string;
  readonly whenToUse?: string;
  readonly confirmationSignal?: string;
  readonly preconditions?: readonly string[];
  readonly appliesTo?: readonly string[];
  readonly cwe?: readonly number[];
  readonly vrt?: readonly string[];
  readonly chainsWith?: readonly string[];
  readonly qualityTier?: number;
  readonly sources?: ReadonlyArray<{
    readonly url: string;
    readonly title?: string;
    readonly tier?: number;
    readonly kind?: string;
  }>;
}

const corpus: readonly CorpusRecord[] = [
  {
    namespaces: ['ssrf'],
    title: 'Blind SSRF to cloud metadata via URL-fetching feature',
    symptom:
      'A feature that fetches a user-supplied URL (webhook validator, image proxy, PDF/URL preview) can be pointed at internal addresses. No response body is reflected, but timing and out-of-band DNS/HTTP callbacks differ for reachable internal hosts.',
    procedure:
      'Submit an external collaborator URL and confirm the server makes the request. Then swap in internal targets: 169.254.169.254 (AWS/GCP/Azure metadata), 127.0.0.1, and RFC1918 ranges. Bypass naive allowlists with alternate encodings (decimal/octal IP, IPv6-mapped, a DNS name that resolves to an internal IP) and open-redirect chaining. On AWS IMDSv1, request /latest/meta-data/iam/security-credentials/ to lift role credentials.',
    whenToUse:
      'Any parameter that causes the backend to fetch a URL: webhooks, avatar-from-URL, SSRF-prone document/HTML renderers, link unfurlers.',
    confirmationSignal:
      'Out-of-band DNS or HTTP hit from the server IP for an attacker-controlled hostname, or a metadata endpoint returning credentials/instance data.',
    preconditions: ['server-side URL fetch of user input', 'no strict egress firewall or allowlist'],
    appliesTo: ['AWS EC2', 'GCP', 'Azure', 'Node.js', 'Ruby on Rails', 'PHP'],
    cwe: [918, 200],
    chainsWith: ['open-redirect', 'cloud-metadata'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/ssrf',
        title: 'Server-side request forgery (SSRF)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['idor'],
    title: 'IDOR on numeric/UUID object references in API endpoints',
    symptom:
      'An object is fetched or mutated by an id in the path/body (e.g. /api/invoices/1042), and changing the id returns another tenant/user’s object. The server checks authentication but not ownership.',
    procedure:
      'Enumerate object ids (increment integers; harvest UUIDs from other responses, emails, or logs). Replay the request as user A against object ids owned by user B on GET, PUT, PATCH and DELETE separately — authorization is often enforced on read but not on write. Test sibling endpoints and export/print variants that share the object but skip the check.',
    whenToUse: 'REST/GraphQL endpoints that take a direct object reference and return per-user data.',
    confirmationSignal:
      'A request authenticated as user A returns or modifies data belonging to user B (200 with foreign data, or a successful state change).',
    preconditions: ['authenticated session', 'object accessed by a guessable/harvestable id'],
    appliesTo: ['REST APIs', 'GraphQL', 'Django', 'Express', 'Spring Boot'],
    cwe: [639, 862, 284],
    chainsWith: ['mass-assignment'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
        title: 'OWASP WSTG: Testing for IDOR',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['sqli'],
    title: 'Error-based and boolean-blind SQL injection in query parameters',
    symptom:
      'A parameter used in a SQL query alters results or throws a database error when injected with a single quote. Boolean payloads (’ AND 1=1 vs ’ AND 1=2) produce different responses; error strings leak the DBMS.',
    procedure:
      'Probe each parameter with a single quote and observe errors. Confirm with boolean pairs (AND 1=1 / AND 1=2) and time-based payloads (SLEEP/pg_sleep/WAITFOR DELAY) for blind cases. Fingerprint the DBMS from error text or version functions, then use UNION SELECT (matching column count/types) or stacked queries to extract data. Automate extraction once a reliable oracle is established.',
    whenToUse:
      'Any parameter (query string, body, header, cookie) that appears to reach a SQL query, especially with string-concatenated queries.',
    confirmationSignal:
      'A time-based payload reliably delays the response, or a boolean oracle flips output deterministically, or UNION output surfaces DB values.',
    preconditions: ['user input concatenated into a SQL statement', 'no parameterization on the sink'],
    appliesTo: ['MySQL', 'PostgreSQL', 'Microsoft SQL Server', 'Oracle', 'SQLite'],
    cwe: [89],
    chainsWith: ['disclosure'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/sql-injection',
        title: 'SQL injection',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['xss-stored'],
    title: 'Stored XSS in user-controlled profile/comment fields',
    symptom:
      'Text submitted in a field (display name, comment, support ticket) is rendered back to other users without contextual output encoding, so injected HTML/JS executes in their browser.',
    procedure:
      'Insert a benign marker in each stored field and locate where it is rendered (admin dashboards and notification emails are high-value sinks). Determine the HTML context (element body, attribute, JS string, URL) and craft a context-appropriate payload. Confirm with a payload that beacons to a collaborator, capturing document.cookie or performing an authenticated action as the viewing user.',
    whenToUse: 'Fields whose values are stored and later rendered to other users or to staff.',
    confirmationSignal:
      'A collaborator callback fires in a victim/admin session when the stored value is viewed, proving script execution in another origin context.',
    preconditions: ['persisted user input', 'output rendered without contextual encoding or CSP'],
    appliesTo: ['React (dangerouslySetInnerHTML)', 'server-rendered templates', 'admin panels'],
    cwe: [79],
    chainsWith: ['csrf', 'account-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/cross-site-scripting/stored',
        title: 'Stored cross-site scripting',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['xxe'],
    title: 'XXE via external entity in XML/SVG/DOCX upload or API body',
    symptom:
      'An endpoint parses XML (SOAP, SAML, SVG, OOXML) with a parser that resolves external entities, allowing local file read or SSRF through a crafted DOCTYPE.',
    procedure:
      'Submit XML with a DOCTYPE declaring an external entity referencing file:///etc/passwd (or a collaborator URL) and reference it in a value echoed back for classic XXE. For blind cases, use an external DTD to exfiltrate file contents over an out-of-band channel (parameter entities + error-based or OOB DTD). SVG and DOCX uploads are common XML sinks even when no obvious XML field exists.',
    whenToUse: 'Any XML-consuming endpoint or file upload that is internally parsed as XML.',
    confirmationSignal:
      'File contents appear in the response or in an out-of-band request, or the parser makes a collaborator request from the server.',
    preconditions: ['XML parsed server-side', 'external entity resolution not disabled'],
    appliesTo: ['Java (JAXP)', '.NET', 'PHP libxml', 'Python lxml', 'SAML IdPs'],
    cwe: [611, 918],
    chainsWith: ['ssrf', 'path-traversal'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/xxe',
        title: 'XML external entity (XXE) injection',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['open-redirect'],
    title: 'Open redirect via unvalidated return/next parameter',
    symptom:
      'A redirect parameter (next, returnUrl, redirect_uri, url) sends the browser to an arbitrary external origin, enabling phishing and OAuth token theft when chained.',
    procedure:
      'Set the redirect parameter to an external origin and follow the response. Defeat weak allowlist checks with tricks like //evil.com, https:evil.com, https://trusted.com@evil.com, backslashes (\\/\\/evil.com), and whitelisted-prefix bypasses (https://trusted.com.evil.com). Confirm the final Location or client-side navigation lands on the attacker origin.',
    whenToUse: 'Login/logout flows and any endpoint that echoes a URL parameter into a redirect.',
    confirmationSignal: 'The response 30x Location header (or JS navigation) points to the attacker-controlled origin.',
    preconditions: ['redirect target taken from user input', 'no strict same-origin/allowlist check'],
    appliesTo: ['OAuth clients', 'SSO login pages', 'marketing redirects'],
    cwe: [601],
    chainsWith: ['oauth-redirect', 'ssrf'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cwe.mitre.org/data/definitions/601.html',
        title: 'CWE-601: URL Redirection to Untrusted Site',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['csrf'],
    title: 'CSRF on state-changing request lacking anti-CSRF token',
    symptom:
      'A sensitive POST (change email, add payment method, transfer) succeeds cross-site with only cookies for auth — no unpredictable token, and SameSite is not Lax/Strict.',
    procedure:
      'Capture the state-changing request and remove any CSRF token; if it still succeeds, the token is not validated. Test token robustness (reuse another user’s token, blank token, method swap POST→GET). Build an auto-submitting cross-origin HTML form and confirm the action executes using the victim’s ambient cookies. Check whether SameSite=Lax still permits top-level GET-based state changes.',
    whenToUse: 'Cookie-authenticated, state-changing endpoints without a per-request token or SameSite protection.',
    confirmationSignal: 'A cross-origin form submission performs the action as the victim without any token.',
    preconditions: ['cookie-based session', 'no CSRF token / weak SameSite', 'predictable request shape'],
    appliesTo: ['classic server-rendered apps', 'form-based APIs'],
    cwe: [352],
    chainsWith: ['xss-stored'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/csrf',
        title: 'Cross-site request forgery (CSRF)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['jwt-alg-confusion'],
    title: 'JWT algorithm confusion (RS256 to HS256) and alg:none',
    symptom:
      'A service verifies JWTs but accepts an attacker-chosen algorithm. Switching an RS256 token to HS256 and signing with the public key as the HMAC secret — or setting alg:none — forges a valid token.',
    procedure:
      'Read the header alg. Try alg:none with an empty signature. For RSA-verified tokens, obtain the public key (JWKS endpoint, TLS cert, or /.well-known), then re-sign the token as HS256 using the PEM public key bytes as the HMAC secret; a library that selects the verifier from the token header will validate it. Modify claims (sub, role, scope) before signing to escalate privileges.',
    whenToUse: 'Any JWT-authenticated API where the token header algorithm may drive verifier selection.',
    confirmationSignal: 'A forged token with elevated claims is accepted (authenticated request succeeds as another/admin user).',
    preconditions: ['verifier trusts the token-supplied alg', 'public key retrievable'],
    appliesTo: ['Node jsonwebtoken', 'Java jjwt', 'PyJWT', 'OAuth resource servers'],
    cwe: [347, 345],
    chainsWith: ['idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt/algorithm-confusion',
        title: 'JWT algorithm confusion attacks',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['path-traversal'],
    title: 'Path traversal in file download/read parameter',
    symptom:
      'A filename/path parameter used to read a file allows ../ sequences to escape the intended directory and read arbitrary files.',
    procedure:
      'Supply ../../../../etc/passwd (and Windows ..\\..\\ variants) to the file parameter. Defeat filters with URL-encoding (%2e%2e%2f), double-encoding (%252e), overlong UTF-8, and nested traversal (....//). If a forced base directory or extension suffix is appended, test absolute paths and NUL/segment tricks. Confirm by reading a known-sensitive file.',
    whenToUse: 'Download endpoints, template/include loaders, and any sink that maps user input to a filesystem path.',
    confirmationSignal: 'The response returns the contents of a file outside the intended directory (e.g. /etc/passwd).',
    preconditions: ['user input used to build a filesystem path', 'insufficient canonicalization'],
    appliesTo: ['Java', 'PHP', 'Node.js', 'nginx alias misconfig', '.NET'],
    cwe: [22, 200],
    chainsWith: ['disclosure', 'xxe'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-community/attacks/Path_Traversal',
        title: 'OWASP: Path Traversal',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['ssti'],
    title: 'Server-side template injection in rendered user input',
    symptom:
      'User input is concatenated into a server-side template, so template syntax is evaluated — arithmetic like {{7*7}} renders 49, and object traversal reaches code execution.',
    procedure:
      'Detect the engine with polyglot probes ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>). Once the engine is known (Jinja2, Twig, Freemarker, Velocity, ERB), walk the object graph to reach OS command execution or file read using engine-specific gadgets (e.g. Jinja2 __class__ / __subclasses__). Escalate from expression evaluation to RCE.',
    whenToUse: 'Any feature that lets users influence a template string: email templates, report/label builders, CMS snippets.',
    confirmationSignal: 'A mathematical expression evaluates server-side, or an engine gadget returns command output/file contents.',
    preconditions: ['user input reaches a template render call', 'engine evaluates the injected syntax'],
    appliesTo: ['Jinja2', 'Twig', 'Freemarker', 'Velocity', 'ERB'],
    cwe: [1336, 94, 95],
    chainsWith: ['rce'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/server-side-template-injection',
        title: 'Server-side template injection',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['graphql-introspection'],
    title: 'GraphQL introspection and field suggestion information exposure',
    symptom:
      'A production GraphQL endpoint answers introspection queries (or leaks the schema via "did you mean" suggestions), exposing hidden types, mutations, and internal fields.',
    procedure:
      'Send a full __schema introspection query. If disabled, use field-suggestion probing (misspelled fields return close matches) to reconstruct the schema. Enumerate mutations and sensitive queries, then test them for missing authorization, IDOR, and batching/alias-based abuse (query cost / brute force via aliases).',
    whenToUse: 'Any GraphQL endpoint, especially internal/admin schemas exposed on the same route.',
    confirmationSignal: 'The endpoint returns the introspected schema, or suggestion errors reveal undocumented field/type names.',
    preconditions: ['GraphQL endpoint reachable', 'introspection or suggestions not disabled'],
    appliesTo: ['Apollo Server', 'graphql-js', 'Hasura', 'GraphQL Yoga'],
    cwe: [200],
    chainsWith: ['idor', 'mass-assignment'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        title: 'OWASP GraphQL Cheat Sheet',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['cors-misconfig'],
    title: 'CORS misconfiguration reflecting Origin with credentials',
    symptom:
      'The API reflects an arbitrary request Origin into Access-Control-Allow-Origin while also returning Access-Control-Allow-Credentials: true, letting any site read authenticated responses.',
    procedure:
      'Send requests with a crafted Origin header and inspect the ACAO/ACAC response headers. Test reflection of an arbitrary origin, null origin (via sandboxed iframe), and weak suffix/prefix matching (evil-trusted.com, trusted.com.evil.com). If ACAO reflects the attacker origin with credentials allowed, host a page that fetches a sensitive authenticated endpoint and exfiltrates the response.',
    whenToUse: 'Credentialed cross-origin APIs whose CORS policy derives from the request Origin.',
    confirmationSignal: 'An attacker-origin page reads an authenticated response body (ACAO echoes the attacker origin with credentials true).',
    preconditions: ['Access-Control-Allow-Credentials: true', 'Origin reflected or weakly matched'],
    appliesTo: ['REST APIs', 'SPAs with cookie auth'],
    cwe: [942, 346],
    chainsWith: ['disclosure'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/cors',
        title: 'Cross-origin resource sharing (CORS)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['subdomain-takeover'],
    title: 'Subdomain takeover via dangling DNS to deprovisioned service',
    symptom:
      'A CNAME/ALIAS points to a third-party service (S3 bucket, GitHub Pages, Heroku, Azure) that no longer exists, so an attacker can claim the resource and serve content on the victim subdomain.',
    procedure:
      'Enumerate subdomains and resolve their CNAMEs. Flag dangling targets that return service-specific "no such bucket/app" fingerprints. Register/claim the underlying resource on the third-party provider using the same name and publish a proof file. Assess impact: cookie scope, OAuth redirect allowlists, and CSP/script trust that extend to the taken-over subdomain.',
    whenToUse: 'Organizations with many subdomains and CNAMEs to cloud/SaaS providers.',
    confirmationSignal: 'Attacker-published content is served from the victim subdomain over the legitimate DNS name.',
    preconditions: ['dangling DNS record', 'target provider allows claiming the freed name'],
    appliesTo: ['AWS S3', 'GitHub Pages', 'Heroku', 'Azure', 'Fastly'],
    cwe: [350, 284],
    chainsWith: ['oauth-redirect', 'cors-misconfig'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://github.com/EdOverflow/can-i-take-over-xyz',
        title: 'Can I take over XYZ? — subdomain takeover fingerprints',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['race-condition'],
    title: 'TOCTOU race condition on limited-use / balance operations',
    symptom:
      'A limit that should hold once (redeem a coupon, withdraw balance, accept an invite) can be exceeded by firing many concurrent requests before the check-then-act completes.',
    procedure:
      'Identify a single-use or balance-limited action. Send many identical requests simultaneously (single-packet / last-byte-sync technique to minimize timing jitter) so they all pass the check before any commits. Compare the resulting state to the intended limit. Confirm the invariant was violated (e.g. a coupon redeemed N times, balance over-withdrawn).',
    whenToUse: 'Actions guarded by a read-check-then-write without an atomic constraint or lock.',
    confirmationSignal: 'A once-only operation succeeds multiple times, or a balance/limit is driven past its intended bound.',
    preconditions: ['non-atomic check-then-act', 'endpoint accepts concurrent requests'],
    appliesTo: ['payment/wallet flows', 'coupon/voucher redemption', 'invite systems'],
    cwe: [362, 367],
    chainsWith: ['logic'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/race-conditions',
        title: 'Race conditions',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['oauth-redirect'],
    title: 'OAuth redirect_uri manipulation for authorization code theft',
    symptom:
      'The authorization server accepts a redirect_uri that is not an exact match to a registered value, letting the authorization code/token be delivered to an attacker-controlled endpoint.',
    procedure:
      'Inspect the registered redirect_uri handling. Test loose matching: append paths, query strings, or fragments; try open-redirect or subdomain-takeover targets under the allowed origin; try path-traversal in the redirect path. If a code is issued to an attacker-influenced URI, capture it and exchange it at the token endpoint. Also test missing/weak state (CSRF on the callback).',
    whenToUse: 'OAuth2/OIDC authorization endpoints, especially with wildcard or prefix redirect matching.',
    confirmationSignal: 'An authorization code or token is delivered to an attacker-controlled URL and can be exchanged for a session.',
    preconditions: ['non-exact redirect_uri validation', 'ability to influence the callback URL'],
    appliesTo: ['OAuth2 providers', 'OIDC IdPs', 'SSO integrations'],
    cwe: [601, 863, 352],
    chainsWith: ['open-redirect', 'subdomain-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 authentication vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['insecure-deserialization'],
    title: 'Insecure deserialization gadget chain to RCE',
    symptom:
      'The app deserializes attacker-controllable data with a native/unsafe deserializer (Java, .NET, PHP, Python pickle, Ruby), enabling object injection and, via gadget chains, remote code execution.',
    procedure:
      'Locate serialized blobs (cookies, view state, cache, message queues) by their magic bytes/format (Java AC ED 00 05, PHP O:, .NET __VIEWSTATE, base64 pickle). Identify the framework and available gadget libraries, then build a chain with a tool like ysoserial (Java) / ysoserial.net / phpggc. Deliver the payload to the sink and confirm code execution out-of-band.',
    whenToUse: 'Any sink that reconstructs objects from client-supplied bytes with an unsafe deserializer.',
    confirmationSignal: 'A crafted serialized payload triggers an out-of-band callback or command execution on the server.',
    preconditions: ['untrusted data passed to a native/unsafe deserializer', 'gadget classes on the classpath'],
    appliesTo: ['Java', '.NET (ViewState)', 'PHP', 'Python pickle', 'Ruby Marshal'],
    cwe: [502, 94],
    chainsWith: ['rce'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/deserialization',
        title: 'Insecure deserialization',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['prototype-pollution'],
    title: 'Server-side prototype pollution via __proto__ in JSON body',
    symptom:
      'A recursive merge/clone of a JSON request body lets keys like __proto__ or constructor.prototype write onto Object.prototype, changing application behavior globally (auth bypass, DoS, or gadget-driven RCE).',
    procedure:
      'Send a JSON body containing {"__proto__": {"polluted": true}} (and constructor.prototype variants) to endpoints that merge user input into config/options objects. Probe for a reflected polluted property in a later response or altered behavior. Escalate with known gadgets in the framework/template engine (e.g. Node child_process options, EJS/Handlebars) to reach RCE, or set flags that bypass authorization checks.',
    whenToUse: 'Node.js endpoints that deep-merge, clone, or assign user-supplied objects into shared config.',
    confirmationSignal: 'A property set via __proto__ appears on unrelated objects/responses, or app behavior flips globally (privilege flag, template gadget fires).',
    preconditions: ['recursive merge/assign of untrusted keys', 'no key filtering for __proto__/constructor'],
    appliesTo: ['Node.js', 'Lodash merge', 'Express body parsers', 'template engines'],
    cwe: [1321, 915],
    chainsWith: ['mass-assignment', 'rce'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/prototype-pollution',
        title: 'Prototype pollution',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['request-smuggling'],
    title: 'HTTP request smuggling via CL.TE / TE.CL desync',
    symptom:
      'A front-end proxy and back-end server disagree on where one request ends (Content-Length vs Transfer-Encoding), so an attacker can prefix bytes onto the next user’s request.',
    procedure:
      'Send crafted requests with both Content-Length and Transfer-Encoding: chunked (obfuscating TE so only one hop honors it). Use timing-based detection first (a partial chunked body stalls the vulnerable path). Confirm with a controlled probe that captures another request or returns a smuggled response. Escalate to request queue poisoning, cache poisoning, or bypassing front-end access controls.',
    whenToUse: 'Multi-hop deployments (CDN/proxy -> origin) where the two ends may parse framing differently.',
    confirmationSignal: 'A smuggled prefix reliably affects a subsequent request (captured victim request, poisoned response, or a delayed-timing oracle).',
    preconditions: ['front-end and back-end parse message framing differently', 'connection reuse to the back-end'],
    appliesTo: ['nginx', 'HAProxy', 'CDNs', 'Node.js', 'legacy app servers'],
    cwe: [444],
    chainsWith: ['cache-poisoning', '403-bypass'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/request-smuggling',
        title: 'HTTP request smuggling',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['mass-assignment'],
    title: 'Mass assignment of privileged fields on create/update',
    symptom:
      'An object create/update endpoint binds the whole request body to the model, so adding fields the UI never shows (role, isAdmin, verified, balance, ownerId) writes them straight through.',
    procedure:
      'Capture a normal create/update and diff the model’s full field set (from GraphQL introspection, API docs, or error messages). Add sensitive fields to the body (role: admin, emailVerified: true, price: 0, userId of another tenant) and resend. Confirm the privileged field was persisted despite not being an intended input.',
    whenToUse: 'REST/GraphQL write endpoints that bind request bodies to ORM models without an allowlist.',
    confirmationSignal: 'A field the client should not control (e.g. role/isAdmin/price) is accepted and persisted, changing authorization or value.',
    preconditions: ['request body bound to model without field allowlist', 'sensitive fields writable'],
    appliesTo: ['Rails', 'Django REST Framework', 'Spring', 'Sequelize/Mongoose'],
    cwe: [915, 639],
    chainsWith: ['idor', 'prototype-pollution'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
        title: 'OWASP Mass Assignment Cheat Sheet',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['host-header'],
    title: 'Password reset poisoning via X-Forwarded-Host',
    symptom:
      'The password-reset email builds its reset link from the request host, and the app trusts a proxy header to derive it, so an attacker can make the emailed link point at an attacker domain and capture the victim’s reset token.',
    procedure:
      'Trigger a password reset for the victim while overriding the host the app uses to build the link. If the Host header is validated, try X-Forwarded-Host: attacker.com (and X-Forwarded-Server / X-Host / a duplicate Host header). The reset email’s link host is taken from X-Forwarded-Host, so the token-bearing URL now points at attacker.com. When the victim clicks it, their browser sends the reset token to the attacker, who replays it to set a new password.',
    whenToUse: 'Password-reset and email-link flows that construct absolute URLs from the incoming request host instead of a fixed configured base URL.',
    confirmationSignal: 'The reset link in the delivered email uses the attacker-supplied host (X-Forwarded-Host), so the reset token is sent to the attacker when the link is followed.',
    preconditions: ['reset link host derived from request headers', 'app trusts X-Forwarded-Host / Host from the client'],
    appliesTo: ['Django', 'Rails', 'Laravel', 'Flask', 'Node.js'],
    cwe: [640, 644, 601],
    chainsWith: ['open-redirect', 'cache-poisoning'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning',
        title: 'Password reset poisoning',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Bugport HTTP-parser-desync pair (cross-linked via chainsWith).
  // -------------------------------------------------------------------------
  {
    namespaces: ['403-bypass'],
    title: 'HTTP parser desync: proxy ACL (403) bypass via trailing trim byte',
    symptom:
      'A reverse proxy (nginx) returns 403 for a path such as /admin, but appending a trailing byte the backend trims — while the proxy keeps it in the path — yields a response that materially differs from the same request without the byte (a non-403 status, a different body/headers/cookies, or a noticeably higher latency). Proxy and backend disagree on the normalized path.',
    procedure:
      'Identify the proxy path ACL (e.g. nginx `location = /admin { deny all; }`). Fingerprint the backend framework, then append the framework-specific trailing byte the backend trims but the proxy keeps: Node.js/Express trims `\\x09 \\xa0 \\x0c`, Flask trims `\\x85 \\xa0 \\x1f \\x1e \\x1d \\x1c \\x0c \\x0b \\x09`, Spring trims `\\x09` (or accepts a matrix `;`). Send a raw request line like `GET /admin\\xa0 HTTP/1.1`; nginx sees `/admin\\xa0` (no exact ACL match) and forwards it, and the backend strips the byte and serves `/admin`.',
    whenToUse:
      'Proxy enforces an exact-match path ACL (e.g. nginx `location = /admin { deny all; }`) in front of a different-language backend (Node/Flask/Spring) that strips trailing bytes.',
    confirmationSignal:
      'Compare the bypass request against a baseline request WITHOUT the trailing byte; a successful desync is a DIVERGENCE from that baseline, not a guaranteed 200 (the backend may still enforce its own auth and answer 401/302/404). Any of the following indicates the proxy ACL was bypassed and the backend is now handling the path: (1) a status other than the proxy 403 — the request is being answered by whatever sits directly behind the proxy; (2) a response whose body, headers, or cookies differ from the un-bypassed request (different HTML, Set-Cookie, framework/version headers, etc.), showing the backend processed it; (3) a noticeably higher response latency than the un-bypassed request, suggesting the proxy forwarded it to the backend for further processing.',
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
    ]
  },
  {
    namespaces: ['cache-poisoning'],
    title: 'HTTP parser desync: cache poisoning via dual Host + control byte',
    symptom:
      'A cache in front of an origin (e.g. S3 behind Varnish/Akamai) serves attacker-controlled content for a legitimate host. Two Host headers are sent; the first is prefixed with a control byte the cache treats as an unparseable header name but the origin strips — so the cache keys on the legitimate Host while the origin honours the attacker Host.',
    procedure:
      'Send a request with dual Host headers where the first is prefixed with a byte S3 ignores in header names (`\\x1d`, `\\x1c`, `\\x1f`): e.g. `GET / HTTP/1.1` then `\\x1dHost: evilbucket.com` then `Host: example.bucket.com`. The cache uses the second (valid) `Host` for the cache key; S3 strips the `\\x1d` and honours the first Host, serving evilbucket content; the cache stores that response under the legitimate key.',
    whenToUse:
      'A caching layer keys responses on the Host header and forwards to an origin (S3) that ignores certain control bytes in header names.',
    confirmationSignal:
      'Subsequent normal requests to the legitimate host/path receive the attacker’s bucket content straight from cache, without the origin being hit.',
    preconditions: [
      'caching layer that keys on the Host header',
      'origin ignores control bytes in header names',
      'ability to send raw duplicate headers'
    ],
    appliesTo: ['Varnish', 'Akamai', 'AWS S3', 'nginx'],
    cwe: [444, 436, 200],
    chainsWith: ['403-bypass', 'ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://blog.bugport.net/exploiting-http-parsers-inconsistencies',
        title: 'Exploiting HTTP Parsers Inconsistencies',
        tier: 1,
        kind: 'writeup'
      }
    ]
  }
];

/**
 * Ingest layer: the real repos + embedding service provided to the ingest
 * service, exactly as at runtime. Each `*Default` already bakes in `DrizzleLive`
 * (which reads `DATABASE_URL`); `EmbeddingServiceLive` reads `EMBEDDING_ENDPOINT`.
 */
const IngestLive = IngestServiceLive.pipe(
  Layer.provide(Layer.mergeAll(RecordRepoDefault, SourceRepoDefault, EmbeddingServiceLive))
);

export const corpusSeed: Seed = {
  name: '0001_corpus',
  run: async (db) => {
    const runtime = ManagedRuntime.make(IngestLive);
    try {
      for (const record of corpus) {
        // Real ingest path: validate -> hash -> dedup -> embed -> insert.
        // Re-runs dedup by content_hash and return the existing id.
        const result = await runtime.runPromise(
          Effect.flatMap(IngestService, (service) => service.ingest(record))
        );
        // Promote staging -> active (no-op if already active on a re-run).
        await db
          .update(records)
          .set({ status: 'active', updatedAt: new Date() })
          .where(eq(records.id, result.id));
      }
    } finally {
      await runtime.dispose();
    }

    // No post-load reindex: the embedding index is HNSW, which builds
    // incrementally as each record is inserted.
  }
};
