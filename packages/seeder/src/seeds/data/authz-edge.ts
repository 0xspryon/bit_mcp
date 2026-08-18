import type { CorpusRecord } from './types';

/**
 * Authorization bypass at the edge / proxy / protocol layer and via trusted
 * headers.
 *
 * Scope: a request is authorized (or refused) by a front-end tier — reverse
 * proxy, CDN, API gateway, WAF, load balancer — that sits in front of a
 * different backend. The bypass is a DESYNC or a MISPLACED-TRUST between the two
 * tiers: they disagree on the normalized path, the backend trusts a header the
 * client actually controls, a protocol upgrade tunnels past the front-end, or
 * the front-end enforcement is simply reachable-around (direct origin, direct
 * internal service).
 *
 * DELIBERATELY DISTINCT from the five records already in `0001_corpus.ts`:
 *   - `403-bypass`      (HTTP parser desync via a trailing trim byte)
 *   - `cache-poisoning` (dual Host + control byte at a cache)
 *   - `host-header`     (X-Forwarded-Host password-reset poisoning)
 *   - `cors-misconfig`  (generic Origin reflection with credentials)
 *   - `request-smuggling` (CL.TE / TE.CL detection + escalation)
 * These records add complementary, non-overlapping techniques.
 *
 * confirmationSignal is DIFFERENTIAL throughout: a successful bypass is a
 * DIVERGENCE from the blocked baseline (a status/body/header/latency that
 * differs from the front-end's refusal), never a guaranteed 200 — the backend
 * may still answer 401/302/404 under its own auth.
 */
export const records: readonly CorpusRecord[] = [
  // -------------------------------------------------------------------------
  // Path / proxy normalization desync — proxy and backend disagree on the path.
  // -------------------------------------------------------------------------
  {
    namespaces: ['path-encoding-decode-differential'],
    title: 'Proxy ACL bypass via encoded slash/dot decode differential (%2f, %2e)',
    symptom:
      'A reverse proxy or WAF matches its path ACL against the RAW request path, but the backend URL-decodes before routing. An encoded separator that the proxy treats as an opaque character resolves, at the backend, to a slash or dot-segment that reaches a protected route the proxy meant to block.',
    procedure:
      'Take a path the front-end refuses (e.g. /admin/config). Re-express its separators with percent-encoding the proxy will not decode but the backend will: %2f for /, %2e for . (e.g. /admin%2fconfig, /%2e%2e/admin, /admin/..%2fconfig). Also try mixing an allowed prefix the proxy trusts with an encoded traversal back into the protected area (/public/..%2fadmin/config). Send each variant and diff the response against the plain blocked request.',
    whenToUse:
      'Front-end enforces a path-prefix or exact-match ACL on the raw URI while the backend (Tomcat, Spring, PHP, a rewrite rule) decodes %-sequences before dispatch.',
    confirmationSignal:
      'The encoded variant diverges from the blocked baseline: a status other than the proxy refusal (401/302/404/200 from the backend instead of the front-end 403), or a body/headers/Set-Cookie that show the backend, not the proxy, answered.',
    preconditions: [
      'front-end path ACL evaluated on the raw (still-encoded) URI',
      'backend URL-decodes before route matching'
    ],
    appliesTo: ['nginx', 'Apache httpd', 'HAProxy', 'AWS ALB', 'Tomcat', 'Spring', 'PHP-FPM'],
    cwe: [436, 863, 22, 288],
    chainsWith: ['path-double-decode-second-order', 'proxy-path-mapping-confusion', '403-bypass'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
        title: 'CVE-2025-0108: PAN-OS Nginx/Apache path-confusion auth bypass',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['path-double-decode-second-order'],
    title: 'ACL bypass via second-order / double URL decoding (%252f, %252e)',
    symptom:
      'The request is decoded more than once across the chain (proxy decode → internal rewrite/redirect decode, or a gateway that decodes then re-dispatches). A double-encoded separator survives the first decode as %2f and is resolved to / on the second, reaching a route neither tier individually intended to expose.',
    procedure:
      'Double-encode the separators of a blocked path: / becomes %252f, . becomes %252e (e.g. /admin%252fusers, /%252e%252e/admin). Try triple-encoding and mixed depth if a value is decoded on an internal redirect (/foo/secret%252ehtml.public). Establish how many decode passes occur by observing which encoding depth first resolves, then diff against the blocked baseline.',
    whenToUse:
      'Multi-stage decode: a gateway/WAF decodes once for its check, and a downstream rewrite, redirect handler, or second proxy hop decodes again before dispatch.',
    confirmationSignal:
      'A specific encoding DEPTH flips the response away from the blocked baseline (the single-encoded and plain forms stay 403, the double-encoded form is handled by the backend), proving an extra decode pass past the ACL.',
    preconditions: ['input decoded more than once along the request path', 'ACL applied at a shallower decode depth than routing'],
    appliesTo: ['nginx', 'Apache httpd', 'API gateways', 'Java servlet filters', 'IIS'],
    cwe: [436, 863, 172],
    chainsWith: ['path-encoding-decode-differential', 'path-traversal'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
        title: 'CVE-2025-0108: PAN-OS Nginx/Apache path-confusion auth bypass',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['path-dotsegment-matrix-acl'],
    title: 'ACL bypass via dot-segment collapse and ;matrix parameters',
    symptom:
      'The proxy ACL sees a path it does not recognize as protected because it contains dot-segments (/./, /../) or a matrix parameter (;foo=bar) that the backend strips or collapses during normalization — so proxy and backend resolve the SAME target from DIFFERENT literal strings.',
    procedure:
      'Rewrite the blocked path so it normalizes to the target only at the backend: dot-segment forms (/admin/./config, /public/../admin/config, /admin/..;/config), and matrix-param forms that Tomcat/Spring drop (/admin;foo=bar/config, /admin/config;jsessionid=x). Combine with a trusted prefix so the proxy prefix-match passes but the backend collapses to /admin. Diff each against the blocked baseline.',
    whenToUse:
      'Servlet-container or framework backends (Tomcat, Spring MVC, Jetty) that collapse dot-segments and strip matrix parameters, fronted by a proxy that path-matches literally.',
    confirmationSignal:
      'The dot-segment/matrix variant diverges from the blocked baseline (backend status/body/headers appear where the proxy 403 stood), while the plain protected path still returns the front-end refusal.',
    preconditions: ['backend normalizes dot-segments / strips ;matrix params', 'proxy matches the ACL on the literal path'],
    appliesTo: ['Tomcat', 'Spring MVC', 'Jetty', 'nginx', 'Apache httpd'],
    cwe: [436, 863, 289],
    chainsWith: ['path-encoding-decode-differential', 'proxy-path-mapping-confusion'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
        title: 'CVE-2025-0108: PAN-OS Nginx/Apache path-confusion auth bypass',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['path-case-suffix-acl'],
    title: 'ACL bypass via case-sensitivity and file-extension/suffix mismatch',
    symptom:
      'The front-end ACL is case-sensitive or extension-sensitive, but the backend route match is not. /Admin, /ADMIN/DeleteUser, or /admin/deleteUser.json reach the same handler the proxy blocked for the exact lowercase, extension-free string.',
    procedure:
      'Vary the case of each path segment (/Admin/Config, /aDmin/config) since many proxies match case-sensitively while the app route (or Windows/IIS filesystem) does not. Append or alter a suffix the backend ignores: a fake extension (/admin/deleteUser.anything, .json, .css) — Spring `useSuffixPatternMatch` maps these back to the base route — or a trailing slash/no-slash flip (/admin vs /admin/). Diff every variant against the exact blocked request.',
    whenToUse:
      'Proxy ACL is a literal, case-sensitive match; the backend framework does case-insensitive routing or suffix-pattern matching (Spring, ASP.NET, IIS).',
    confirmationSignal:
      'A case- or suffix-mutated request diverges from the blocked baseline (the backend handles it — different status/body) while the canonical protected path stays refused at the front-end.',
    preconditions: ['case- or extension-sensitive front-end ACL', 'case-insensitive / suffix-tolerant backend routing'],
    appliesTo: ['Spring MVC', 'ASP.NET', 'IIS', 'nginx', 'Apache httpd'],
    cwe: [178, 863, 289],
    chainsWith: ['path-dotsegment-matrix-acl', 'header-x-original-url'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['nginx-alias-traversal'],
    title: 'Nginx off-by-slash alias traversal to protected files',
    symptom:
      'A `location /assets` block (prefix, no trailing slash) paired with `alias /var/www/assets/` lets a request like /assets../ escape the mapped directory. The path outside the location is concatenated onto the alias, so /assets../<file> reads siblings of the intended folder, including protected files (WEB-INF, .env, source, configs).',
    procedure:
      'Find static roots served via alias (CSS/JS/image dirs). For a known asset like /folder1/folder2/static/main.css, test off-by-slash traversal: /folder1/folder2/static../static/main.css and /folder1../folder1/folder2/static/main.css should return the same body as the direct request. Once confirmed, walk upward (/static../<target>) to reach application source, WEB-INF/web.xml, or credentials files.',
    whenToUse:
      'Nginx with a prefix `location` (no trailing slash) whose `alias` DOES end in a slash — the classic off-by-slash misconfiguration.',
    confirmationSignal:
      'A traversal path (/static../) returns a response IDENTICAL to a legitimate resource fetched normally — proving the escape resolves — and then a protected file outside the static root is returned where a plain request to it is blocked or 404s.',
    preconditions: ['nginx `alias` directive with off-by-slash location/alias mismatch', 'readable sensitive files above the alias root'],
    appliesTo: ['nginx'],
    cwe: [22, 552, 200],
    chainsWith: ['path-traversal', 'proxy-path-mapping-confusion'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://github.com/bayotop/off-by-slash',
        title: 'off-by-slash: detecting nginx alias traversal (Breaking Parser Logic, Orange Tsai)',
        tier: 2,
        kind: 'tool'
      }
    ]
  },
  {
    namespaces: ['merge-slashes-acl'],
    title: 'ACL bypass via double slashes and merge_slashes / location-prefix confusion',
    symptom:
      'The proxy and backend disagree on how repeated or leading slashes collapse. //admin, /%2f/admin, or /./admin/ matches (or dodges) a `location` prefix differently than the backend route, so the ACL prefix comparison and the actual dispatch diverge.',
    procedure:
      'Insert redundant slashes into the blocked path: //admin/config, /admin//config, ///admin. When nginx `merge_slashes off` is set (or the backend merges while the proxy does not), the proxy prefix ACL (`location /admin`) fails to match //admin but the backend still routes it to the admin handler. Also test a leading-slash strip/add against proxied upstreams. Diff each against the single-slash blocked request.',
    whenToUse:
      'A `location`-prefix or path-prefix ACL where proxy and backend apply different slash-merging (nginx `merge_slashes`, gateway path rules vs framework router).',
    confirmationSignal:
      'A multi-slash variant diverges from the blocked single-slash baseline (backend answers it) while the canonical path stays refused, showing the prefix ACL was side-stepped by slash normalization.',
    preconditions: ['prefix-based path ACL', 'proxy vs backend differ on slash merging'],
    appliesTo: ['nginx', 'Apache httpd', 'Envoy', 'API gateways', 'Tomcat'],
    cwe: [436, 863, 289],
    chainsWith: ['path-dotsegment-matrix-acl', 'proxy-path-mapping-confusion'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
        title: 'CVE-2025-0108: PAN-OS Nginx/Apache path-confusion auth bypass',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['proxy-path-mapping-confusion'],
    title: 'Reverse-proxy path-mapping confusion (proxy_pass rewrite vs backend routing)',
    symptom:
      'A reverse proxy maps an external prefix to an internal one (e.g. `location /app/ { proxy_pass http://backend/; }`) and rewrites the path before forwarding. A crafted path desynchronizes the proxy rewrite from the backend router, so a request that looks in-scope externally lands on an out-of-scope internal endpoint (management/admin/actuator) the proxy believed it had walled off.',
    procedure:
      'Map the proxy prefix rules, then craft paths whose rewrite result differs from what the proxy ACL evaluated: traversal after the mapped prefix (/app/..%2f..%2factuator), trailing-slash mismatches in proxy_pass rewriting, and encoded segments that survive rewrite. Target well-known internal routes exposed only behind the proxy (Spring Boot /actuator, /manager, /internal, health/metrics). Diff each against the same request without the confusion.',
    whenToUse:
      'Multi-tier deployments where the proxy rewrites/strips a path prefix before proxy_pass and the backend exposes sensitive routes that are only supposed to be reachable through the mapped prefix.',
    confirmationSignal:
      'A crafted external path yields a response from an internal endpoint that a direct external request cannot reach (management data / actuator JSON / admin markup) — a divergence from both the blocked direct path and the ordinary proxied path.',
    preconditions: ['proxy rewrites the path prefix before forwarding', 'backend exposes internal routes reachable via the mapping'],
    appliesTo: ['nginx', 'Apache httpd', 'Spring Boot', 'Tomcat', 'Kubernetes ingress'],
    cwe: [436, 863, 706],
    chainsWith: ['path-encoding-decode-differential', 'gateway-internal-service-ssrf', 'merge-slashes-acl'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-0108',
        title: 'CVE-2025-0108: PAN-OS Nginx/Apache path-confusion auth bypass',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Trusted-header bypasses — backend trusts a header the client controls.
  // -------------------------------------------------------------------------
  {
    namespaces: ['header-x-original-url'],
    title: 'Front-end ACL bypass via X-Original-URL / X-Rewrite-URL override',
    symptom:
      'The front-end enforces access control on the request line, but the backend framework lets a non-standard header override the effective URL. Requesting an allowed path while smuggling the protected path in X-Original-URL (or X-Rewrite-URL) reaches the blocked endpoint.',
    procedure:
      'Confirm the header is honored: request GET / with `X-Original-URL: /doesnotexist` and check the response changes (404 vs the homepage) — that proves the backend routes on the header. Then send an allowed request line with `X-Original-URL: /admin/deleteUser` (put params in the query string or `X-Original-URL: /admin/deleteUser?username=carlos`). The front-end ACL sees the innocuous path; the backend acts on the header value.',
    whenToUse:
      'Frameworks/servers that support URL-override headers (some IIS/ASP.NET, Symfony, and proxies) sitting behind a front-end that filters on the literal request path.',
    confirmationSignal:
      'The override request diverges from a plain request to the allowed path (the response reflects the OVERRIDDEN path — its body/status/side effect), while a direct request to the protected path returns the front-end refusal.',
    preconditions: ['backend honors X-Original-URL / X-Rewrite-URL', 'front-end ACL evaluated on the request line only'],
    appliesTo: ['IIS/ASP.NET', 'Symfony', 'nginx+backend', 'API gateways'],
    cwe: [862, 863, 288],
    chainsWith: ['path-case-suffix-acl', 'internal-trust-header'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['internal-trust-header'],
    title: 'Backend trusts injected internal identity headers (X-Auth-User, X-Forwarded-User)',
    symptom:
      'An internal service assumes an upstream gateway populates identity/role headers (X-Auth-User, X-Forwarded-User, X-Authenticated-User, X-User-Id, X-Internal, X-Admin) and trusts them. If those headers are not stripped/overwritten at the edge, a client injects them to impersonate a user or assert admin.',
    procedure:
      'Guess the header contract from framework/gateway conventions (X-Forwarded-User, X-Auth-User, X-User-Role, X-Internal-Request, Service-Gateway-*: true style flags). Inject candidate identity/role headers on a normal request and watch for authorization or user-context changes. In desync/SSRF scenarios where the edge normally injects these, the leaked real header names sharpen the guess. Compare against the request without the headers.',
    whenToUse:
      'Zero-trust-gap microservice setups where authentication is centralized at a gateway and downstream services read identity from headers they assume are gateway-authored.',
    confirmationSignal:
      'Adding the identity/role header diverges from the baseline: the response is served as the asserted user/role (different data, elevated action succeeds) where the same request without the header is anonymous or forbidden.',
    preconditions: ['backend trusts identity/role headers', 'edge fails to strip or overwrite client-supplied copies'],
    appliesTo: ['microservices', 'API gateways', 'service meshes', 'nginx auth_request'],
    cwe: [290, 348, 863],
    chainsWith: ['xff-ip-allowlist-bypass', 'smuggling-reveal-internal-headers', 'gateway-internal-service-ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn',
        title: 'HTTP Desync Attacks: Request Smuggling Reborn (Service-Gateway-Is-*-Admin header)',
        tier: 1,
        kind: 'research'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
        title: 'OWASP Authorization Cheat Sheet',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['host-routing-ssrf'],
    title: 'Routing-based SSRF and internal-vhost access via Host / X-Forwarded-Host',
    symptom:
      'The front-end routes upstream based on the Host (or X-Forwarded-Host) header. Supplying an internal hostname or an internal IP in that header makes the trusted front-end connect to an internal service or serve an internal virtual host (admin panel, staging) that is not externally routable.',
    procedure:
      'Send requests varying the Host to internal targets (Host: localhost, Host: 192.168.x.x, Host: internal-admin) and to known internal service names; also try X-Forwarded-Host and a duplicate Host. Watch for the front-end proxying to an internal backend (different app, internal-only vhost, or an SSRF callback from the front-end IP). This is authorization bypass by making the trusted edge issue the internal request for you. Compare each against the ordinary Host value.',
    whenToUse:
      'Load balancers / CDNs / proxies that select the upstream from the Host header, especially when internal vhosts share the front-end.',
    confirmationSignal:
      'A modified Host diverges from the baseline: an internal vhost/app is served, or an out-of-band request arrives from the front-end IP for an attacker hostname — content unreachable with the normal Host header.',
    preconditions: ['upstream routing derived from Host/X-Forwarded-Host', 'internal vhosts/services reachable from the front-end'],
    appliesTo: ['nginx', 'HAProxy', 'CDNs', 'AWS ALB', 'Kubernetes ingress'],
    cwe: [290, 918, 863],
    chainsWith: ['duplicate-host-header-routing', 'gateway-internal-service-ssrf', 'ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/host-header',
        title: 'HTTP Host header attacks',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['duplicate-host-header-routing'],
    title: 'Internal-vhost access via ambiguous / duplicate Host headers',
    symptom:
      'Front-end and backend pick a DIFFERENT Host when two are present (or when Host is line-wrapped/indented). The front-end validates and routes on one value; the backend honors the other, so a request that passes front-end host validation is served by an internal virtual host.',
    procedure:
      'Send two Host headers (first legitimate, second internal, then swapped) and observe which one drives routing at each tier. Try line-wrapped/indented Host continuations and an absolute-form request line combined with a Host header. Aim the "backend-honored" value at an internal-only vhost (admin.internal, staging). Diff against a single, legitimate Host header. (Distinct from the cache-poisoning technique: no control byte, and the goal is authz routing, not a poisoned cache key.)',
    whenToUse:
      'Deployments where duplicate/ambiguous Host handling differs between the validating front-end and the routing backend.',
    confirmationSignal:
      'The dual/ambiguous-Host request diverges from the single-Host baseline by returning an internal vhost’s content (different app/markup/headers) that the validated Host alone never yields.',
    preconditions: ['front-end and backend disagree on which Host wins', 'internal vhost co-hosted behind the front-end'],
    appliesTo: ['nginx', 'Apache httpd', 'Varnish', 'CDNs'],
    cwe: [436, 290, 863],
    chainsWith: ['host-routing-ssrf', 'cache-poisoning', 'absolute-uri-request-line'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/host-header',
        title: 'HTTP Host header attacks',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['absolute-uri-request-line'],
    title: 'Proxy routing/ACL bypass via absolute-form request line',
    symptom:
      'The proxy makes routing or access decisions from the Host header or the path, but the backend derives the target from an absolute-form request line (GET http://internal-host/admin HTTP/1.1). The two disagree on the effective target, side-stepping the front-end decision.',
    procedure:
      'Send an absolute-URI request line pointing at an internal host/path (GET https://internal-admin/console HTTP/1.1) while keeping an innocuous Host header for the front-end. Also test an absolute URI whose authority differs from Host, and an absolute URI to override the path the ACL matched. Observe whether the backend resolves the absolute URI instead of the Host/path the proxy evaluated. Diff against the origin-form equivalent.',
    whenToUse:
      'Proxies/servers that accept absolute-form request targets and forward or resolve them differently from how the front-end ACL parsed the request.',
    confirmationSignal:
      'The absolute-form request diverges from the origin-form baseline: the backend serves the absolute-URI target (internal host/path) where the front-end ACL, keyed on Host/path, would have refused it.',
    preconditions: ['backend honors absolute-form request-line authority/path', 'front-end decision keyed on Host header or origin-form path'],
    appliesTo: ['nginx', 'Apache httpd', 'forward/reverse proxies', 'Java app servers'],
    cwe: [436, 290, 863],
    chainsWith: ['duplicate-host-header-routing', 'host-routing-ssrf'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://portswigger.net/web-security/host-header',
        title: 'HTTP Host header attacks',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['referer-based-acl-bypass'],
    title: 'Referer-based access control bypass on admin sub-pages',
    symptom:
      'An app protects admin sub-actions by checking the Referer header instead of re-authorizing (e.g. it lets /admin/deleteUser through when Referer is /admin). The Referer is fully client-controlled, so it is trivially forged.',
    procedure:
      'Locate actions that appear reachable only from an admin page. Request the sensitive sub-action directly with `Referer: https://target/admin` (matching whatever the check expects). If access is granted, the control is Referer-based. Test as a low-privilege user to confirm privilege escalation rather than just navigation. Compare with the same request lacking (or with a foreign) Referer.',
    whenToUse:
      'Platform/framework access control that gates sub-pages on the Referer header rather than a server-side session role check.',
    confirmationSignal:
      'Supplying the expected Referer diverges from the baseline (the action succeeds / privileged content returns) where the same request without that Referer is refused — proving the decision keys on the forgeable header.',
    preconditions: ['access control derived from the Referer header', 'no independent server-side authorization on the action'],
    appliesTo: ['server-rendered apps', 'admin panels', 'legacy frameworks'],
    cwe: [290, 807, 863],
    chainsWith: ['header-x-original-url', 'path-case-suffix-acl'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Protocol-level desync / tunneling past the front-end.
  // -------------------------------------------------------------------------
  {
    namespaces: ['http2-downgrade-desync'],
    title: 'HTTP/2 downgrade desync (H2.CL / H2.TE) to bypass front-end controls',
    symptom:
      'The front-end speaks HTTP/2 to clients but downgrades to HTTP/1.1 upstream, rebuilding Content-Length / Transfer-Encoding from the HTTP/2 message. Because HTTP/2 carries its own length, an attacker-supplied CL or TE that the front-end ignored is honored by the HTTP/1.1 backend, desynchronizing message boundaries.',
    procedure:
      'Confirm HTTP/2 to the front-end and an HTTP/1.1 downgrade upstream. For H2.CL, send an HTTP/2 request with an explicit `content-length` smaller/larger than the real body; the front-end trusts the frame length, the downgraded backend trusts CL and mis-splits the stream. For H2.TE, inject `transfer-encoding: chunked` (which HTTP/2 forbids as connection-specific) and see if the backend honors it post-downgrade. Use a smuggled prefix to reach a restricted path or poison the next request.',
    whenToUse:
      'Edge terminates HTTP/2 and forwards HTTP/1.1, and does not strictly re-derive framing — enabling a desync distinct from a same-protocol CL.TE/TE.CL smuggle.',
    confirmationSignal:
      'A smuggled prefix reliably affects a subsequent request (captured victim data, a poisoned/mismatched response, or a timing stall) — a divergence produced only via the HTTP/2 framing the front-end failed to normalize on downgrade.',
    preconditions: ['front-end HTTP/2 with HTTP/1.1 downgrade upstream', 'framing not fully re-derived from the HTTP/2 message'],
    appliesTo: ['CDNs', 'nginx', 'HAProxy', 'Envoy', 'load balancers'],
    cwe: [444, 436, 863],
    chainsWith: ['h2c-smuggling', 'request-smuggling', 'cache-poisoning'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/research/http2',
        title: 'HTTP/2: The Sequel is Always Worse (James Kettle)',
        tier: 1,
        kind: 'research'
      }
    ]
  },
  {
    namespaces: ['h2c-smuggling'],
    title: 'h2c smuggling: upgrade tunnel past a reverse-proxy ACL',
    symptom:
      'A reverse proxy blindly forwards an HTTP/1.1 Upgrade request. If it forwards `Upgrade: h2c` and the backend accepts the cleartext-HTTP/2 upgrade (101 Switching Protocols), the proxy turns the connection into an opaque TCP tunnel and is no longer content-aware — subsequent requests reach the backend unfiltered.',
    procedure:
      'Send a request with `Upgrade: h2c`, `HTTP2-Settings: <base64>`, and `Connection: Upgrade, HTTP2-Settings` through the proxy. If a 101 comes back, multiplex fresh HTTP/2 requests over the now-tunneled connection aimed at paths the proxy ACL blocks (/admin, internal APIs). Tools like h2csmuggler automate the upgrade + tunnel. Compare tunneled requests to the same paths sent normally through the proxy.',
    whenToUse:
      'Proxies that treat h2c upgrades like WebSocket upgrades and pass Upgrade/Connection through to an h2c-capable backend.',
    confirmationSignal:
      'Requests sent inside the h2c tunnel diverge from the proxied baseline: the proxy-enforced 403/routing rules no longer apply (backend answers restricted paths), proving the proxy dropped out of the request path.',
    preconditions: ['proxy forwards Upgrade/Connection headers unmodified', 'backend supports h2c prior-knowledge/upgrade'],
    appliesTo: ['nginx', 'Envoy', 'HAProxy', 'AWS ALB', 'Go/Node backends'],
    cwe: [444, 441, 668],
    chainsWith: ['http2-downgrade-desync', 'gateway-internal-service-ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://bishopfox.com/blog/h2c-smuggling-request',
        title: 'h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext (Bishop Fox)',
        tier: 1,
        kind: 'research'
      }
    ]
  },
  {
    namespaces: ['ajp-ghostcat'],
    title: 'Ghostcat: AJP connector trust bypass to read protected files (CVE-2020-1938)',
    symptom:
      'Tomcat exposes its AJP connector (default 8009), which it trusts more than HTTP. An attacker who can reach the AJP port sets request attributes to make Tomcat read or JSP-process arbitrary files under the app root — including WEB-INF resources the HTTP layer protects — bypassing the front-end entirely.',
    procedure:
      'Detect a reachable AJP port (8009) not fronted by the HTTP proxy. Using an AJP client, set the javax.servlet.include.* attributes (request_uri / path_info / servlet_path) to point at protected files (/WEB-INF/web.xml, config, source). Read them directly; if file upload exists, the same primitive can JSP-process an uploaded file for RCE. Confirm files are returned that the HTTP endpoint refuses.',
    whenToUse:
      'Tomcat 6/7/8/9 (pre-fix) or reverse-proxy setups where the AJP connector is enabled and network-reachable rather than bound to loopback.',
    confirmationSignal:
      'AJP-attribute requests return protected file contents (WEB-INF/web.xml, credentials, source) that the equivalent HTTP request blocks or 404s — a divergence proving the AJP path bypassed the HTTP-layer control.',
    preconditions: ['reachable AJP connector (default 8009)', 'unpatched Tomcat honoring include attributes'],
    appliesTo: ['Apache Tomcat', 'reverse-proxied Java apps'],
    cwe: [668, 552, 290],
    chainsWith: ['nginx-alias-traversal', 'gateway-internal-service-ssrf'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-1938',
        title: 'CVE-2020-1938: Ghostcat — Tomcat AJP file read/inclusion',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['smuggling-reveal-internal-headers'],
    title: 'Desync reflection to leak and replay internal auth headers',
    symptom:
      'A front-end appends internal, trusted headers (auth flags, real client IP, gateway identity) before forwarding upstream. A desync/reflection primitive causes those internal headers to be echoed back, exposing the exact names/values the backend trusts — which are then replayed to forge internal trust.',
    procedure:
      'With a desync foothold, smuggle a request whose body reflects the following request (e.g. a search/echo endpoint), so the victim/next request — carrying the front-end-injected internal headers — is reflected back to you. Read the leaked header names (X-Forwarded-For, gateway auth flags, identity headers). Then send those exact headers directly (see internal-trust-header) to assert the trusted context. Confirm against a request without them.',
    whenToUse:
      'When a smuggling/desync foothold exists and the front-end injects internal trust headers you want to enumerate and replay.',
    confirmationSignal:
      'The reflected response reveals internal header names/values that never appear in a normal response; replaying them then diverges from baseline by granting the internal/admin context.',
    preconditions: ['desync/reflection foothold', 'front-end injects internal trust headers upstream'],
    appliesTo: ['CDNs', 'API gateways', 'nginx', 'microservices'],
    cwe: [444, 290, 200],
    chainsWith: ['internal-trust-header', 'request-smuggling', 'http2-downgrade-desync'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn',
        title: 'HTTP Desync Attacks: Request Smuggling Reborn (leaking internal headers)',
        tier: 1,
        kind: 'research'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // API-protocol authorization gaps (WebSocket, GraphQL, gRPC).
  // -------------------------------------------------------------------------
  {
    namespaces: ['websocket-message-authz'],
    title: 'WebSocket per-message authorization missing after authenticated handshake',
    symptom:
      'The WebSocket handshake is authenticated (session cookie / token), but individual messages over the socket are not re-authorized. A connected user sends messages that act on other users’ objects or invoke privileged operations the UI never offers.',
    procedure:
      'Establish an authenticated socket as a low-privilege user and enumerate the message schema (action/type + id fields). Replay messages targeting other users’ object ids, and craft messages for privileged actions (role changes, admin commands) not exposed in the client. Because authorization was decided only at the handshake, the server may act on any message the session can send. Compare with the intended-scope message.',
    whenToUse:
      'Real-time features (chat, dashboards, collaboration, trading) where authorization is checked at connect time but not per message/action.',
    confirmationSignal:
      'A message diverges from the intended scope: it returns or mutates another user’s data, or performs a privileged action, where the same account is denied over the equivalent HTTP endpoint.',
    preconditions: ['authorization enforced only at the handshake', 'no per-message ownership/role check'],
    appliesTo: ['Socket.IO', 'ws (Node)', 'SignalR', 'Django Channels', 'Phoenix Channels'],
    cwe: [862, 863, 306],
    chainsWith: ['cross-site-websocket-hijacking', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/websockets',
        title: 'Testing for WebSockets security vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['cross-site-websocket-hijacking'],
    title: 'Cross-site WebSocket hijacking (CSWSH) via unvalidated handshake Origin',
    symptom:
      'The WebSocket handshake authenticates with cookies but does not use CSRF tokens or validate the Origin. An attacker page opens a socket to the target; the victim’s cookies ride along, so the attacker’s script reads/sends messages in the victim’s authenticated session.',
    procedure:
      'Check the handshake for an anti-CSRF token and Origin validation. If the socket is established with only ambient cookies, host a page that opens a WebSocket to the target from an arbitrary origin, then exfiltrate messages the server pushes (or send privileged messages) using the victim’s session. Confirm the attacker origin can complete the handshake and exchange authenticated data.',
    whenToUse:
      'Cookie-authenticated WebSocket endpoints lacking a CSRF token on the handshake and lacking strict Origin checks.',
    confirmationSignal:
      'A handshake initiated from an attacker origin diverges from the expected same-origin baseline: it succeeds and returns authenticated data / accepts privileged messages using only the victim’s cookies.',
    preconditions: ['cookie-authenticated handshake', 'no CSRF token / no Origin validation on upgrade'],
    appliesTo: ['Socket.IO', 'ws (Node)', 'SignalR', 'Spring WebSocket', 'Phoenix Channels'],
    cwe: [352, 1385, 346],
    chainsWith: ['websocket-message-authz', 'csrf', 'cors-allowlisted-subdomain-trust'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/websockets',
        title: 'Testing for WebSockets security vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['graphql-field-authz'],
    title: 'GraphQL field/node authorization gap surfaced via introspection',
    symptom:
      'Introspection (or field suggestions) exposes the full schema, and authorization is enforced unevenly — at the top-level query but not on nested nodes, or on some mutations but not others. Attackers reach under-guarded fields/mutations the UI never calls.',
    procedure:
      'Introspect the schema (or reconstruct it via suggestion errors). Inventory mutations and sensitive queries, then send each directly as a low-privilege user. Test edge-vs-node authorization: fetch a permitted list, then request a sensitive nested field on those nodes (e.g. connection edges authorized but the node’s private fields not). Probe object references for IDOR. Compare each field/mutation against the expected denial.',
    whenToUse:
      'GraphQL APIs relying on resolver-level checks, where introspection reveals fields/mutations that individual resolvers fail to authorize.',
    confirmationSignal:
      'A direct field/mutation call diverges from the intended denial: it returns private data or performs a privileged mutation for an account that should not be authorized, exposing an unguarded resolver/node.',
    preconditions: ['introspection or suggestions enabled', 'authorization enforced inconsistently across resolvers/nodes'],
    appliesTo: ['Apollo Server', 'graphql-js', 'Hasura', 'GraphQL Yoga', 'Graphene'],
    cwe: [862, 863, 285],
    chainsWith: ['graphql-batching-authz', 'idor', 'mass-assignment'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        title: 'OWASP GraphQL Cheat Sheet (authorize edges and nodes)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['grpc-reflection-authz'],
    title: 'gRPC server reflection enumeration to reach unguarded methods',
    symptom:
      'A gRPC service ships with server reflection enabled and is reachable (often assumed "internal-only"). Reflection lists every service, method, and message type; some methods enforce authorization only at the service level or not at all, so method-level calls succeed unauthenticated.',
    procedure:
      'Point grpcurl at the endpoint with reflection (grpcurl -plaintext host:port list / describe) to enumerate services and methods. Call sensitive methods directly, testing both without credentials and with a low-privilege token. Check method-level access control, not just service-level — internal/admin RPCs frequently lack per-method checks. Compare each call against the expected auth requirement.',
    whenToUse:
      'gRPC / gRPC-web services exposed beyond a trusted network with reflection on and inconsistent per-method authorization.',
    confirmationSignal:
      'A reflected method call diverges from the expected denial: it returns data or performs an action without proper credentials, where the service was assumed to require them.',
    preconditions: ['server reflection enabled and reachable', 'authorization missing or only service-level for some methods'],
    appliesTo: ['gRPC (Go/Java/.NET/Node)', 'gRPC-web', 'Envoy gRPC'],
    cwe: [862, 863, 306],
    chainsWith: ['gateway-internal-service-ssrf', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://grpc.io/docs/guides/reflection/',
        title: 'gRPC Server Reflection (disable in production)',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Reachable-around the edge: origin, gateway, cache.
  // -------------------------------------------------------------------------
  {
    namespaces: ['origin-ip-exposure'],
    title: 'CDN/WAF auth enforced at the edge but origin directly reachable',
    symptom:
      'Access control, WAF rules, or auth (e.g. Cloudflare Access, signed edge cookies) are enforced only at the CDN/edge, while the origin server accepts direct connections. Reaching the origin IP bypasses every edge control.',
    procedure:
      'Discover the origin IP: certificate transparency logs (Censys/crt.sh), historical DNS (SecurityTrails, DNSDumpster), transactional-email headers (Return-Path/Received), non-proxied subdomains (mail, dev, legacy), and SSRF/pingback leaks. Verify by sending the target Host header to the candidate IP and matching the app response. Then replay edge-gated requests straight to the origin. Compare origin responses to the edge-enforced ones.',
    whenToUse:
      'Any deployment where security depends on traffic passing through a CDN/WAF but the origin is not restricted to the CDN’s IP ranges (or mTLS-authenticated origin pulls).',
    confirmationSignal:
      'A request to the origin IP diverges from the edge baseline: WAF/auth/rate-limit no longer applies (blocked payloads, edge-gated paths, or throttled actions now succeed) because the edge is out of the path.',
    preconditions: ['origin accepts direct (non-edge) connections', 'security controls enforced only at the edge'],
    appliesTo: ['Cloudflare', 'Akamai', 'Fastly', 'AWS CloudFront', 'any CDN/WAF'],
    cwe: [668, 284, 348],
    chainsWith: ['gateway-internal-service-ssrf', 'subdomain-takeover'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://blog.detectify.com/industry-insights/bypassing-cloudflare-waf-with-the-origin-server-ip-address/',
        title: 'Bypassing Cloudflare WAF with the origin server IP address (Detectify)',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['gateway-internal-service-ssrf'],
    title: 'API gateway validates auth but internal service reachable via SSRF pivot',
    symptom:
      'An API gateway authenticates/authorizes and then calls internal microservices that trust the gateway implicitly and have no auth of their own. An SSRF (or any request that reaches the internal network) hits those services directly, bypassing all gateway-side authorization.',
    procedure:
      'Find an SSRF or request-forwarding primitive that can address the internal network (service DNS names, RFC1918, cluster IPs, 169.254 link-local). Enumerate internal service endpoints (from the gateway’s routes, service discovery, or reflection) and call their privileged operations directly. Because the service assumes the gateway already authorized the caller, the internal request is honored. Compare direct internal calls with gateway-mediated ones.',
    whenToUse:
      'Gateway-plus-microservices architectures where internal services are unauthenticated and depend on the gateway for all access control, and an SSRF/forwarding foothold exists.',
    confirmationSignal:
      'A request reaching the internal service directly diverges from the gateway baseline: privileged operations succeed without the gateway’s auth, returning internal data/actions the external path forbids.',
    preconditions: ['internal services trust the gateway and lack their own authz', 'a request primitive reaches the internal network'],
    appliesTo: ['Kong', 'AWS API Gateway', 'Kubernetes', 'service meshes', 'microservices'],
    cwe: [918, 668, 306],
    chainsWith: ['ssrf', 'host-routing-ssrf', 'grpc-reflection-authz', 'internal-trust-header'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/host-header',
        title: 'HTTP Host header attacks (routing-based SSRF to internal systems)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
        title: 'OWASP Authorization Cheat Sheet (enforce authorization server-side/at the gateway)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['web-cache-deception'],
    title: 'Web cache deception: cache an authenticated response for public retrieval',
    symptom:
      'Cache and origin map a URL to resources differently. An authenticated, personalized response is fetched via a URL that looks like a static asset to the cache (e.g. /account/settings/foo.css); the cache stores it, and anyone requesting that URL then retrieves the victim’s private data.',
    procedure:
      'Find a personalized endpoint (/account, /profile, /api/me). Append a fake static-file segment the origin ignores but the cache caches by extension: /account/settings/wcd.css (or .js/.jpg), and variants using path/encoded-delimiter confusion. Load it in the victim context, then re-request the same URL unauthenticated (or as another user) and check the cached body. Confirm the cache served personalized data without auth.',
    whenToUse:
      'A caching layer that caches by file extension/static heuristics in front of an origin whose routing ignores the trailing segment (REST-style path mapping).',
    confirmationSignal:
      'An unauthenticated request to the crafted URL diverges from its normal denial by returning another user’s cached personalized response — served from cache without the victim’s session.',
    preconditions: ['cache/origin disagree on URL-to-resource mapping', 'personalized responses become cacheable via the crafted path'],
    appliesTo: ['Cloudflare', 'Akamai', 'Varnish', 'CloudFront', 'nginx cache'],
    cwe: [525, 639, 200],
    chainsWith: ['path-encoding-decode-differential', 'cache-poisoning'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/web-cache-deception',
        title: 'Web cache deception',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // CORS trust-chain and cross-tier authorization race.
  // -------------------------------------------------------------------------
  {
    namespaces: ['cors-allowlisted-subdomain-trust'],
    title: 'Credentialed CORS exfiltration via a compromisable allowlisted subdomain',
    symptom:
      'The API returns Access-Control-Allow-Credentials: true and dynamically reflects any Origin that matches an allowlist of the org’s own subdomains. If ANY allowlisted subdomain is XSS-able or takeover-able, that origin is trusted to read authenticated cross-origin responses. (Distinct from generic arbitrary-origin reflection: the trust is scoped, but a weak sibling origin breaks it.)',
    procedure:
      'Map which origins the ACAO allowlist trusts (send crafted Origin values; note which are echoed with credentials true). Identify a trusted subdomain you can control — a stored/reflected XSS, a dangling DNS/subdomain takeover, or an open subdomain. From that origin, script a credentialed fetch to the sensitive endpoint and exfiltrate the body. Confirm the response is readable from the compromised-but-allowlisted origin.',
    whenToUse:
      'Credentialed CORS APIs that trust an allowlist of first-party subdomains, when one such subdomain is attacker-controllable.',
    confirmationSignal:
      'A credentialed cross-origin read from the compromised allowlisted subdomain diverges from the arbitrary-origin baseline (which is refused): ACAO echoes the trusted subdomain with credentials true and the authenticated body is readable there.',
    preconditions: ['Access-Control-Allow-Credentials: true with subdomain-allowlist matching', 'a trusted subdomain is XSS-able or takeover-able'],
    appliesTo: ['REST APIs', 'SPAs with cookie auth', 'multi-subdomain platforms'],
    cwe: [942, 346, 863],
    chainsWith: ['subdomain-takeover', 'xss-stored', 'cors-misconfig'],
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
    namespaces: ['authz-toctou-revocation'],
    title: 'TOCTOU authorization race: revoked/not-yet-enforced permission window',
    symptom:
      'Authorization is checked at one instant but enforced/committed at another, leaving a sub-state where access is granted before a constraint applies. A permission just revoked, a token just invalidated, or an MFA/step-up not yet enforced still authorizes concurrent in-flight requests.',
    procedure:
      'Identify a multi-step or transition flow: permission/role revocation, session logout/token rotation, MFA enrollment, or an approval that flips a flag. Fire the protected request concurrently with (or immediately around) the state transition — single-packet / last-byte-sync to align timing — so it passes the check before enforcement lands. Look for the sub-state where a logged-in-but-MFA-not-enforced session, or a revoked-but-in-flight grant, is still honored. Confirm the invariant was violated.',
    whenToUse:
      'Non-atomic check-then-enforce authorization: revocation, session/token transitions, step-up auth windows, or approval state machines.',
    confirmationSignal:
      'A request that should be denied post-transition instead succeeds when raced against it — a divergence showing access survived into a state (revoked/pre-enforcement) where the sequential request is refused.',
    preconditions: ['authorization decision and enforcement are not atomic', 'endpoint accepts concurrent/in-flight requests during the transition'],
    appliesTo: ['session/token systems', 'MFA/step-up flows', 'RBAC revocation', 'approval workflows'],
    cwe: [367, 362, 863],
    chainsWith: ['race-condition', 'graphql-batching-authz'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/race-conditions',
        title: 'Race conditions (multi-step/state-machine and TOCTOU authorization)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  }
];
