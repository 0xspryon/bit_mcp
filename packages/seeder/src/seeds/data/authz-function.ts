import type { CorpusRecord } from './types';

/**
 * Broken Function Level Authorization (BFLA) + access-control-model bypass.
 *
 * Each record is a DISTINCT fundamental technique for invoking an endpoint,
 * function, action, or management interface that the caller's role or
 * privilege level should not be able to reach. This is the *function*-level
 * counterpart to the object-level (IDOR/BOLA) and privilege-flag
 * (mass-assignment) records already in `0001_corpus.ts` — those are referenced
 * via `chainsWith` rather than duplicated here.
 *
 * Every `confirmationSignal` is DIFFERENTIAL: the proof is that the SAME
 * request behaves differently across privilege levels or against a baseline
 * (a low-privileged / unauthenticated session succeeds where it should be
 * refused, or a variant request diverges from the un-tampered one), never a
 * bare "200 OK".
 */
export const records: readonly CorpusRecord[] = [
  {
    namespaces: ['bfla-vertical-privesc'],
    title: 'Vertical privilege escalation: invoking an admin-only function as a low-privileged user',
    symptom:
      'An administrative operation (delete user, change another account, read all records) is exposed by an endpoint that authenticates the caller but never checks their role. A standard user replaying the admin request succeeds.',
    procedure:
      'Map the application as a high-privileged role and capture the admin-only requests (endpoints, verbs, bodies). Re-issue each captured request verbatim while authenticated as a low-privileged user (swap only the session token/cookie). Because BFLA is about functions rather than objects, also enumerate admin operations you have not seen — /api/admin/v1/users/all, POST /api/invites/new with {"role":"admin"} — and call them directly. Where roles are hierarchical, test each function as every role below the intended one.',
    whenToUse:
      'Any application with more than one privilege tier where administrative or elevated functions live behind endpoints reachable by lower-tier authenticated sessions.',
    confirmationSignal:
      'The identical request that an admin session is allowed to run also succeeds (returns admin data or performs the state change) under a low-privileged session, whereas a correctly-secured endpoint would answer 403/404 for that lower role. The differential is admin-vs-user on the same request.',
    preconditions: ['multiple privilege tiers', 'authorization decided by authentication alone, not role'],
    appliesTo: ['REST APIs', 'GraphQL', 'Spring Boot', 'Express', 'Django REST Framework'],
    cwe: [862, 285, 863],
    vrt: ['broken_authentication_and_session_management', 'privilege_escalation'],
    chainsWith: ['idor', 'mass-assignment', 'bfla-forced-browsing'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-forced-browsing'],
    title: 'Forced browsing to hidden/guessable admin endpoints',
    symptom:
      'Administrative functionality is "protected" only by being unlinked from the UI. Requesting a predictable path (/admin, /administrator, /manager/html, /api/internal/*) directly reaches it with no authorization gate.',
    procedure:
      'Brute-force paths with a wordlist (ffuf/gobuster/ZAP Forced Browse) and harvest candidates from robots.txt, sitemaps, JS bundles, source comments, and framework defaults (/wp-admin/, /administrator/, /phpmyadmin/, /manager/html). Request each candidate as an unauthenticated (or low-privileged) client. Follow up by exercising the actions found there, not just loading the index.',
    whenToUse:
      'Whenever the app relies on obscurity — an admin area or internal API that is simply not shown to normal users but is served from the same origin.',
    confirmationSignal:
      'An unauthenticated or low-privileged request to the discovered admin path returns the privileged page/function, while the normal user flow never links to it and a hardened app would 401/403 — i.e. the access differs only because the URL was guessed, not authorized.',
    preconditions: ['admin functionality served on a reachable path', 'access control by non-linking rather than role check'],
    appliesTo: ['web apps', 'REST APIs', 'WordPress', 'Joomla', 'Tomcat'],
    cwe: [425, 862, 285],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-vertical-privesc', 'bfla-swagger-discovery'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
        title: 'OWASP WSTG: Enumerate Infrastructure and Application Admin Interfaces',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control (unprotected functionality, forced browsing)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-verb-tampering'],
    title: 'HTTP verb tampering: write verbs unguarded where the read verb is checked',
    symptom:
      'Authorization is enforced for the verb the UI uses (often GET), but the same resource path answers PUT/POST/PATCH/DELETE with no role check, so state-changing operations slip through.',
    procedure:
      'For each protected resource, take the path and re-send it under every other verb (GET, POST, PUT, PATCH, DELETE) as a low-privileged user. Declarative rules that bind an authorization constraint to a specific method (e.g. a filter mapped to GET) leave sibling verbs open. Confirm which verb actually mutates state and issue that one; also try OPTIONS to enumerate the allowed set.',
    whenToUse:
      'Endpoints where authorization is expressed per-method (framework method-security annotations, servlet security-constraints, route-level guards on one verb).',
    confirmationSignal:
      'The path refused under the guarded verb (403 on GET/POST) performs the operation under a different verb (PUT/PATCH/DELETE succeeds) for the same low-privileged session — the outcome diverges purely by swapping the method.',
    preconditions: ['authorization scoped to specific HTTP methods', 'other verbs routed to the same handler'],
    appliesTo: ['Java EE security-constraints', 'Spring Security', 'Express routers', 'Rails routes'],
    cwe: [862, 650, 285],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-method-override-header', 'bfla-method-based-bypass', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        title: 'OWASP WSTG: Test HTTP Methods (verb tampering)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-method-override-header'],
    title: 'Method-override headers to smuggle a blocked verb past a filter',
    symptom:
      'A proxy/WAF or framework blocks a verb (405/403 on DELETE/PUT), but the server honours an override header, so X-HTTP-Method-Override: DELETE on a permitted GET/POST is executed as the blocked method.',
    procedure:
      'Send the operation with an allowed outer verb (GET or POST) plus an override header the stack respects: X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override, or the _method body/query parameter (Rails, Laravel, Symfony, many Java frameworks). The front-end control sees the harmless outer verb while the backend dispatches the overridden one, circumventing a middleware/proxy/WAF that filters specific methods.',
    whenToUse:
      'When a direct DELETE/PUT is rejected by an edge device but the application framework supports method-override semantics.',
    confirmationSignal:
      'The direct blocked-verb request returns 405/403, but the same action wrapped as GET/POST + an override header succeeds — proving the backend acted on the overridden method the filter never saw.',
    preconditions: ['edge filter blocks certain verbs', 'framework honours method-override header/param'],
    appliesTo: ['Rails (_method)', 'Laravel', 'Symfony', 'Spring HiddenHttpMethodFilter', 'Node method-override'],
    cwe: [862, 650, 436],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-verb-tampering', 'bfla-x-original-url'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        title: 'OWASP WSTG: Test HTTP Methods (X-HTTP-Method-Override)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-method-based-bypass'],
    title: 'Method-based access-control bypass via unrecognised or alternate verb',
    symptom:
      'The access check is bound to the exact method the UI uses. Switching to a semantically-equivalent method (GET instead of POST), an unknown method (POSTX, FOO), or HEAD/OPTIONS causes the framework to route the request while the method-scoped guard fails to match.',
    procedure:
      'Take an admin action refused for your role and replay it with a mutated method: change POST to GET (moving parameters to the query string), invent a bogus method like POSTX, or try HEAD. Frameworks that map authorization to a specific verb often still dispatch the handler for the mismatched method but skip the check. A 302/redirect page that guards GET may return 200 with the protected content under HEAD.',
    whenToUse:
      'Endpoints whose authorization filter enumerates methods (e.g. secured for POST only) but whose router accepts additional or unknown methods.',
    confirmationSignal:
      'The action denied under the intended method (POST -> "Unauthorized") completes when the method is changed (GET/POSTX -> action performed, or HEAD returns 200 where GET returned 302) for the same session, isolating the method as the only variable.',
    preconditions: ['authorization matched to a specific verb', 'router dispatches other/unknown verbs to the handler'],
    appliesTo: ['servlet security-constraints', 'Spring MVC', 'Express', 'PHP frameworks'],
    cwe: [650, 862, 289],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-verb-tampering', 'bfla-state-changing-get'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented',
        title: 'PortSwigger: Method-based access control can be circumvented',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        title: 'OWASP WSTG: Test HTTP Methods',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-client-side-authz'],
    title: 'Client-side-only authorization: UI hides the control, the API is unguarded',
    symptom:
      'The front-end decides what a user may do (buttons hidden, menu items removed, disabled fields, role read from a JS variable), but the backend endpoint behind the hidden control performs no server-side check.',
    procedure:
      'Diff the client for privileged code paths and endpoint references that the current role never renders (feature flags in JS, admin routes in the SPA bundle, disabled form fields). Recover the underlying request shape and issue it directly with a proxy, bypassing the browser entirely. Treat all client-side gating (hidden/disabled elements, "isAdmin" JS booleans) as advisory only.',
    whenToUse:
      'SPAs and rich clients that render capabilities from role data on the client while the API trusts the client to self-restrict.',
    confirmationSignal:
      'A request the UI never lets your role initiate succeeds when replayed directly, showing the server enforced nothing that the browser was not already enforcing — the block existed only client-side.',
    preconditions: ['authorization implied by UI rendering', 'API endpoint lacks an independent server-side check'],
    appliesTo: ['React/Angular/Vue SPAs', 'mobile app backends', 'REST APIs'],
    cwe: [602, 862, 285],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-vertical-privesc', 'bfla-param-based-role'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/logic-flaws/examples',
        title: 'PortSwigger: Business logic vulnerabilities (excessive trust in client-side controls)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control (unprotected functionality)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-param-based-role'],
    title: 'Parameter/cookie-based role: privilege flag trusted from the request',
    symptom:
      'The application derives the caller’s role from a client-controlled value on each request — a cookie (Admin=false), a hidden field, a query/body flag (?admin=true, role=1, isAdmin) — instead of from server-side session state.',
    procedure:
      'Locate where role/entitlement is transmitted by the client: cookies set at login (Admin=false), request parameters, or JSON fields. Flip the value (false->true, user->admin, 0->1) and resend the request. Unlike mass-assignment (which persists a privileged field), this is per-request trust: the flag is re-read on every call, so no stored state is needed. Test high-value actions once the flag is accepted.',
    whenToUse:
      'Apps that carry authorization data in the request round-trip rather than binding it to an opaque server session.',
    confirmationSignal:
      'The same endpoint returns user-level output with the flag unset and admin-level output/behaviour once the client-supplied flag is toggled, proving the server read the role straight from the request.',
    preconditions: ['role transmitted in a client-controlled field', 'server trusts it without server-side verification'],
    appliesTo: ['cookie-based apps', 'REST APIs', 'legacy server-rendered apps'],
    cwe: [862, 639, 602],
    vrt: ['broken_access_control', 'privilege_escalation'],
    chainsWith: ['mass-assignment', 'bfla-client-side-authz'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter',
        title: 'PortSwigger: User role controlled by request parameter',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control (parameter-based access control)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-sibling-endpoint-gap'],
    title: 'Authorization present on one endpoint, missing on a sibling or older version',
    symptom:
      'A function is correctly guarded on its primary route (e.g. /api/v2/users/{id}) but an equivalent legacy, aliased, internal, or differently-shaped endpoint exposes the same capability without the check.',
    procedure:
      'For every guarded operation, enumerate alternatives that reach the same logic: prior API versions (/v1/ vs /v2/), REST-vs-GraphQL twins, batch-vs-single variants, export/print/download endpoints, mobile-only or internal routes, and undocumented paths from Swagger/introspection. Replay the operation on each alternative as a low-privileged user — authorization retrofitted onto the main path is frequently absent on the siblings.',
    whenToUse:
      'Mature APIs with multiple versions/surfaces where a security fix or role check was added to one route but not propagated to its equivalents.',
    confirmationSignal:
      'The primary endpoint refuses the low-privileged caller (403) while a sibling/legacy endpoint performs the identical operation for that same caller — the check exists on one route and not the other.',
    preconditions: ['multiple endpoints reaching the same function', 'inconsistent authorization across them'],
    appliesTo: ['versioned REST APIs', 'GraphQL + REST', 'microservice fleets'],
    cwe: [862, 285, 863],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-swagger-discovery', 'bfla-graphql-mutation-authz', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
        title: 'OWASP API9:2023 Improper Inventory Management',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-workflow-step-skip'],
    title: 'Multi-step workflow step-skipping to the privileged step',
    symptom:
      'A guarded action is protected only by the assumption that earlier steps ran first (login before 2FA, cart before payment, request before approval). Requesting the later step directly reaches it in an unexpected, under-authorized state.',
    procedure:
      'Complete the workflow once as an authorized user to capture each step’s request. Then, from a fresh or lower-privileged session, jump straight to the sensitive step (POST the 2FA-verify, the confirm-order, the state-transition endpoint) without performing the prerequisites. Also try repeating or reordering steps. The server often infers authorization from position in the flow rather than re-checking at the privileged step.',
    whenToUse:
      'Sequential processes (checkout, onboarding, 2FA, KYC, provisioning) where a later endpoint assumes the caller has passed the earlier gates.',
    confirmationSignal:
      'Invoking the later step directly — skipping the prerequisite steps — advances/completes the workflow, whereas the intended sequence would have required the prior authorization; the app ends in a state only reachable by bypassing a gate.',
    preconditions: ['stateful multi-step process', 'later step trusts that earlier steps enforced authorization'],
    appliesTo: ['checkout flows', '2FA flows', 'onboarding/KYC', 'approval pipelines'],
    cwe: [841, 840, 306],
    vrt: ['broken_authentication_and_session_management', 'business_logic'],
    chainsWith: ['bfla-approval-bypass', 'race-condition'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/logic-flaws/examples',
        title: 'PortSwigger: Business logic vulnerabilities (skipping steps)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-admin-separate-host'],
    title: 'Admin functionality on a separate host/port/subdomain left unauthenticated',
    symptom:
      'Administrative or management functionality is split onto its own subdomain, an alternate port, or an internal host, and that surface is trusted-by-location — reachable without the authentication the main app enforces.',
    procedure:
      'Enumerate the org’s hosts and ports (admin.*, internal.*, staging.*, :8080/:9990/:8443, management consoles like Tomcat /manager). Where the admin surface assumes it is network-restricted but is actually reachable, access its functions directly. Cross-reference DNS, certificate SANs, and virtual-host routing; a Host-header swap sometimes reveals an admin vhost served by the same IP.',
    whenToUse:
      'Deployments that isolate admin/management onto a distinct origin or port and rely on that separation instead of authentication.',
    confirmationSignal:
      'The admin host/port serves privileged functionality to an unauthenticated request, in contrast to the main application origin which requires login for equivalent actions — access hinges on which host was contacted, not on credentials.',
    preconditions: ['admin split to a separate host/port/subdomain', 'that surface assumes network isolation it does not have'],
    appliesTo: ['Tomcat manager', 'app-server admin consoles', 'internal admin subdomains'],
    cwe: [862, 668, 306],
    vrt: ['server_security_misconfiguration', 'broken_access_control'],
    chainsWith: ['bfla-internal-microservice', 'bfla-forced-browsing'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces',
        title: 'OWASP WSTG: Enumerate Admin Interfaces (alternate ports/hosts)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
        title: 'OWASP API9:2023 Improper Inventory Management (non-production/internal hosts)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-graphql-mutation-authz'],
    title: 'GraphQL mutation lacking authorization while queries are guarded',
    symptom:
      'Authorization is implemented in query resolvers but a state-changing mutation (or a nested field/edge) resolves without a role check, so a low-privileged client can invoke privileged mutations exposed by the schema.',
    procedure:
      'Recover the schema (introspection or field-suggestion probing) and list every mutation and sensitive field. For each mutation — createUser, updateRole, deleteAccount, admin-scoped operations — send it as a low-privileged user. Because authorization in GraphQL must be enforced per-resolver, checks are commonly present on nodes/queries but missing on edges/mutations. Test nested privileged fields separately from their parent.',
    whenToUse:
      'Any GraphQL API where mutations or specific fields exist that the current role should not be able to execute.',
    confirmationSignal:
      'A mutation that the schema exposes executes successfully for a low-privileged session and persists a privileged change, while the corresponding guarded query would deny that role — authorization is enforced on one resolver type but not the mutation.',
    preconditions: ['GraphQL endpoint reachable', 'authorization enforced inconsistently across resolvers'],
    appliesTo: ['Apollo Server', 'graphql-js', 'Hasura', 'GraphQL Yoga'],
    cwe: [862, 285, 863],
    vrt: ['broken_access_control'],
    chainsWith: ['graphql-introspection', 'mass-assignment', 'bfla-sibling-endpoint-gap'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        title: 'OWASP GraphQL Cheat Sheet (authorization on mutations, edges and nodes)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-actuator-exposure'],
    title: 'Spring Boot Actuator management endpoints exposed (/actuator/env, /heapdump)',
    symptom:
      'Sensitive Actuator endpoints are reachable without authentication because exposure was widened (management.endpoints.web.exposure.include=*) without a Spring Security filter, leaking configuration, mappings, and memory.',
    procedure:
      'Probe /actuator and its children: /actuator/env and /configprops (property values, sometimes secrets pre-sanitisation), /beans and /mappings (full route/structure map to feed forced browsing), /heapdump (download and grep the heap for tokens/passwords/session ids), /threaddump, /httpexchanges (recent requests, possibly bearing auth headers). Only /health is exposed by default, so any of the others answering signals a misconfiguration. Also check the legacy Spring Boot 1.x root paths (/env, /heapdump without the /actuator prefix).',
    whenToUse:
      'Any Spring Boot service; probe the management base path in production and on internal/management ports.',
    confirmationSignal:
      'A management endpoint that ships disabled-by-default (env/beans/mappings/heapdump/httpexchanges) returns its data to an unauthenticated caller, unlike a hardened deployment where only /health responds and the rest are 404/401 — the delta is the misconfigured exposure.',
    preconditions: ['Spring Boot Actuator on the classpath', 'sensitive endpoints exposed without Spring Security'],
    appliesTo: ['Spring Boot', 'Spring Cloud gateways', 'Java microservices'],
    cwe: [862, 200, 668],
    vrt: ['server_security_misconfiguration', 'sensitive_data_exposure'],
    chainsWith: ['bfla-actuator-invoke', 'bfla-forced-browsing', 'ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://docs.spring.io/spring-boot/reference/actuator/endpoints.html',
        title: 'Spring Boot Actuator Endpoints (exposure defaults and sensitive endpoints)',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/',
        title: 'OWASP API8:2023 Security Misconfiguration',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-actuator-invoke'],
    title: 'Invoking Actuator write operations (/shutdown, /loggers, /env, Jolokia)',
    symptom:
      'Beyond reading, an exposed Actuator offers state-changing management functions: POST /actuator/shutdown stops the app, POST /actuator/loggers/{name} changes log levels, POST /actuator/env mutates properties, and /actuator/jolokia can invoke arbitrary MBean operations.',
    procedure:
      'Enumerate writable management operations. POST to /actuator/shutdown for availability impact; POST to /actuator/loggers to flip a package to DEBUG/TRACE and surface secrets in logs; POST to /actuator/env to set a property (e.g. inject a malicious config value), then trigger a /refresh. Where /actuator/jolokia is present, call MBean operations to reach code execution. These are privileged functions invoked by an unauthenticated caller — the management-endpoint counterpart of a BFLA admin action.',
    whenToUse:
      'When an Actuator base path is reachable and its access mode permits write operations (not read-only) without authentication.',
    confirmationSignal:
      'A POST to a management operation takes effect for an unauthenticated caller (the app shuts down, a logger level changes and is reflected on a subsequent GET, or an env property is altered) — a state change no anonymous user should be able to cause.',
    preconditions: ['Actuator exposed with write access', 'no Spring Security on the management endpoints'],
    appliesTo: ['Spring Boot', 'Spring Cloud', 'Jolokia/JMX-over-HTTP'],
    cwe: [862, 732, 285],
    vrt: ['server_security_misconfiguration', 'broken_access_control'],
    chainsWith: ['bfla-actuator-exposure', 'insecure-deserialization'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://docs.spring.io/spring-boot/reference/actuator/endpoints.html',
        title: 'Spring Boot Actuator Endpoints (write operations, access modes, shutdown/loggers)',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['bfla-django-debug'],
    title: 'Django DEBUG=True in production exposing settings and tracebacks',
    symptom:
      'A Django app runs with DEBUG=True in production, so unhandled errors render detailed debug pages exposing settings, environment metadata, file paths, and SQL — and any request can trigger them.',
    procedure:
      'Force an exception (bad type in a parameter, nonexistent object, malformed input) and inspect the response. A DEBUG traceback page enumerates installed apps, middleware, settings (partially-sanitised — filtering is name-based on API/KEY/PASS/SECRET/TOKEN, so mis-named secrets leak), local variables, and the SQL executed. Use the disclosed structure to locate further endpoints and secrets. Confirm via the technical-500 page rather than a generic error.',
    whenToUse:
      'Django applications where a 500 renders the yellow debug page instead of a plain error.',
    confirmationSignal:
      'A triggered error returns the Django technical debug page (settings/traceback/SQL) rather than the generic production error page — a response only served when DEBUG is on, differing sharply from a hardened deployment’s opaque 500.',
    preconditions: ['DEBUG=True in production', 'ability to trigger an unhandled exception'],
    appliesTo: ['Django'],
    cwe: [489, 215, 200],
    vrt: ['server_security_misconfiguration', 'sensitive_data_exposure'],
    chainsWith: ['bfla-forced-browsing', 'sqli'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://docs.djangoproject.com/en/stable/ref/settings/#debug',
        title: 'Django documentation: DEBUG setting (never deploy with DEBUG on)',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/',
        title: 'OWASP API8:2023 Security Misconfiguration',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-rails-dev-endpoints'],
    title: 'Rails development/debug endpoints mounted in production',
    symptom:
      'Development-only Rails tooling is reachable in production — /rails/info/routes (full route map), /rails/info/properties, or a mounted web-console — exposing structure or, with web-console, an interactive server-side REPL.',
    procedure:
      'Request /rails/info, /rails/info/routes and /rails/info/properties to dump routes and environment. Probe for the web-console (its error pages carry an interactive console); if the requesting IP is within web_console.whitelisted_ips, code executes server-side. Also test other dev/test engines and Rack apps mounted in routes.rb that should not be present in production. Use disclosed routes to drive further authorization testing.',
    whenToUse:
      'Ruby on Rails apps where development gems or diagnostic routes were not stripped from the production build.',
    confirmationSignal:
      'A production request returns Rails diagnostic output (route table / environment) or an interactive web-console prompt — endpoints that a correctly-built production app either 404s or never mounts, so their presence itself is the finding.',
    preconditions: ['dev/test engines or /rails/info reachable in production', 'web-console gem present or IP allowlisted'],
    appliesTo: ['Ruby on Rails', 'web-console gem'],
    cwe: [489, 215, 200],
    vrt: ['server_security_misconfiguration', 'sensitive_data_exposure'],
    chainsWith: ['bfla-forced-browsing', 'ssti'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://github.com/eliotsykes/rails-security-checklist',
        title: 'Rails Security Checklist (dev/test engines must not expose endpoints in production)',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-swagger-discovery'],
    title: 'Exposed Swagger/OpenAPI docs revealing then invoking internal operations',
    symptom:
      'An API-documentation surface (/swagger-ui, /swagger.json, /openapi.json, /v3/api-docs, /api-docs) is public and describes internal, deprecated, or admin operations that are not otherwise linked — and often are not authorization-checked.',
    procedure:
      'Fetch the machine-readable spec (swagger.json / openapi.json) and parse every path, method, and parameter, focusing on internal/*, admin/*, and deprecated operations that the UI never calls. Reconstruct each request from the schema and invoke it directly as a low-privileged or unauthenticated client. Note any secrets embedded in example values or query-parameter defaults. Documentation exposure is the discovery vector; the finding is a documented operation that runs without proper authorization.',
    whenToUse:
      'Any service shipping OpenAPI/Swagger artifacts reachable in production, especially auto-generated docs that include non-public routes.',
    confirmationSignal:
      'An operation learned only from the exposed spec executes for an under-privileged caller, whereas it appears nowhere in the normal UI and should require elevated rights — the spec both revealed the function and it proved unguarded.',
    preconditions: ['OpenAPI/Swagger surface reachable', 'documented internal/admin operations lack authorization'],
    appliesTo: ['Swagger UI', 'OpenAPI', 'Springdoc', 'FastAPI /docs'],
    cwe: [862, 200, 285],
    vrt: ['broken_access_control', 'sensitive_data_exposure'],
    chainsWith: ['bfla-sibling-endpoint-gap', 'graphql-introspection', 'bfla-forced-browsing'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
        title: 'OWASP API9:2023 Improper Inventory Management (exposed API documentation)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-state-changing-get'],
    title: 'State-changing action reachable via a safe GET request',
    symptom:
      'A sensitive operation (delete, grant role, toggle setting) can be triggered by a GET request. Treating a nominally safe method as an action both evades method-scoped access checks and enables CSRF-by-link and log/referrer leakage.',
    procedure:
      'For each privileged action, try expressing it as a GET with parameters in the query string (e.g. GET /admin/deleteUser?id=5). Servers that trust the HTTP method to imply read-only will still execute the side effect. This bypasses controls that only guard the POST form of the action and turns the action into something reachable by an <img>/link (no body, no token). Confirm the side effect occurred and check whether the parameters leak into access logs, referrers, and browser history.',
    whenToUse:
      'Endpoints where an action handler is bound to GET, or where the write is reachable under GET in addition to its intended verb.',
    confirmationSignal:
      'The privileged state change takes effect from a GET request — a method that must be side-effect-free — and, notably, succeeds where the POST variant was refused or CSRF-protected; the safe-method invocation diverges from the guarded one.',
    preconditions: ['state-changing operation handled under GET', 'no verb restriction or anti-CSRF on the GET path'],
    appliesTo: ['REST APIs', 'server-rendered apps', 'legacy action endpoints'],
    cwe: [650, 352, 862],
    vrt: ['broken_access_control', 'cross_site_request_forgery_csrf'],
    chainsWith: ['csrf', 'bfla-method-based-bypass'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
        title: 'OWASP REST Security Cheat Sheet (authorize the HTTP method per resource)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        title: 'OWASP WSTG: Test HTTP Methods',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-bulk-import-authz'],
    title: 'Bulk/import/CSV endpoint bypassing per-item authorization',
    symptom:
      'A batch endpoint (CSV/JSON import, bulk-update, multi-create) applies the caller’s permission once at the batch level, then processes each row without the per-object ownership/role check the single-item endpoint enforces.',
    procedure:
      'Find the batch counterpart of a guarded single-item operation. In the batch payload, embed items that target other tenants/users or set privileged per-row fields (ownerId, role, status, price) that the single endpoint would reject. Submit and inspect which rows were accepted. Because the authorization was evaluated for the request as a whole, individual rows escaping their owner/role boundary indicates the per-item check was skipped in the bulk path.',
    whenToUse:
      'APIs offering import/export or bulk operations alongside guarded single-record endpoints.',
    confirmationSignal:
      'A row in the bulk request that references or mutates another principal’s object is persisted, even though the equivalent single-item request for that object is refused for the caller — per-item authorization holds on the single path but not the batch path.',
    preconditions: ['bulk/import endpoint exists', 'authorization checked per-batch, not per-item'],
    appliesTo: ['CSV/JSON import endpoints', 'bulk REST APIs', 'GraphQL batched mutations'],
    cwe: [862, 639, 915],
    vrt: ['broken_access_control'],
    chainsWith: ['idor', 'mass-assignment', 'bfla-graphql-mutation-authz'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html',
        title: 'OWASP GraphQL Cheat Sheet (batching / per-object controls in code)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-approval-bypass'],
    title: 'Approval/moderation bypass by invoking the state-transition directly',
    symptom:
      'A workflow requires a reviewer/approver role to move an item to a privileged state (publish, approve, mark-paid, activate), but the state-transition endpoint itself is callable by the requester who created the item.',
    procedure:
      'Identify the transition that should require a second, higher role (approve, publish, verify, release). As the requesting/low-privileged user, call the transition endpoint directly on your own item, skipping the reviewer. Also try self-approval loops and setting the target status field via the create/update path. The vulnerability is separation-of-duties collapsing to a single actor because the approve function lacks its own role check.',
    whenToUse:
      'Maker/checker or moderation pipelines where creation and approval are meant to be performed by different roles.',
    confirmationSignal:
      'The item reaches the approved/published state through an action taken solely by the requester, with no reviewer-role session involved — the transition the approver alone should perform succeeds for the maker.',
    preconditions: ['separation-of-duties workflow', 'the privileged transition endpoint lacks a distinct role check'],
    appliesTo: ['CMS moderation', 'financial maker-checker', 'content publishing', 'expense/approval systems'],
    cwe: [862, 863, 841],
    vrt: ['broken_access_control', 'business_logic'],
    chainsWith: ['bfla-workflow-step-skip', 'mass-assignment'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/logic-flaws/examples',
        title: 'PortSwigger: Business logic vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-impersonation-endpoint'],
    title: 'Impersonation / act-on-behalf endpoint with missing authorization',
    symptom:
      'A "login as user" / impersonate / switch-user function meant only for admins/support is reachable by unauthorized callers because its authorization relies on a flawed or absent check, yielding a session as any target user.',
    procedure:
      'Locate impersonation actions (users/impersonate, switch_user, actAsUser, support "view as customer"). Test the guard: is it role-checked server-side, or does it trust a token/flag that any route can satisfy? In Craft CMS, users/impersonate-with-token was listed as anonymous-allowed and its token guard only verified that some token existed, so an attacker appended &action=users/impersonate-with-token&userId=1 to a preview URL to log in as admin. Try invoking the impersonation endpoint directly with a target userId as a low-privileged/unauthenticated user.',
    whenToUse:
      'Apps with admin/support impersonation, delegated-access, or "act on behalf of" features.',
    confirmationSignal:
      'A caller who is not the intended admin obtains an authenticated session as the target user (subsequent requests act as that user), whereas the feature should be usable only from a privileged role — impersonation succeeds across the privilege boundary it was meant to enforce.',
    preconditions: ['impersonation/act-as feature exists', 'its authorization is absent or bypassable'],
    appliesTo: ['Craft CMS', 'support/admin tooling', 'multi-tenant SaaS', 'Django/Rails admin impersonation'],
    cwe: [862, 863, 270],
    vrt: ['broken_access_control', 'privilege_escalation'],
    chainsWith: ['bfla-vertical-privesc', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://github.com/craftcms/cms/security/advisories/GHSA-cc7p-2j3x-x7xf',
        title: 'Craft CMS advisory GHSA-cc7p-2j3x-x7xf: privilege escalation via impersonate-with-token',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-debug-feature-toggle'],
    title: 'Debug/feature-flag toggles that unlock privileged behaviour',
    symptom:
      'An application-level toggle in the request — ?debug=1, ?admin=1, ?test=true, X-Debug headers, a feature-flag cookie — switches on verbose output, test bypasses, or hidden functionality that the caller should not have.',
    procedure:
      'Fuzz common debug/feature parameters and headers on interesting endpoints: debug, test, admin, preview, internal, X-Debug-Mode, X-Feature-*. Compare responses with and without the toggle for extra data (stack traces, internal fields, unmasked values) or unlocked actions (auth bypass in "test mode", hidden admin operations behind a flag). Distinct from framework-wide DEBUG: these are app-authored flags read from the request.',
    whenToUse:
      'Apps that keep debug/test/feature code paths in production gated behind client-supplied flags.',
    confirmationSignal:
      'The same endpoint returns richer data or performs a privileged action only when the debug/feature toggle is present, and behaves normally without it — the differential between the toggled and un-toggled request proves a request-controlled bypass.',
    preconditions: ['debug/feature code paths shipped to production', 'gated by a client-supplied flag'],
    appliesTo: ['REST APIs', 'web apps', 'feature-flagged services'],
    cwe: [489, 862, 200],
    vrt: ['server_security_misconfiguration', 'broken_access_control'],
    chainsWith: ['bfla-param-based-role', 'bfla-django-debug'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control (parameter-based access control)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/',
        title: 'OWASP API8:2023 Security Misconfiguration',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-internal-microservice'],
    title: 'Internal microservice reachable without the gateway’s authentication',
    symptom:
      'Authentication/authorization is enforced only at the API gateway/edge, and an internal service that trusts callers by network position is directly reachable, so its endpoints run without the edge checks.',
    procedure:
      'From a foothold or an unintentionally-exposed route, address the internal service directly (its cluster DNS name, pod IP, internal port, or an SSRF pivot) rather than through the gateway. Because the service assumes edge auth and does not re-verify, its endpoints — including privileged inter-service operations — execute unauthenticated. Look for gateway-stripped-vs-forwarded header trust (e.g. an X-User/X-Roles header the gateway sets that the service blindly believes) and forge it.',
    whenToUse:
      'Microservice/service-mesh deployments where authorization is centralized at the edge and internal services rely on defense-by-network.',
    confirmationSignal:
      'A request sent straight to the internal service (bypassing the gateway) is served, while the same operation via the gateway requires authentication — access differs solely by whether the edge was traversed, proving no per-service authorization.',
    preconditions: ['edge-only authorization', 'internal service reachable and trusting network position or gateway-set headers'],
    appliesTo: ['Kubernetes/service mesh', 'API gateways', 'gRPC/REST microservices'],
    cwe: [862, 668, 306],
    vrt: ['broken_access_control', 'server_security_misconfiguration'],
    chainsWith: ['ssrf', 'bfla-admin-separate-host', 'bfla-sibling-endpoint-gap'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html',
        title: 'OWASP Microservices Security Cheat Sheet (gateway bypass, defense in depth)',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/',
        title: 'OWASP API9:2023 Improper Inventory Management (internal endpoints)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-hpp-authz-bypass'],
    title: 'HTTP parameter pollution to bypass an authorization check',
    symptom:
      'A duplicated parameter is parsed differently by the component that authorizes and the component that acts: the guard reads one occurrence while the operation uses another, so a permitted value passes the check and a malicious value drives the action.',
    procedure:
      'Send the same parameter twice with different values (e.g. blogID=mine&blogID=victim, or id=1&id=999). Exploit the parsing split — a front-end/WAF or authorization layer that inspects the first occurrence while the app uses the last (or vice-versa; PHP takes last, Java Servlet first, ASP.NET concatenates, Python returns a list). The Blogger takeover is the canonical case: the check ran on the first blogID, the operation on the second.',
    whenToUse:
      'When an authorization or validation layer and the business logic may disagree on which duplicate parameter wins, especially across proxy/backend or framework boundaries.',
    confirmationSignal:
      'A request with duplicated parameters is authorized as though it targets a permitted value yet operates on the malicious one — differing from both single-parameter requests — showing the check and the action resolved different occurrences.',
    preconditions: ['authorization and logic parse duplicate params inconsistently', 'attacker can inject a duplicate'],
    appliesTo: ['ASP.NET/IIS', 'PHP', 'Java Servlets', 'Django/Flask', 'WAF+app splits'],
    cwe: [235, 862, 863],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-sibling-endpoint-gap', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution',
        title: 'OWASP WSTG: Testing for HTTP Parameter Pollution',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-ip-allowlist-bypass'],
    title: 'IP-allowlist bypass to reach internal/admin endpoints via forwarding headers',
    symptom:
      'An admin or internal endpoint is restricted to trusted IPs, but the app derives the client IP from a spoofable forwarding header (X-Forwarded-For, X-Real-IP, X-Client-IP), so a crafted header value passes the allowlist.',
    procedure:
      'Against an IP-restricted endpoint (403 from the internet), add X-Forwarded-For (and X-Real-IP, X-Forwarded, X-Client-IP, True-Client-IP) with a trusted value — 127.0.0.1, an RFC1918 address, or a known office IP. If the app trusts the leftmost/first entry, a single spoofed value works; where a proxy prepends entries, supply a comma-delimited list of the trusted IP repeated so a reverse-traversal still lands on it. Enumerate ranges if the trusted IP is unknown.',
    whenToUse:
      'Endpoints protected by source-IP allowlisting behind a proxy/CDN that populates or trusts forwarding headers.',
    confirmationSignal:
      'The endpoint that returns 403 without the header serves the protected content once a forwarding header carrying a trusted IP is added — the only change being an attacker-controlled header, proving the ACL trusts spoofable input.',
    preconditions: ['IP-based access restriction', 'client IP taken from a client-supplied forwarding header'],
    appliesTo: ['nginx/Apache allowlists', '.htaccess restrictions', 'CDN/proxy fronted apps'],
    cwe: [290, 348, 862],
    vrt: ['broken_access_control'],
    chainsWith: ['bfla-forced-browsing', 'bfla-admin-separate-host'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://shubs.io/enumerating-ips-in-x-forwarded-headers-to-bypass-403-restrictions/',
        title: 'Assetnote/Shubham Shah: Enumerating IPs in X-Forwarded headers to bypass 403 restrictions',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema',
        title: 'OWASP WSTG: Testing for Bypassing Authorization Schema (IP-spoofing headers)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-scope-not-enforced'],
    title: 'Valid token accepted but its scope/role claim never checked per-endpoint',
    symptom:
      'The resource server verifies that a JWT/OAuth token is authentic but does not enforce the scope, audience, or role claim required for the specific operation, so any valid token — including a low-scope one — can call privileged endpoints.',
    procedure:
      'Obtain a legitimately-issued token with minimal scope (a normal user login, a read-only OAuth grant, a token minted for a different client). Call privileged endpoints that should require a higher scope/role. Distinct from algorithm-confusion/forgery: the token is genuine and unmodified; the gap is that the endpoint checks authentication (is the token valid?) but not authorization (does this token bear the required scope?). Test each operation against the least-privileged valid token you can obtain.',
    whenToUse:
      'OAuth2/OIDC or JWT-secured APIs where scopes/roles exist in the token but per-endpoint enforcement may be missing.',
    confirmationSignal:
      'A privileged endpoint succeeds with a genuine minimal-scope token as it does with a fully-scoped one — the outcome does not vary with the token’s scope/role claim, showing the required scope is never enforced.',
    preconditions: ['token authenticity verified', 'required scope/role claim not enforced at the endpoint'],
    appliesTo: ['OAuth2 resource servers', 'OIDC APIs', 'JWT-secured microservices'],
    cwe: [862, 863, 285],
    vrt: ['broken_access_control'],
    chainsWith: ['jwt-alg-confusion', 'bfla-internal-microservice', 'bfla-sibling-endpoint-gap'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html',
        title: 'OWASP Microservices Security Cheat Sheet (per-service authorization)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-missing-auth-middleware'],
    title: 'Endpoint missing authentication/authorization middleware entirely',
    symptom:
      'A route was added without the auth middleware/decorator its siblings use — a forgotten @login_required, an un-guarded router mount, an anonymous-allowed action — so a critical function is fully public.',
    procedure:
      'Enumerate endpoints (routes file, Swagger, introspection, forced browsing) and test each unauthenticated. Focus on routes that break the pattern: a new/refactored handler, a legacy or mobile-only route, an action explicitly on an allow-anonymous list. Where the middleware is applied per-route rather than globally, gaps are common. Confirm the function performs its sensitive operation with no credentials at all.',
    whenToUse:
      'Frameworks where authentication/authorization is opt-in per route/handler, making an omission silently expose a function.',
    confirmationSignal:
      'A sensitive operation completes for a request bearing no session/token, while comparable operations in the same app require authentication — the endpoint answers the anonymous caller because its guard was never attached.',
    preconditions: ['per-route auth middleware', 'the middleware is absent on the target endpoint'],
    appliesTo: ['Express', 'Flask/Django views', 'Spring controllers', 'ASP.NET actions'],
    cwe: [306, 862, 285],
    vrt: ['broken_access_control', 'broken_authentication_and_session_management'],
    chainsWith: ['bfla-sibling-endpoint-gap', 'bfla-swagger-discovery', 'bfla-forced-browsing'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
        title: 'OWASP API5:2023 Broken Function Level Authorization',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/',
        title: 'OWASP API8:2023 Security Misconfiguration',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bfla-dangerous-http-methods'],
    title: 'Dangerous HTTP methods (PUT/DELETE/WebDAV) enabled at the web-server layer',
    symptom:
      'The web/app server accepts write methods it should not — PUT, DELETE, or WebDAV verbs — allowing files to be uploaded or removed on the server outside any application authorization.',
    procedure:
      'Send OPTIONS to list the Allow methods, then test PUT (upload a benign file to a writable path and re-request it) and DELETE. On misconfigured servers PUT can place a web-executable file (leading to code execution) and DELETE can remove content — file manipulation performed straight against the server, bypassing the application entirely. Also probe TRACE and WebDAV methods (PROPFIND, MKCOL) if present.',
    whenToUse:
      'Directly testing the HTTP server/container configuration, independent of application routes.',
    confirmationSignal:
      'A PUT stores a file that is then retrievable (or DELETE removes one), where the server should reject write methods with 405 — the server itself honoured a state-changing method no unauthenticated client should be allowed to use.',
    preconditions: ['web/app server permits write/WebDAV methods', 'writable path reachable'],
    appliesTo: ['Apache/nginx misconfig', 'IIS/WebDAV', 'Tomcat', 'legacy app servers'],
    cwe: [650, 732, 862],
    vrt: ['server_security_misconfiguration'],
    chainsWith: ['bfla-verb-tampering', 'path-traversal'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods',
        title: 'OWASP WSTG: Test HTTP Methods (PUT/DELETE file manipulation)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  }
];
