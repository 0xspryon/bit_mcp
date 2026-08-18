import type { CorpusRecord } from './types';

/**
 * Broken Object Level Authorization / IDOR family.
 *
 * Object-level access-control bypass: reading or writing a resource that
 * belongs to another user or tenant by manipulating the object reference the
 * request carries. Each record is a DISTINCT fundamental technique (a different
 * way the reference is expressed, discovered, or smuggled past the check), not
 * a restatement of the generic `idor` / `mass-assignment` records already in
 * 0001_corpus. The through-line for every confirmationSignal is DIFFERENTIAL:
 * a request bound to identity A returns or mutates an object owned by B, while
 * the same request for one of A's own non-existent ids yields 403/404.
 */
export const records: readonly CorpusRecord[] = [
  {
    namespaces: ['bola-uuid-harvest'],
    title: 'Object access via harvested "unguessable" UUID/GUID references',
    symptom:
      'Objects are keyed by UUID/GUID rather than integers, so the team assumes references are unguessable and skips ownership checks. The ids are not secret, though — they leak in other responses, share links, emails, and page source.',
    procedure:
      'Do not brute-force the UUID; harvest it. Collect other users’ object ids from public profiles, sharing/collaboration links, unsubscribe URLs, notification emails, embedded JSON, GraphQL/list responses, the Wayback Machine, and search engines. Replay the target request as user A with a UUID owned by user B on GET/PUT/PATCH/DELETE separately. Also check that "list" or "search" endpoints do not return ids the caller should never see, which seeds the harvest.',
    whenToUse:
      'Endpoints that switched from numeric ids to UUIDs and then dropped the per-object authorization check on the assumption that the id is secret.',
    confirmationSignal:
      'A UUID lifted from user B’s context returns or mutates B’s object under A’s session (200 with foreign data), while a random/own-but-nonexistent UUID returns 404 — proving the check is on existence, not ownership.',
    preconditions: ['objects referenced by UUID/GUID', 'ownership not verified against the session', 'ids observable somewhere'],
    appliesTo: ['REST APIs', 'GraphQL', 'SaaS multi-tenant apps', 'share-link features'],
    cwe: [639, 284, 200],
    chainsWith: ['idor', 'bola-uuidv1-predict', 'bola-cross-tenant'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        title: 'API1:2023 Broken Object Level Authorization',
        tier: 1,
        kind: 'reference'
      }
    ]
  },
  {
    namespaces: ['bola-uuidv1-predict'],
    title: 'Predicting UUIDv1 object/token ids (timestamp + MAC) via the sandwich attack',
    symptom:
      'An id or single-use token (password-reset link, invite, object handle) is a UUIDv1, which is time+MAC based rather than random. Sequential generations share the node/MAC bytes and differ only in a predictable timestamp/clock-sequence field.',
    procedure:
      'Confirm the version nibble is 1 (13th hex digit). Generate your own UUIDv1s just before and just after triggering the victim’s generation (e.g. request a reset for your account, then the victim, then your account) to "sandwich" the victim value: the node/MAC and clock-sequence bytes match yours and the 100ns timestamp lies between your two brackets, leaving a small keyspace to enumerate. Iterate the bracketed timestamps against the consuming endpoint.',
    whenToUse:
      'Any UUIDv1 used where unpredictability matters: reset/verify tokens, invite ids, or object ids that gate access without a separate ownership check.',
    confirmationSignal:
      'One of the bracketed candidate UUIDs is accepted as the victim’s token/object (reset succeeds, or the object returns B’s data), whereas a random v4-style UUID is rejected — proving the value was predicted, not authorized.',
    preconditions: ['identifier is UUID version 1', 'attacker can trigger generations around the victim’s', 'no rate limit on the consuming endpoint'],
    appliesTo: ['Node uuid v1', 'Python uuid1', 'Java UUID (time-based)', 'password-reset flows'],
    cwe: [340, 330, 639],
    chainsWith: ['bola-uuid-harvest', 'host-header', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://appsec-labs.com/sandwich-attacks/',
        title: 'Sandwich Attacks: From Reset Password to Account Takeover',
        tier: 2,
        kind: 'research'
      }
    ]
  },
  {
    namespaces: ['bola-encoded-id'],
    title: 'Decoding/re-encoding obfuscated object ids (base64, hex, hashids, ROT)',
    symptom:
      'The object reference looks opaque — base64, hex, a hashid, or a lightly transformed string — so ownership checks are skipped on the belief the client cannot forge a valid neighbour id.',
    procedure:
      'Decode the token: try base64/base64url, hex, URL-encoding, ROT/XOR, and hashids/sqids (recover the salt/alphabet from a handful of known id pairs). If it resolves to a small integer or predictable string, increment/mutate it, re-encode with the original scheme, and replay. Where a hashid alphabet is default, precompute neighbour ids. Confirm the encoding is decorative, not authorization.',
    whenToUse:
      'Ids that are conspicuously encoded or hashed and are the only thing standing between the caller and another object.',
    confirmationSignal:
      'A neighbour id you produced by decode→mutate→re-encode returns another user’s object (200 with foreign data), while a malformed/own-nonexistent encoded value returns 404 — the transform was cosmetic.',
    preconditions: ['object id is reversibly encoded/hashed client-side', 'no ownership check behind the decode'],
    appliesTo: ['REST APIs', 'hashids/sqids', 'base64 tokens', 'legacy id obfuscation'],
    cwe: [639, 284],
    chainsWith: ['idor', 'bola-graphql-nodeid'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/',
        title: 'How to Find IDOR Vulnerabilities for Large Bounty Rewards',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-json-array-wrap'],
    title: 'JSON globbing: wrap the id in an array/object or change its type to slip the check',
    symptom:
      'A scalar id is validated ("does this id belong to you?") but the same handler accepts and dereferences the id in a different JSON shape that the validator never inspected.',
    procedure:
      'Take a request the server rejects for a foreign id and resend the id in alternate shapes: an array `{"id":[VICTIM]}` or `{"id":[OWN,VICTIM]}`, a nested object `{"id":{"id":VICTIM}}`, a JSON string vs number, a negative/zero/decimal value, or a wildcard/`*`. The authorization filter often matches only the scalar path while the ORM/loader flattens the array or coerces the type and fetches the object anyway.',
    whenToUse:
      'JSON APIs where the ownership check and the data-fetch parse the id independently, so a shape the validator ignores still reaches the loader.',
    confirmationSignal:
      'The scalar form returns 403 but the wrapped/retyped form returns 200 with the same foreign object — a divergence between the validating parse and the fetching parse, not a normal success.',
    preconditions: ['id validated in one shape but dereferenced in another', 'loose body parsing / type coercion'],
    appliesTo: ['Express', 'Rails', 'Django REST Framework', 'GraphQL variables', 'MongoDB operators'],
    cwe: [639, 863, 20],
    chainsWith: ['idor', 'bola-param-pollution', 'mass-assignment'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-param-pollution'],
    title: 'IDOR via HTTP parameter pollution (duplicate id, validate-one/use-other)',
    symptom:
      'Sending the id parameter twice with different values passes authorization but operates on the other value, because the auth layer and the data layer disagree on which duplicate wins.',
    procedure:
      'Duplicate the id parameter with your own id and the victim’s: `?id=OWN&id=VICTIM` (and the reverse), `id[]=OWN&id[]=VICTIM`, and mixed query-string vs body copies. Servers/frameworks differ — some take the first occurrence, some the last, some concatenate — so the gateway that authorizes may read one copy while the backend that fetches reads the other. Try all orderings and both transport locations.',
    whenToUse:
      'A proxy/gateway or middleware authorizes the id, then forwards to a backend that parses duplicates differently (classic first-vs-last split).',
    confirmationSignal:
      'A single-copy request for the victim id is 403, but the polluted request returns/mutates the victim object — authorization read your copy while the sink read the victim copy.',
    preconditions: ['multiple layers parse query/body params', 'inconsistent duplicate-parameter precedence'],
    appliesTo: ['reverse proxies + app servers', 'PHP', 'ASP.NET', 'Node/Express', 'Java servlets'],
    cwe: [639, 235, 863],
    chainsWith: ['idor', 'bola-json-array-wrap', '403-bypass'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://0xgaurang.medium.com/case-study-bypassing-idor-via-parameter-pollution-78f7b3f9f59d',
        title: 'Case Study: Bypassing IDOR via Parameter Pollution',
        tier: 3,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-method-swap'],
    title: 'Verb swap: authorization enforced on one HTTP method but not its siblings',
    symptom:
      'GET on an object is properly authorized, but PUT/PATCH/DELETE/POST (or HEAD/OPTIONS) on the same object reference skip the ownership check because the guard was attached to a single handler.',
    procedure:
      'For each object endpoint, replay the identical id under every method: read via GET, then attempt PUT/PATCH to modify, DELETE to remove, and POST to a collection with an explicit id. Also try overriding the method (`X-HTTP-Method-Override`, `_method`) when a proxy authorizes by verb. Test the write methods independently — read protection frequently does not imply write protection.',
    whenToUse:
      'REST resources where authorization is wired per-handler rather than per-object, so unlisted verbs fall through.',
    confirmationSignal:
      'GET on the foreign id is 403 but PUT/PATCH/DELETE succeeds (2xx and the object’s state visibly changes for the real owner), or vice-versa — the check depends on the verb, not the object.',
    preconditions: ['per-method (not per-object) authorization', 'write verbs reachable for the reference'],
    appliesTo: ['REST APIs', 'Spring', 'Express routers', 'API gateways with per-route ACLs'],
    cwe: [862, 639, 285],
    chainsWith: ['idor', 'bola-blind-write', 'bola-content-type-wrap'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/',
        title: 'How to Find IDOR Vulnerabilities for Large Bounty Rewards',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-content-type-wrap'],
    title: 'Content-Type switch to reach a parser/handler that lacks the object check',
    symptom:
      'The same route serves multiple body formats (JSON, form-encoded, XML, multipart), and one format is dispatched to an older or looser handler where the ownership check is missing.',
    procedure:
      'Take an authorized-only request and resend the same id with a different `Content-Type`: JSON → `application/x-www-form-urlencoded`, form → `application/xml` or `text/xml`, or add/remove `multipart/form-data`. Frameworks route by content type to distinct deserializers/controllers; a legacy XML or form path may predate the guard. Combine with array/scalar shape changes per format.',
    whenToUse:
      'Endpoints advertising or tolerating multiple request formats, especially where XML/form support is legacy.',
    confirmationSignal:
      'The canonical Content-Type returns 403 for the foreign id while an alternate Content-Type with the same id returns/mutates the object — a handler-selection divergence, not a normal 200.',
    preconditions: ['route accepts multiple body formats', 'authorization not uniform across deserializers'],
    appliesTo: ['Spring content negotiation', 'Rails respond_to', 'ASP.NET formatters', 'SOAP/REST hybrids'],
    cwe: [862, 436],
    chainsWith: ['bola-method-swap', 'idor', 'xxe'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-legacy-api'],
    title: 'Object access through a deprecated API version or mobile/legacy endpoint',
    symptom:
      'The current API (/v3, web) enforces object authorization, but an older version (/v1, /internal, /mobile, /rpc) still routes to code that predates the fix and skips the check.',
    procedure:
      'Enumerate version prefixes and parallel surfaces: swap `/v3/` → `/v1/`, `/v2/`; look for `/mobile/`, `/api/legacy/`, `/internal/`, GraphQL vs REST twins, and hostnames in old mobile-app builds or JS bundles. Replay the object request against each older surface with a foreign id. Legacy endpoints often lack the ownership check, rate limits, and logging the modern path added.',
    whenToUse:
      'Products with a long API history or a separate mobile backend where old versions were never decommissioned.',
    confirmationSignal:
      'The modern endpoint returns 403 for the foreign id while a legacy-version endpoint returns the same foreign object 200 — the check exists only on the newer surface.',
    preconditions: ['deprecated API version still reachable', 'authorization added only to the current version'],
    appliesTo: ['versioned REST APIs', 'mobile backends', 'partner/internal APIs'],
    cwe: [639, 862, 284],
    chainsWith: ['idor', 'bola-method-swap', 'graphql-introspection'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-keyword-me'],
    title: 'Replacing an identity alias ("me"/"current"/"self") with an explicit id',
    symptom:
      'An endpoint normally scopes to the caller via a symbolic segment (`/users/me`, `/account/current`, `?user=self`) and derives identity from it — substituting a concrete id makes it operate on that other user.',
    procedure:
      'Find routes using an identity alias and swap it for a literal id: `/users/me/settings` → `/users/<VICTIM_ID>/settings`; `?scope=self` → `?scope=<id>`; `/me` → `/me?user_id=<id>`. Some backends resolve the alias to a session id but then trust an explicit id if present, or accept both and prefer the explicit one. Test read and write.',
    whenToUse:
      'APIs that mix an identity-alias convenience form with an explicit-id form on the same handler.',
    confirmationSignal:
      'The alias form returns your data, and the explicit-id form returns/mutates the victim’s data under your session (200 with foreign data) rather than 403 — identity came from the parameter, not the session.',
    preconditions: ['endpoint accepts both alias and explicit id', 'identity resolved from the reference when present'],
    appliesTo: ['REST APIs', 'account/settings endpoints', 'profile APIs'],
    cwe: [639, 284],
    chainsWith: ['idor', 'bola-header-override'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-second-order'],
    title: 'Second-order IDOR: id validated on submit, dereferenced later without recheck',
    symptom:
      'A foreign id is accepted and stored in step one (where it may even be validated), then consumed by a later feature — an export, a redirect target, a session-cached "last viewed", a scheduled job — that fetches the object without re-authorizing.',
    procedure:
      'Map flows that persist an id you supply (schedules, saved reports, "recently viewed", multi-step wizards, redirect-after-action). Submit your own id to pass the front check, or submit the victim id and hold the intermediate response; then trigger the downstream consumer and observe whether it re-fetches by the stored id. Classic pattern: request your own receipt (validated), then request the victim receipt without following the redirect, then follow the success page that reads the last-stored id.',
    whenToUse:
      'Whenever an id crosses a step boundary — stored, queued, or session-cached — and a different function later acts on it.',
    confirmationSignal:
      'The downstream step returns/acts on the victim’s object even though the immediate response to the id submission was clean — the authorization gap is temporal (check on write, none on later read).',
    preconditions: ['id persisted/queued in one step', 'consuming step omits the ownership check'],
    appliesTo: ['multi-step flows', 'scheduled exports', 'redirect-after-POST', 'session-cached ids'],
    cwe: [639, 863, 284],
    chainsWith: ['idor', 'bola-file-export', 'bola-blind-write'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://ozguralp.medium.com/a-less-known-attack-vector-second-order-idor-attacks-14468009781a',
        title: 'A Less Known Attack Vector: Second Order IDOR Attacks',
        tier: 2,
        kind: 'writeup'
      },
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-blind-write'],
    title: 'Blind IDOR on write-only actions confirmed by side effects',
    symptom:
      'A state-changing action on a foreign id returns a generic 200/204 with no object body, so the bypass is invisible in the direct response — the change lands elsewhere.',
    procedure:
      'For write actions that do not echo the object (update, delete, invite, share, trigger-email, reassign), send the foreign id and detect success through out-of-band side effects: a notification email to the victim, an item count or list changing in the victim’s view, an audit-log entry, a webhook/callback firing, or a follow-up read (from a victim-side session) showing the mutation. Baseline against the same call on your own object to distinguish real effect from generic acceptance.',
    whenToUse:
      'DELETE/PUT/PATCH/POST endpoints that return no object representation, so read-back is unavailable.',
    confirmationSignal:
      'A side effect tied to the victim (their email arrives, their record changes, an integration fires) occurs after your call, whereas the same call with a non-existent own id produces no such effect — the write reached B’s object.',
    preconditions: ['write endpoint with no reflected object', 'an observable side channel exists'],
    appliesTo: ['REST write endpoints', 'notification/webhook systems', 'collaboration features'],
    cwe: [862, 639],
    chainsWith: ['bola-method-swap', 'bola-second-order', 'bola-webhook-config'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/',
        title: 'How to Find IDOR Vulnerabilities for Large Bounty Rewards',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-file-export'],
    title: 'IDOR on file/attachment/export/invoice/report download endpoints',
    symptom:
      'Generated artifacts — invoices, PDF reports, CSV exports, attachments — are served by a download route that maps an id or filename straight to a stored file, often bypassing the object authorization enforced on the app’s HTML views.',
    procedure:
      'Locate download/export/print routes (`/invoice/1042.pdf`, `/download?file=report_1042.csv`, `/attachments/<id>`). Enumerate or harvest neighbour ids/filenames (sequential counters, dates, predictable names) and request them under your session. These routes frequently live outside the main authorization middleware (static handler, separate microservice, signed path) and check only that the file exists. Test both the id-based and filename-based forms.',
    whenToUse:
      'Any feature that produces a downloadable per-user document and serves it by a guessable id or name.',
    confirmationSignal:
      'A neighbour id/filename returns another user’s document (200 with their PII/financials) while your own missing id returns 404 — the download path checks existence, not ownership.',
    preconditions: ['artifact served by id/filename', 'download route outside the object-authorization layer'],
    appliesTo: ['billing/invoice systems', 'reporting/export features', 'attachment storage', 'static file handlers'],
    cwe: [639, 201, 200],
    chainsWith: ['idor', 'bola-signed-url', 'path-traversal'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control/idor',
        title: 'Insecure direct object references (IDOR)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-signed-url'],
    title: 'Predictable object-storage keys and over-scoped signed URLs (S3/GCS)',
    symptom:
      'An endpoint mints a pre-signed S3/GCS URL from a client-supplied key or path, or objects live under predictable keys, so an attacker can obtain a signed URL for — or directly reach — another user’s object.',
    procedure:
      'Inspect how the signed URL is built. If the app signs a key/path taken from the request, substitute another user’s key (`pdfs/123/receipt.pdf` → `pdfs/124/receipt.pdf`) or traverse (`../`) toward the bucket root and request a fresh signature. Harvest real keys from XML listings, prior responses, or predictable naming (`<userId>_<doc>_<ts>.jpg`). Also test the signed URL’s scope: whether it grants more than the intended single GET (root listing, PUT/overwrite, or a longer TTL).',
    whenToUse:
      'File upload/download built on cloud object storage where the backend generates signatures from user-influenced keys.',
    confirmationSignal:
      'A signed URL you obtained for a key you do not own returns that object, or a crafted key/path yields a signature that lists/overwrites others’ objects — versus a 403/AccessDenied for a correctly scoped request.',
    preconditions: ['signed URL derived from client-supplied key/path', 'or predictable object keys + a signing endpoint'],
    appliesTo: ['AWS S3 pre-signed URLs', 'GCS signed URLs', 'direct-to-bucket upload/download flows'],
    cwe: [639, 284, 200],
    chainsWith: ['bola-file-export', 'idor', 'ssrf'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/',
        title: 'Bypassing and exploiting Bucket Upload Policies and Signed URLs',
        tier: 1,
        kind: 'research'
      }
    ]
  },
  {
    namespaces: ['bola-graphql-nodeid'],
    title: 'GraphQL global object ids: refetch any object via node(id:)',
    symptom:
      'A Relay-style schema exposes a `node(id: ID!)` (or `nodes`) root field that refetches any object by an opaque global id — base64 of `Type:pk` — often without the per-object authorization applied on the typed query fields.',
    procedure:
      'Grab a global id from any response and base64-decode it to reveal `["Type", pk]` / `Type:pk`. Re-encode neighbour primary keys or ids of other types and query `{ node(id:"<b64>"){ __typename ... on User { email } } }`. The generic node resolver commonly loads by primary key and skips the auth check that the domain-specific `user(id:)` field performs. Enumerate types and pks this way; combine with introspection to find sensitive types.',
    whenToUse:
      'GraphQL APIs implementing the Global Object Identification spec (Relay `node`/`nodes`, GitHub-style `node_id`).',
    confirmationSignal:
      'node(id:) returns a foreign object’s fields for a re-encoded id, while the typed query field for the same id returns null/forbidden — the generic refetch resolver bypasses the object check.',
    preconditions: ['Relay node interface exposed', 'global id reversibly encodes type+pk', 'node resolver lacks per-object authz'],
    appliesTo: ['Relay/Apollo GraphQL', 'graphql-ruby', 'Hot Chocolate', 'GitHub-style node ids'],
    cwe: [639, 284],
    chainsWith: ['graphql-introspection', 'bola-encoded-id', 'bola-graphql-mutation-authz'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        title: 'API1:2023 Broken Object Level Authorization',
        tier: 1,
        kind: 'reference'
      },
      {
        url: 'https://docs.github.com/en/graphql/guides/using-global-node-ids',
        title: 'Using global node IDs (GraphQL)',
        tier: 2,
        kind: 'reference'
      }
    ]
  },
  {
    namespaces: ['bola-graphql-mutation-authz'],
    title: 'GraphQL mutation skips the object check its query counterpart enforces',
    symptom:
      'Read queries authorize the object, but a mutation that takes the same id (deleteDocument, updateOrder, removeMember) mutates it with no per-object permission check.',
    procedure:
      'From introspection, list mutations that accept an object id. For each, supply an id you do not own and execute the mutation, then verify the effect (the object is gone/changed for its real owner). Mutations are frequently added later and inherit only authentication, not the resolver-level ownership guard the query side has. Test aliased mutations and mutations nested behind input objects.',
    whenToUse:
      'GraphQL schemas where write resolvers were bolted on and the authorization lives only in query resolvers.',
    confirmationSignal:
      'The mutation reports success and the foreign object is observably modified/deleted, while the corresponding query for that id would return forbidden/null — write authz is absent though read authz exists.',
    preconditions: ['mutation accepts a caller-supplied object id', 'resolver omits object-level authorization'],
    appliesTo: ['Apollo Server', 'graphql-js', 'Hasura permissions gaps', 'graphql-ruby'],
    cwe: [862, 639, 284],
    chainsWith: ['bola-graphql-nodeid', 'graphql-introspection', 'bola-blind-write'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        title: 'API1:2023 Broken Object Level Authorization',
        tier: 1,
        kind: 'reference'
      }
    ]
  },
  {
    namespaces: ['bola-graphql-batch-alias'],
    title: 'Mass object enumeration via GraphQL aliases/batching in one request',
    symptom:
      'A single GraphQL POST carries many aliased copies of the same field (or a batched array of operations), letting an attacker fan out hundreds of object lookups that per-request rate limits and per-object throttles never see.',
    procedure:
      'Build one document with N aliases: `a0: node(id:"..0"){...} a1: node(id:"..1"){...}` (or use query batching where the server accepts an array of operations). Iterate ids/global-ids across the alias set to pull many objects, or brute-force a guarded lookup, in a single HTTP request that counts as one against rate limits. Effective for harvesting the ids that then feed node(id:) or REST IDOR.',
    whenToUse:
      'GraphQL endpoints that allow aliasing/batching and enforce limits per HTTP request rather than per resolved field.',
    confirmationSignal:
      'One request returns many objects (including foreign ones) or succeeds after the single-request limit should have tripped — throughput far exceeds the advertised per-request rate limit.',
    preconditions: ['aliasing or batching enabled', 'no per-field cost/rate accounting'],
    appliesTo: ['Apollo Server', 'graphql-js', 'GraphQL Yoga', 'Relay node lookups'],
    cwe: [639, 799],
    chainsWith: ['bola-graphql-nodeid', 'graphql-introspection', 'bola-uuid-harvest'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/',
        title: "Didn't Notice Your Rate Limiting? GraphQL Batching Attack",
        tier: 2,
        kind: 'research'
      }
    ]
  },
  {
    namespaces: ['bola-cross-tenant'],
    title: 'Cross-tenant object access by swapping the tenant/org identifier',
    symptom:
      'A multi-tenant app scopes data by a tenant/org/workspace id carried in the path, body, header (`X-Org-Id`), or subdomain, and changing it to another tenant’s value returns that tenant’s objects.',
    procedure:
      'Identify the tenant discriminator (path segment `/orgs/<id>/...`, `tenant_id` in body, `X-Tenant`/`X-Account` header, or subdomain). As a user of tenant A, replace it with tenant B’s id/slug on list and object endpoints — including "shop revenue"-style aggregate routes — and on writes. The server often authorizes membership generally but never checks that the requested object/tenant matches the caller’s tenant. Try id enumeration and header injection where the tenant is normally implicit from the session.',
    whenToUse:
      'SaaS/multi-tenant APIs where a tenant identifier is client-supplied or overridable rather than derived solely from the session.',
    confirmationSignal:
      'A request as tenant A returns/mutates tenant B’s objects or aggregate data (200 with foreign-tenant records), whereas requesting a nonexistent tenant id returns 404 — scoping follows the supplied id, not the session.',
    preconditions: ['tenant id client-supplied or overridable', 'object-to-tenant ownership not verified'],
    appliesTo: ['multi-tenant SaaS', 'B2B dashboards', 'org-scoped REST/GraphQL APIs'],
    cwe: [639, 863, 284],
    chainsWith: ['idor', 'bola-header-override', 'bola-webhook-config'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        title: 'API1:2023 Broken Object Level Authorization',
        tier: 1,
        kind: 'reference'
      }
    ]
  },
  {
    namespaces: ['bola-webhook-config'],
    title: 'IDOR on webhook/integration configuration objects',
    symptom:
      'Webhook, API-key, OAuth-app, or integration-config records are managed by id, and the CRUD routes let one account read, edit, re-point, or delete another account’s integration.',
    procedure:
      'Enumerate integration-management routes (`/settings/webhook/<id>`, `/integrations/<id>`, `/apikeys/<id>`). As account A, list/update/delete account B’s config id. High-value variants: change a webhook’s target URL to exfiltrate B’s event stream, disable B’s integration (DoS), or read a stored secret/token. Test GET (read secret), PUT (re-point URL), and DELETE separately — these settings routes are often authorized only by "is logged in".',
    whenToUse:
      'Apps exposing per-account webhooks, API keys, or third-party integrations addressable by id.',
    confirmationSignal:
      'You read/modify/delete a config id you do not own (B’s webhook URL changes, B’s integration stops firing, or B’s secret is returned), while your own nonexistent id gives 404 — the settings route omits ownership.',
    preconditions: ['integration/webhook objects addressable by id', 'no ownership check on the settings route'],
    appliesTo: ['SaaS integration settings', 'webhook managers', 'API-key/OAuth-app dashboards'],
    cwe: [639, 862, 284],
    chainsWith: ['bola-cross-tenant', 'bola-blind-write', 'ssrf'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://hackersatty.com/critical-idor-vulnerability/',
        title: 'Critical IDOR Vulnerability in Webhook Deletion',
        tier: 3,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-header-override'],
    title: 'Object/identity override via trusted custom headers (X-User-Id, X-Account-Id)',
    symptom:
      'The backend derives the acting identity or target object from a custom header (`X-User-Id`, `X-UID`, `X-Account-Id`, `X-Customer`) that the frontend/gateway is supposed to set, but which a direct client can forge.',
    procedure:
      'Look for internal identity headers in JS, mobile traffic, or gateway conventions. Add or override them on a direct request: `X-User-Id: <VICTIM>`, `X-Account-Id: <B>`, `X-Forwarded-User`, `X-Consumer-Custom-Id`. Backends behind an API gateway often trust these implicitly (assuming only the gateway sets them). Combine with `me`-alias endpoints so the header supplies the id the route otherwise derives from the session.',
    whenToUse:
      'Microservice/gateway architectures where identity is passed downstream in a header and the service does not re-verify it.',
    confirmationSignal:
      'Injecting the header makes the response reflect the victim’s object/identity (200 with foreign data), whereas the same request without the header returns your own — identity followed the client-set header.',
    preconditions: ['identity/object derived from a client-reachable header', 'header not stripped/validated at the edge'],
    appliesTo: ['API gateways (Kong, Apigee)', 'microservices', 'reverse-proxied backends'],
    cwe: [639, 472],
    chainsWith: ['bola-keyword-me', 'bola-cross-tenant', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/',
        title: 'How to Find IDOR Vulnerabilities for Large Bounty Rewards',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-wildcard-query'],
    title: 'Wildcard / partial-match in an id or lookup parameter to dump objects',
    symptom:
      'A lookup that expects one id/username accepts a wildcard, prefix, or empty value and returns many objects — or a search/typeahead scoped to the caller silently returns everyone’s records.',
    procedure:
      'Replace an exact id/identifier with `*`, `%`, a common prefix (`sam*`), an empty string, or a broadening operator, on lookup, search, autocomplete, and "check availability" endpoints. Also strip a scoping filter (drop `?user=` entirely) to see whether results default to all objects rather than the caller’s. Where a typeahead is meant to match only your contacts/records, verify it does not surface other tenants’ data.',
    whenToUse:
      'Search/lookup/typeahead endpoints where a single-object parameter may be interpreted as a pattern or where scoping is optional.',
    confirmationSignal:
      'A wildcard/empty value returns a set that includes objects you do not own (other users/tenants), versus a specific own-scoped value returning only your record — the filter is pattern-matched or absent, not ownership-bound.',
    preconditions: ['lookup accepts pattern/partial/empty input', 'results not constrained to the caller’s objects'],
    appliesTo: ['search/autocomplete APIs', 'user-lookup endpoints', 'SSO/dealer portals'],
    cwe: [639, 284, 200],
    chainsWith: ['bola-uuid-harvest', 'bola-cross-tenant', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://samcurry.net/web-hackers-vs-the-auto-industry',
        title: 'Web Hackers vs. The Auto Industry',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities',
        title: 'IDOR: A complete guide to exploiting advanced IDOR vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['bola-business-identifier'],
    title: 'Object access via a business identifier (VIN, account/policy number, email) not bound to the session',
    symptom:
      'The object reference is a real-world business key — a VIN, account/policy/membership number, order number, or email — known or enumerable to an attacker, and the API acts on it without confirming it belongs to the caller.',
    procedure:
      'Find endpoints keyed by an external identifier rather than an internal id. Obtain the key from public sources (a VIN is visible on the windshield; order/policy numbers appear on documents; emails are public) or enumerate its structured format. Submit it as an authenticated (or under-authenticated) user and check whether the service returns the associated PII or performs the privileged action. These keys are treated as "known only to the owner" but are effectively public.',
    whenToUse:
      'APIs that look up or command a resource by a human-facing identifier (automotive/telematics, insurance, banking, logistics).',
    confirmationSignal:
      'Supplying a business key you do not own returns that owner’s PII or lets you act on their resource (e.g. a VIN returns another owner’s account and vehicle controls), while an invalid key returns not-found — authorization rode on knowing the key.',
    preconditions: ['resource keyed by a public/enumerable business identifier', 'identifier not tied to the session’s ownership'],
    appliesTo: ['connected-vehicle/telematics APIs', 'insurance/banking portals', 'order/shipment lookups'],
    cwe: [639, 359, 284],
    chainsWith: ['idor', 'bola-wildcard-query', 'bola-cross-tenant'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://samcurry.net/web-hackers-vs-the-auto-industry',
        title: 'Web Hackers vs. The Auto Industry',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        title: 'API1:2023 Broken Object Level Authorization',
        tier: 1,
        kind: 'reference'
      }
    ]
  }
];
