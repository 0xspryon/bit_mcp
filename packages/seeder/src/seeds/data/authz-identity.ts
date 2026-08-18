import type { CorpusRecord } from './types';

/**
 * Corpus slice: authorization bypass via identity, token, session &
 * federation flaws — techniques that make the server treat you as a different
 * or higher-privileged principal (JWT / OAuth / OIDC / SAML / session).
 *
 * Distinct from the two token/identity records already in `0001_corpus.ts`
 * (`jwt-alg-confusion` covering RS256->HS256 + alg:none, and `oauth-redirect`
 * covering redirect_uri manipulation) — those are intentionally NOT re-authored
 * here. Every record below is a distinct technique with a differential
 * confirmation signal and verified, renowned sourcing.
 */
export const records: readonly CorpusRecord[] = [
  // -------------------------------------------------------------------------
  // JWT — key/verification & header-injection primitives
  // -------------------------------------------------------------------------
  {
    namespaces: ['jwt-unverified-signature'],
    title: 'JWT signature not verified — decode()-instead-of-verify() claim tampering',
    symptom:
      'A JWT-authenticated endpoint accepts tokens whose payload has been edited without re-signing. The backend reads claims from a decoded token but never validates the signature (a classic decode() vs verify() mix-up), so any claim can be rewritten.',
    procedure:
      'Capture a valid token and base64url-decode the payload. Flip an authorization-bearing claim (e.g. role:user -> role:admin, isAdmin:false -> true, or the user/sub id) and leave the original signature untouched, then replay. If accepted, the signature is not checked at all. Also test a syntactically valid but wrong signature and a signature copied from a different token — if either is accepted, verification is absent or non-fatal.',
    whenToUse:
      'Any JWT-authenticated API, especially frameworks/middleware where developers call a decode helper for convenience instead of the verifying call.',
    confirmationSignal:
      'A token whose payload was modified but whose signature was NOT recomputed is accepted and grants the tampered privilege — while the SAME request with an intact original token and an intact (unmodified) payload is the control. Acceptance of the mismatched signature/payload pair, not merely a 200, proves the signature is unverified.',
    preconditions: ['server derives authz from JWT claims', 'signature verification missing or non-blocking'],
    appliesTo: ['Node jsonwebtoken', 'PyJWT', 'Java jjwt', 'Go golang-jwt', 'API gateways'],
    cwe: [347, 287, 345],
    chainsWith: ['jwt-claim-escalation', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — Web Security Academy',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['jwt-weak-hmac-secret'],
    title: 'JWT weak/guessable HMAC secret cracked offline, then re-signed with elevated claims',
    symptom:
      'An HS256/HS384/HS512 JWT is signed with a low-entropy, default, or placeholder secret (e.g. "secret", "changeme", a copied sample key). The secret can be recovered offline from a single captured token, after which the attacker mints arbitrary valid tokens.',
    procedure:
      'Capture any valid HS-signed token. Feed the full token to a brute-force/dictionary cracker (hashcat mode 16500, jwt_tool, or john) against a wordlist such as rockyou plus common framework default secrets. Once the secret is recovered, edit the payload to elevate claims (role/scope/sub) and HMAC-sign with the cracked key so the signature verifies legitimately.',
    whenToUse:
      'JWTs using a symmetric HS* algorithm where the signing secret may be short, default, or reused from public sample code.',
    confirmationSignal:
      'The offline cracker returns a secret that reproduces the exact signature of the captured token (deterministic HMAC match), and a freshly forged token signed with that secret — carrying claims the attacker never legitimately held — is accepted by the server. The differential is that the forged token verifies where a random-secret forgery would not.',
    preconditions: ['symmetric HMAC-signed JWT', 'low-entropy/default/reused secret'],
    appliesTo: ['Node jsonwebtoken', 'PyJWT', 'Java jjwt', 'hashcat', 'jwt_tool'],
    cwe: [326, 347, 521],
    chainsWith: ['jwt-claim-escalation', 'jwt-unverified-signature'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — Brute-forcing secret keys',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JSON Web Token Cheat Sheet',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['jwt-kid-injection'],
    title: 'JWT kid header injection — path traversal / SQLi to control the verification key',
    symptom:
      'The token header carries a kid (key id) that the server uses to look up the verification key from a file path or database row. Because kid is attacker-controlled and unauthenticated, it can be steered to a predictable/attacker-known key so a self-signed token verifies.',
    procedure:
      'Inspect the header kid. For file-backed key stores, inject path traversal to point kid at a file whose contents the attacker knows or controls — e.g. kid pointing at /dev/null (empty key -> sign HS with empty secret) or at a static public file — then sign the token with that known value. For DB-backed lookups, inject SQL into kid (e.g. a UNION that returns an attacker-chosen key string) so the returned "key" is one the attacker signed with. Edit claims before signing.',
    whenToUse:
      'JWT verifiers that resolve the key dynamically from the token-supplied kid via a filesystem path or a SQL query.',
    confirmationSignal:
      'A token whose kid was manipulated (traversal or SQLi) verifies with a key the attacker chose, and the elevated-claims token is accepted — whereas the same forged token with an unmodified kid is rejected. The kid-dependent acceptance isolates the injection as the cause.',
    preconditions: ['kid used to select the verification key', 'kid resolves via file path or SQL without sanitisation'],
    appliesTo: ['Node.js', 'Java', 'PHP', 'JWKS-from-DB designs', 'jwt_tool'],
    cwe: [347, 22, 89],
    chainsWith: ['sqli', 'path-traversal', 'jwt-claim-escalation'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — kid parameter',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['jwt-jku-ssrf'],
    title: 'JWT jku header pointing at an attacker-hosted JWKS',
    symptom:
      'The server fetches the JWK Set from a URL named in the token header (jku). If jku is not strictly allowlisted, the attacker hosts their own JWKS and signs tokens with the matching private key, so the forged token verifies against the attacker\'s public key.',
    procedure:
      'Generate an RSA keypair, publish a JWKS containing the public key at an attacker-controlled URL, and set the token header jku to that URL (kid matching the published key). Sign the forged, elevated-claims token with the attacker private key. If the server enforces a same-origin/allowlist on jku, defeat it with URL-parsing tricks (embedded credentials trusted@attacker.com, @-host confusion, path/fragment tricks, open-redirect or subdomain-takeover targets under the trusted origin).',
    whenToUse:
      'JWT verifiers that dynamically retrieve signing keys from a jku/JWKS URL taken from the token header.',
    confirmationSignal:
      'The server issues an outbound request to the attacker-hosted JWKS URL (out-of-band hit from the server IP), then accepts the token signed by the attacker\'s private key — the same token with jku pointing anywhere the server will not fetch is rejected. Acceptance is contingent on the attacker JWKS being fetched.',
    preconditions: ['jku URL honoured from the token header', 'no strict host allowlist on the JWKS source'],
    appliesTo: ['OAuth/OIDC resource servers', 'Node.js', 'Java', 'jwt_tool'],
    cwe: [347, 918, 345],
    chainsWith: ['ssrf', 'open-redirect', 'subdomain-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — jku parameter',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — trusting header key material',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['jwt-x5u-injection'],
    title: 'JWT x5u / x5c header injection — attacker-supplied X.509 cert as the verification key',
    symptom:
      'The verifier trusts an X.509 certificate named by the token header — either fetched from the x5u URL or embedded inline in x5c — and uses its public key to validate the signature, without pinning the certificate to a trusted issuer.',
    procedure:
      'Mint a self-signed X.509 certificate and RSA keypair. For x5u, host the PEM/DER at an attacker URL and set x5u to it (defeating any allowlist with the same URL-parsing tricks as jku). For x5c, embed the self-signed certificate chain directly in the header. Sign the elevated-claims token with the matching private key; a verifier that trusts the header-named cert validates it.',
    whenToUse:
      'JWT verifiers that accept x5u (cert URL) or x5c (inline cert chain) header parameters and do not validate the chain against a pinned trust anchor.',
    confirmationSignal:
      'A token whose signature is verifiable ONLY by the attacker-supplied certificate (self-signed, chaining to no trusted root) is accepted, and the elevated claims take effect — whereas stripping the x5u/x5c header or pointing it at an untrusted-but-unfetched location fails. Trust of the attacker cert is the discriminator.',
    preconditions: ['x5u/x5c honoured from the token header', 'certificate not validated against a pinned trust anchor'],
    appliesTo: ['OAuth/OIDC resource servers', 'Java', '.NET', 'Node.js'],
    cwe: [347, 295, 918],
    chainsWith: ['ssrf', 'jwt-jku-ssrf'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — x5u/x5c header key material',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['jwt-jwk-header-injection'],
    title: 'JWT self-signed via embedded jwk header key',
    symptom:
      'A misconfigured verifier uses the public key embedded inline in the token\'s jwk header parameter to validate the signature, so the attacker can supply their own key and self-sign a fully valid token.',
    procedure:
      'Generate an RSA keypair. Build a token whose header embeds the attacker public key in a jwk object (and a matching kid), sign the elevated-claims payload with the attacker private key, and send it. If the library validates against the header-embedded jwk instead of a server-side key, the token verifies. Tools like the JWT Editor Burp extension or jwt_tool automate embedding the jwk.',
    whenToUse:
      'JWT verifiers that honour an inline jwk in the header (RFC 7515 permits it, but trusting it for verification is the flaw).',
    confirmationSignal:
      'A token self-signed with a freshly generated keypair, carrying that keypair\'s public key in the jwk header, is accepted with elevated claims — while the identical token with the jwk header removed is rejected. Acceptance is bound to the server trusting the embedded key.',
    preconditions: ['verifier trusts the header-embedded jwk', 'no server-side pinning of the signing key'],
    appliesTo: ['Node.js', 'Java', 'OAuth resource servers', 'Burp JWT Editor', 'jwt_tool'],
    cwe: [347, 287, 345],
    chainsWith: ['jwt-jku-ssrf', 'jwt-claim-escalation'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — injecting self-signed JWTs via the jwk parameter',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — jwk header key material',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['jwt-claim-escalation'],
    title: 'JWT role/scope claim escalation (vertical privilege via trusted claims)',
    symptom:
      'Once a token can be forged or re-signed, authorization decisions keyed on claims like role, scope, permissions, groups, or admin flags can be lifted — the server treats the claim as ground truth for what the principal may do.',
    procedure:
      'Enumerate authorization-bearing claims by diffing tokens across privilege levels (a low-priv vs a higher-priv account) and inspecting protected endpoints for the claim that gates them. Using any working forgery primitive (weak secret, jwk/jku/kid/x5u injection, alg confusion), set the claim to a privileged value (role:admin, scope:"admin:write", groups:["superuser"]). Confirm the escalation reaches functionality the account never had, not merely reflection of the claim.',
    whenToUse:
      'JWT-authenticated apps that make vertical authorization decisions directly from token claims once a signing/verification weakness exists.',
    confirmationSignal:
      'A forged token with an elevated authorization claim executes an admin/privileged function that the base account is denied when using its legitimate token — the SAME action, same account context, differing only by the injected claim. Successful state change or admin-only data return is the signal, not a reflected claim.',
    preconditions: ['a JWT forgery/re-sign primitive available', 'server authorizes from token claims without a server-side check'],
    appliesTo: ['REST APIs', 'GraphQL', 'microservices', 'API gateways'],
    cwe: [863, 639, 347],
    chainsWith: ['jwt-weak-hmac-secret', 'jwt-jwk-header-injection', 'jwt-kid-injection', 'jwt-alg-confusion'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/jwt',
        title: 'JWT attacks — modifying claims',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['jwt-expiration-replay'],
    title: 'JWT expiration / revocation not enforced — stale-token replay',
    symptom:
      'The verifier checks the signature but not the exp claim (or ignores nbf/iat, or has no revocation list), so an expired, logged-out, or otherwise-invalidated token continues to authenticate — a captured token stays usable indefinitely.',
    procedure:
      'Capture a valid token and note its exp. After expiry (or after the user logs out / has access revoked), replay the same token. If it still authenticates, expiration/revocation is not enforced. Also test tokens with exp set far in the future, exp removed entirely, or a token that should have been denylisted (jti) after logout — acceptance of any confirms the missing lifecycle check.',
    whenToUse:
      'Stateless JWT sessions where server-side revocation is absent and the resource server may skip temporal-claim validation.',
    confirmationSignal:
      'A token that is provably past its exp (or was invalidated by logout/revocation) still returns authenticated data — while a correctly-behaving verifier would answer 401. The differential is time/lifecycle: same token, before vs after it should have been rejected.',
    preconditions: ['exp/revocation not validated on the resource server', 'no jti denylist for logout/revocation'],
    appliesTo: ['stateless JWT APIs', 'Node.js', 'Java', 'mobile backends'],
    cwe: [613, 287, 384],
    chainsWith: ['token-swapping-identity-confusion'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — token revocation & replay',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['jwt-audience-confusion'],
    title: 'JWT audience/issuer not pinned — cross-service token reuse (confused deputy)',
    symptom:
      'A microservice or API validates a JWT\'s signature but not its aud (audience) or iss (issuer), so a legitimately-signed token minted for a different service, environment, or lower-trust context is accepted — a token good for service A unlocks service B.',
    procedure:
      'Collect valid tokens the attacker can legitimately obtain from adjacent contexts (a public/low-trust service sharing the same signing key or IdP, a staging environment, a different first-party app). Replay each against the target service. If a token whose aud/iss names a different relying party is accepted, audience/issuer binding is missing. Compare the privileges the target grants versus the token\'s intended context.',
    whenToUse:
      'Fleets of services that share a signing key or a common IdP but each expect tokens scoped to themselves via aud/iss.',
    confirmationSignal:
      'A validly-signed token whose aud/iss designates a DIFFERENT service is accepted by the target and grants access — whereas a correct implementation rejects the audience mismatch. The token is cryptographically genuine; only the audience binding is being bypassed, isolating the flaw from signature issues.',
    preconditions: ['shared signing key or common issuer across services', 'target does not validate aud/iss'],
    appliesTo: ['microservices', 'service meshes', 'multi-app SSO estates', 'API gateways'],
    cwe: [863, 347, 287],
    chainsWith: ['oauth-token-audience-confusion', 'jwt-claim-escalation'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — validating audience and issuer',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // SAML — assertion trust, signature scope & canonicalization
  // -------------------------------------------------------------------------
  {
    namespaces: ['saml-xsw'],
    title: 'SAML XML Signature Wrapping (XSW)',
    symptom:
      'A SAML SP verifies a signature over one element but processes claims from a different, attacker-injected element. By restructuring the XML so the signed assertion still validates while the SP reads an unsigned attacker assertion, the attacker authenticates as anyone.',
    procedure:
      'Capture a signed SAML Response. Move the original signed assertion to a wrapper location the signature reference still resolves to (e.g. inside the Signature/Object, or a decoy element with the original Id), and inject a second, forged assertion with an attacker-chosen NameID/attributes where the SP\'s claim-extraction logic will read it. Iterate the many XSW permutations (different parent nodes, duplicated Ids, sibling placement) since which one works depends on how the SP couples signature-reference resolution to claim reading.',
    whenToUse:
      'SAML SPs whose signature verification and assertion-processing use different element lookups (DOM position vs signed reference), a broad class since 2012.',
    confirmationSignal:
      'A Response that still passes signature validation (the original signed blob is intact) but whose SP-consumed NameID/attributes are the attacker-injected, UNSIGNED values logs the attacker in as a different (often admin) user — the divergence between "what was signed" and "what was read" is the proof, not merely a valid signature.',
    preconditions: ['SP verifies a signature reference decoupled from claim extraction', 'attacker has one validly signed Response to restructure'],
    appliesTo: ['SAML SPs', 'Shibboleth', 'OneLogin', 'python-saml', 'ruby-saml', 'OpenSAML'],
    cwe: [347, 345, 287],
    chainsWith: ['saml-comment-injection', 'saml-unsigned-assertion'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html',
        title: 'OWASP SAML Security Cheat Sheet — XML Signature Wrapping',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['saml-comment-injection'],
    title: 'SAML NameID XML comment injection (canonicalization truncation)',
    symptom:
      'Inserting an XML comment inside the NameID does not invalidate the signature (canonicalization ignores comments) but causes the SP\'s text extractor to read only the fragment before the comment — so admin@company.com<!--x-->.evil.com is signed intact yet read as admin@company.com.',
    procedure:
      'Register or control an account whose identifier embeds the victim\'s as a prefix followed by a comment, e.g. NameID text victim@company.com<!--anything-->attacker-suffix, obtained via a legitimately signed assertion for the attacker identity. Because C14N strips the comment before signing/verification, the signature stays valid; if the SP\'s XML API returns only the first text node, it extracts victim@company.com and authenticates the attacker as the victim.',
    whenToUse:
      'SAML SPs on XML libraries whose text-node extraction stops at a comment boundary while signature validation canonicalizes it away (the 2018 Duo/Ludwig class).',
    confirmationSignal:
      'A signed assertion for an attacker-controlled identity that contains an injected comment is accepted, and the session is established as the DIFFERENT victim identity (the pre-comment substring) — the same assertion without the comment authenticates only as the attacker. The comment flips the resolved identity while the signature stays valid.',
    preconditions: ['SP text extraction truncates at XML comments', 'canonicalization removes comments before signature check'],
    appliesTo: ['python-saml', 'ruby-saml', 'omniauth-saml', 'OneLogin toolkits', 'Shibboleth'],
    cwe: [290, 347, 287],
    chainsWith: ['saml-xsw'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://developer.okta.com/blog/2018/02/27/a-breakdown-of-the-new-saml-authentication-bypass-vulnerability',
        title: 'A Breakdown of the New SAML Authentication Bypass Vulnerability',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html',
        title: 'OWASP SAML Security Cheat Sheet',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['saml-unsigned-assertion'],
    title: 'SAML unsigned / partially-signed assertion accepted',
    symptom:
      'The SP accepts a Response where the assertion (or the whole Response) is unsigned, or only the Response envelope is signed while the assertion is not — allowing the attacker to author or swap in an assertion the IdP never signed.',
    procedure:
      'Take a valid Response and strip the assertion signature (or the Signature element entirely), editing the NameID/attributes to a target/admin identity. Also test signing only the outer Response while injecting an unsigned inner assertion, and vice versa. If the SP does not require the specific element carrying identity to be signed and validated, the forged assertion is trusted.',
    whenToUse:
      'SAML SPs that fail to enforce "the assertion conveying identity must be signed and that signature must validate" (WantAssertionsSigned effectively off).',
    confirmationSignal:
      'A Response whose identity-bearing assertion carries NO valid signature is accepted and authenticates the attacker-chosen identity — where a conformant SP rejects it as unsigned. Acceptance of the unsigned/edited assertion, versus rejection when the same tampering is applied to a required-signed element, isolates the missing enforcement.',
    preconditions: ['SP does not require the identity assertion to be signed', 'signature scope not pinned to the consumed element'],
    appliesTo: ['SAML SPs', 'misconfigured OpenSAML/Shibboleth', 'SaaS SAML integrations'],
    cwe: [347, 287, 345],
    chainsWith: ['saml-xsw', 'saml-assertion-replay'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html',
        title: 'OWASP SAML Security Cheat Sheet — validate signatures',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['saml-assertion-replay'],
    title: 'SAML assertion replay / missing audience, recipient & InResponseTo validation',
    symptom:
      'A previously used (or intercepted) SAML assertion is accepted again, or an assertion minted for a different SP/session is honoured, because the SP does not enforce one-time use, Audience (=EntityID), Recipient/Destination (=ACS URL), NotOnOrAfter, or InResponseTo binding.',
    procedure:
      'Capture a valid Response and replay it verbatim to establish whether OneTimeUse/assertion-ID caching is enforced. Then test cross-context reuse: submit an assertion whose Audience names a different SP, whose Recipient/Destination is a different ACS, whose NotOnOrAfter has passed, or with no InResponseTo matching an outstanding AuthnRequest. Any acceptance shows the corresponding condition is unvalidated.',
    whenToUse:
      'SAML SPs that validate the signature but skip the SubjectConfirmationData / Conditions checks that bind an assertion to one SP, one request, and one short window.',
    confirmationSignal:
      'A replayed or wrong-audience/expired assertion authenticates a session — while a correctly-scoped assertion is the baseline and the reused/mis-scoped one should be rejected. The signal is that an assertion outside its intended one-time, single-SP, in-window scope is still accepted.',
    preconditions: ['signature valid but Conditions/SubjectConfirmation not enforced', 'no assertion-ID replay cache'],
    appliesTo: ['SAML SPs', 'SSO integrations', 'IdP-initiated SSO flows'],
    cwe: [294, 384, 287],
    chainsWith: ['saml-unsigned-assertion', 'session-fixation'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html',
        title: 'OWASP SAML Security Cheat Sheet — replay, audience & recipient',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // OAuth 2.0 / OIDC — scope, token audience, flow & federation attacks
  // -------------------------------------------------------------------------
  {
    namespaces: ['oauth-scope-escalation'],
    title: 'OAuth scope escalation (scope upgrade not enforced at token exchange or resource)',
    symptom:
      'A client is granted a limited scope, but the attacker widens it — adding scopes at the code/token exchange, or at the /userinfo or resource call — because the authorization server does not pin issued scope to what was consented, or the resource server does not enforce scope at all.',
    procedure:
      'Complete a normal consent for a narrow scope. At the token endpoint, append or broaden the scope parameter on the code-for-token exchange (e.g. add admin, write, or an extra resource scope) and see whether the returned token carries it. In implicit/browser flows, add scope to the /userinfo or resource request directly. Separately, take a legitimately narrow token and call higher-privilege resource endpoints to test whether scope is enforced server-side.',
    whenToUse:
      'OAuth2/OIDC deployments where issued scope may exceed consented scope, or where resource servers trust the presence of a token more than its scope.',
    confirmationSignal:
      'A token obtained after consenting to a narrow scope successfully invokes an operation that requires a broader scope — either because the AS minted the broader scope on request, or the resource server ignored scope. The differential is consented scope vs exercised capability, not merely a 200.',
    preconditions: ['issued scope not bound to consented scope, OR resource server does not check scope'],
    appliesTo: ['OAuth2 authorization servers', 'OIDC providers', 'API resource servers'],
    cwe: [863, 862, 285],
    chainsWith: ['oauth-token-audience-confusion', 'jwt-claim-escalation'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 authentication vulnerabilities — flawed scope validation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['oauth-token-audience-confusion'],
    title: 'OAuth social-login token not verified for the client (audience) — account takeover',
    symptom:
      'A "sign in with X" backend accepts an access/ID token and reads the user identity from it without verifying the token was issued for THIS application (its client_id / audience). A token minted for the attacker\'s own app is accepted, letting the attacker log in as the victim it names.',
    procedure:
      'Register an attacker application with the IdP and obtain an access token for a victim (e.g. by having the victim use the attacker app, or via any token the attacker legitimately holds for the same user). Submit that token to the target\'s social-login token-verification endpoint. If the target calls the IdP\'s userinfo/token-info but never checks that the token\'s aud/client_id equals its own, it establishes a session as the identity the token names.',
    whenToUse:
      'Social/federated login backends that validate a token\'s existence/signature but skip audience (aud / client_id / appid) verification — the Salt Labs "OAuth" class.',
    confirmationSignal:
      'A token whose audience is the ATTACKER\'s client_id (not the target\'s) is accepted and yields a session as the token\'s subject — where a correct implementation rejects the audience mismatch. The token is genuine and IdP-issued; only the cross-client audience is being abused.',
    preconditions: ['backend does not verify token audience/client_id', 'attacker can obtain a valid token for the victim from the same IdP'],
    appliesTo: ['Sign in with Google/Facebook/Apple', 'social-login backends', 'mobile OAuth flows'],
    cwe: [287, 345, 863],
    chainsWith: ['jwt-audience-confusion', 'oidc-email-verification-trust'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts',
        title: 'Oh-Auth — Abusing OAuth to take over millions of accounts',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 authentication vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['oauth-idp-mixup'],
    title: 'OAuth IdP mix-up attack',
    symptom:
      'A client that supports multiple identity providers can be confused about which IdP the user actually chose, so it sends the authorization code/token issued by an honest IdP to the attacker\'s IdP (or its own endpoint keyed to the wrong IdP), leaking the credential.',
    procedure:
      'Start a flow selecting the attacker IdP so the client associates the session with it, but have the user authenticate at the honest IdP (via a manipulated first request / redirect). Because the client fails to bind the authorization response to the specific IdP it was issued by (no iss in the response, or unchecked), it delivers the honest IdP\'s code to the attacker-controlled token endpoint. Capture the code and redeem it, or use it to log in as the victim.',
    whenToUse:
      'Multi-IdP OAuth/OIDC clients that do not verify which authorization server issued a given response (missing iss validation — RFC 9700 4.4).',
    confirmationSignal:
      'The honest IdP\'s authorization code/token is delivered to an attacker-controlled endpoint (or accepted by the client as if from the attacker IdP), enabling login as the victim — the differential from a safe client is that the response is not bound to its issuer, so it is honoured in the wrong IdP context.',
    preconditions: ['client supports multiple IdPs', 'authorization response not bound to the issuing IdP (no iss check)'],
    appliesTo: ['multi-IdP OAuth clients', 'OIDC relying parties', 'SSO brokers'],
    cwe: [287, 290, 863],
    chainsWith: ['oauth-code-injection', 'oauth-csrf-state'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://datatracker.ietf.org/doc/html/rfc9700',
        title: 'RFC 9700 — OAuth 2.0 Security BCP §4.4 Mix-Up Attacks',
        tier: 1,
        kind: 'spec'
      }
    ]
  },
  {
    namespaces: ['oauth-code-injection'],
    title: 'OAuth authorization code injection',
    symptom:
      'An authorization code stolen or issued for the attacker (or for the victim) is injected into a different session at the client\'s redirect/callback, binding the victim\'s browser to the attacker\'s account or vice versa, because the code is not bound to the browser that requested it (no PKCE / no state binding).',
    procedure:
      'Obtain a valid authorization code (leaked via referer/logs, or freshly minted for an attacker-controlled account). Replay it into a victim\'s in-progress callback (or your own session) so the client exchanges an attacker code in the victim context. Without PKCE binding the code to the original code_verifier, or without nonce/state binding, the client accepts the injected code and links the session to the wrong account.',
    whenToUse:
      'OAuth clients that redeem authorization codes without PKCE and without binding the code to the requesting browser/nonce (RFC 9700 4.5).',
    confirmationSignal:
      'A code minted in one browser/account context is redeemed and honoured in a DIFFERENT session, cross-linking accounts (attacker resources appear under victim, or the victim is logged into the attacker\'s account) — a correctly PKCE/nonce-bound client rejects the code as unbound. The cross-context acceptance is the signal.',
    preconditions: ['no PKCE code_verifier binding', 'no nonce/state binding of the code to the session'],
    appliesTo: ['OAuth2 clients', 'OIDC relying parties', 'public/mobile clients'],
    cwe: [345, 384, 287],
    chainsWith: ['oauth-idp-mixup', 'oauth-pkce-downgrade', 'oauth-csrf-state'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://datatracker.ietf.org/doc/html/rfc9700',
        title: 'RFC 9700 — OAuth 2.0 Security BCP §4.5 Authorization Code Injection',
        tier: 1,
        kind: 'spec'
      }
    ]
  },
  {
    namespaces: ['oauth-pkce-downgrade'],
    title: 'OAuth PKCE downgrade',
    symptom:
      'An authorization server that supports PKCE does not enforce it: an attacker who intercepts an authorization code redeems it without presenting a code_verifier by stripping the PKCE parameters, defeating the protection the client believed it had.',
    procedure:
      'Observe that the client uses PKCE (code_challenge in the authorization request). Intercept an authorization code, then at the token endpoint omit the code_verifier entirely (or send a request that never carried a code_challenge). If the AS issues tokens despite the missing verifier, PKCE is not enforced and an intercepted code is fully redeemable by the attacker.',
    whenToUse:
      'OAuth deployments where PKCE is advertised but the token endpoint does not require a matching code_verifier for codes issued with a challenge (RFC 9700 4.8).',
    confirmationSignal:
      'An intercepted authorization code is exchanged for tokens WITHOUT a valid code_verifier — where correct PKCE enforcement rejects the exchange. The token issuance despite the missing/incorrect verifier, versus rejection when enforced, isolates the downgrade.',
    preconditions: ['AS does not require code_verifier when a code_challenge was used', 'attacker can intercept the code'],
    appliesTo: ['public/mobile OAuth clients', 'SPAs', 'authorization servers'],
    cwe: [345, 287, 863],
    chainsWith: ['oauth-code-injection'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://datatracker.ietf.org/doc/html/rfc9700',
        title: 'RFC 9700 — OAuth 2.0 Security BCP §4.8 PKCE Downgrade Attack',
        tier: 1,
        kind: 'spec'
      }
    ]
  },
  {
    namespaces: ['oauth-csrf-state'],
    title: 'OAuth login CSRF via missing/unvalidated state',
    symptom:
      'The callback does not validate a per-session state value, so an attacker can complete their own authorization and trick the victim\'s browser into consuming the attacker\'s code — logging the victim into the ATTACKER\'s account (or silently linking the attacker\'s identity), enabling data capture under the attacker-controlled account.',
    procedure:
      'Begin an OAuth flow as the attacker and capture the resulting authorization code/callback URL before it is used. Deliver that callback URL to the victim (auto-submitting form / image). If the client\'s callback has no state, or does not tie state to the victim\'s session, the victim\'s browser completes login into the attacker\'s account; anything the victim then enters (payment, notes) lands in an account the attacker controls. The linking variant silently attaches the attacker\'s social identity to the victim.',
    whenToUse:
      'OAuth/OIDC callbacks lacking an unpredictable, session-bound state parameter (RFC 9700 4.7 CSRF).',
    confirmationSignal:
      'A cross-site request drives the victim\'s browser through the callback and establishes a session tied to the ATTACKER\'s account (victim actions surface in the attacker account) — a state-protected client rejects the mismatched/absent state. The forced cross-account session, not merely a redirect, is the proof.',
    preconditions: ['no state parameter, or state not bound to the user session', 'callback accepts a code the victim did not initiate'],
    appliesTo: ['OAuth2 clients', 'OIDC relying parties', 'social login callbacks'],
    cwe: [352, 287, 384],
    chainsWith: ['sso-account-linking-takeover', 'oauth-code-injection'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 authentication vulnerabilities — flawed CSRF protection',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://datatracker.ietf.org/doc/html/rfc9700',
        title: 'RFC 9700 — OAuth 2.0 Security BCP §4.7 CSRF',
        tier: 1,
        kind: 'spec'
      }
    ]
  },
  {
    namespaces: ['oauth-implicit-token-leak'],
    title: 'OAuth access token leakage via Referer / browser history (implicit-style responses)',
    symptom:
      'Access tokens (or codes) returned in the URL fragment/query of the redirect land in the browser history and are forwarded in the Referer header to third-party resources on the callback page, letting an attacker who controls or observes that off-site content harvest the token and impersonate the user.',
    procedure:
      'Complete a flow where the token/code is delivered in the URL (implicit grant, or code in query). Inspect the callback page for outbound requests to third-party origins (analytics, ad, image, script) — those carry the token-bearing URL in Referer. Also test whether the token persists in browser history / is re-sent on back-navigation. Capture the leaked token from the third-party log or history and replay it.',
    whenToUse:
      'Clients using implicit grant or returning credentials in the URL, with third-party content on the redirect landing page (RFC 9700 4.2/4.3).',
    confirmationSignal:
      'The access token/code appears in a Referer header sent to an attacker-observable third-party origin (or is recoverable from browser history) and, when replayed, authenticates as the victim — the leak channel and successful replay together, not just the token being in the URL.',
    preconditions: ['credential returned in URL fragment/query', 'third-party content on the callback page or history exposure'],
    appliesTo: ['implicit-grant clients', 'legacy SPAs', 'OAuth callbacks with analytics/ads'],
    cwe: [200, 598, 287],
    chainsWith: ['oauth-code-injection', 'oauth-token-audience-confusion'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://datatracker.ietf.org/doc/html/rfc9700',
        title: 'RFC 9700 — OAuth 2.0 Security BCP §4.2/4.3 Credential Leakage',
        tier: 1,
        kind: 'spec'
      }
    ]
  },
  {
    namespaces: ['oauth-device-code-phishing'],
    title: 'OAuth device authorization grant phishing (device code)',
    symptom:
      'An attacker initiates the OAuth 2.0 device-code flow, then phishes the victim into entering the attacker\'s user_code at the IdP\'s legitimate verification page and approving — tokens are then issued to the attacker\'s waiting client, satisfying MFA on the real IdP with no password or token theft.',
    procedure:
      'Call the IdP device-authorization endpoint to obtain a device_code + user_code + verification URL. Send the victim a lure asking them to visit the genuine verification URL (e.g. the provider\'s device-login page) and enter the user_code; the page shows the real IdP and prompts real MFA. While the victim approves, poll the token endpoint with the device_code; on approval the IdP returns access/refresh tokens to the attacker\'s client.',
    whenToUse:
      'IdPs that enable the device authorization grant broadly (not restricted to genuine input-constrained devices) — the Microsoft 365 / Azure device-code phishing class.',
    confirmationSignal:
      'The attacker\'s token-endpoint polling returns valid access + refresh tokens for the victim immediately after the victim approves the attacker-initiated user_code — MFA is satisfied on the legitimate IdP yet the tokens are delivered to the attacker\'s client. The token issuance to a session the victim never started is the signal.',
    preconditions: ['device authorization grant enabled', 'victim can be induced to approve an attacker-initiated user_code'],
    appliesTo: ['Microsoft Entra ID / M365', 'Azure', 'Google Cloud', 'device-grant IdPs'],
    cwe: [287, 1021, 640],
    chainsWith: ['mfa-bypass'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover',
        title: 'Access Granted: phishing with device code authorization for account takeover',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Federated identity linking & email/identifier trust
  // -------------------------------------------------------------------------
  {
    namespaces: ['sso-account-linking-takeover'],
    title: 'SSO account-linking confusion — merge federated identity by email without verification',
    symptom:
      'A service links a federated (SSO) identity to a local account by matching email address without proving the SSO identity or the local account owner consented, so an attacker who controls one side (a federated identity asserting the victim\'s email, or a pre-created local account) is merged into the victim\'s account.',
    procedure:
      'Identify the linking logic: does "Sign in with X" attach to any existing local account sharing the returned email, and does adding a federated login require re-authentication? Attack from either side — (a) authenticate via an IdP that will assert the victim\'s email (or a non-verifying IdP) and get merged into the victim\'s local account; or (b) pre-create a local account on the victim\'s email so that when the victim later uses SSO, the accounts merge and the attacker\'s pre-set credentials still work (a pre-hijacking merge).',
    whenToUse:
      'Apps supporting both password and federated login that auto-link by email without verifying ownership/consent (the Sudhodanan/Paverd pre-hijacking "federated merge" class).',
    confirmationSignal:
      'After the merge, the attacker-controlled login path (attacker\'s federated identity or attacker-set password) authenticates into the account holding the VICTIM\'s data — a safe implementation would require the victim to explicitly confirm the link. Retained attacker access to the victim\'s account is the signal.',
    preconditions: ['auto-linking by email without ownership/consent proof', 'both password and federated login supported'],
    appliesTo: ['SaaS with social login', 'account-linking flows', 'SSO onboarding'],
    cwe: [287, 863, 290],
    chainsWith: ['oidc-email-verification-trust', 'oauth-csrf-state', 'pwreset-account-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan',
        title: 'Pre-hijacked accounts: Security Failures in User Account Creation (USENIX Security 2022)',
        tier: 1,
        kind: 'paper'
      },
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 authentication vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['oidc-email-verification-trust'],
    title: 'OIDC email_verified ignored — impersonation via unverified/attacker-set email claim',
    symptom:
      'A relying party keys accounts on the email claim from an ID token / userinfo but does not check email_verified (or accepts an IdP that lets users set an arbitrary unverified email), so an attacker registers an identity asserting the victim\'s email and is logged into the victim\'s account.',
    procedure:
      'Find an IdP (or the app\'s own IdP) that will issue a token containing an attacker-chosen email without verifying ownership, or where email_verified can be false. Sign in to the target via that IdP asserting the victim\'s email. If the RP maps the account by email while ignoring email_verified, it authenticates the attacker as the victim. Test both first-login (account creation) and returning-login (merge into an existing victim account).',
    whenToUse:
      'OIDC relying parties that trust the email claim for identity mapping without enforcing email_verified and issuer trust (pre-hijacking "non-verifying IdP" class).',
    confirmationSignal:
      'A login whose ID token carries the victim\'s email with email_verified false/absent establishes a session as the victim — while an RP that enforces email_verified rejects it. The differential is the verified flag: the same email claim is trusted vs distrusted based on verification.',
    preconditions: ['RP maps identity by email', 'email_verified not enforced / non-verifying IdP accepted'],
    appliesTo: ['OIDC relying parties', 'social login', 'B2B SSO with self-service IdPs'],
    cwe: [287, 290, 345],
    chainsWith: ['sso-account-linking-takeover', 'oauth-token-audience-confusion'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan',
        title: 'Pre-hijacked accounts (USENIX Security 2022) — non-verifying IdP attack',
        tier: 1,
        kind: 'paper'
      },
      {
        url: 'https://portswigger.net/web-security/oauth',
        title: 'OAuth 2.0 — unverified user registration',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Session & cookie/token identity handling
  // -------------------------------------------------------------------------
  {
    namespaces: ['session-fixation'],
    title: 'Session fixation — session id not rotated on authentication',
    symptom:
      'The application keeps the same session identifier before and after login, so an attacker who plants a known session id in the victim\'s browser (via a URL parameter, a settable cookie, or a subdomain) shares the victim\'s authenticated session once they log in.',
    procedure:
      'Obtain a session id as an unauthenticated attacker. Force that id into the victim\'s browser (session id accepted from the URL/query, an attacker-set cookie, or a sibling-subdomain cookie). Have the victim authenticate with that id present. Then use the same id from the attacker\'s client — if it is now authenticated as the victim, the app failed to regenerate the id on privilege change.',
    whenToUse:
      'Apps that accept externally-influenced session ids and do not regenerate the session id at login / privilege elevation.',
    confirmationSignal:
      'The pre-authentication session id, held by the attacker, becomes an authenticated session as the victim after the victim logs in — a safe app issues a NEW id at login, so the attacker\'s known id stays unauthenticated. The pre/post-login continuity of the same id is the discriminator.',
    preconditions: ['session id not regenerated on login', 'attacker can set/fix the victim session id'],
    appliesTo: ['classic server-rendered apps', 'PHP/Java/.NET session frameworks', 'SSO landing flows'],
    cwe: [384, 287],
    chainsWith: ['saml-assertion-replay', 'predictable-session-token'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/www-community/attacks/Session_fixation',
        title: 'OWASP: Session fixation',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation',
        title: 'OWASP WSTG — Testing for Session Fixation',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['predictable-session-token'],
    title: 'Predictable session token / insufficient entropy',
    symptom:
      'Session identifiers (or auth tokens) are generated with low entropy or a non-cryptographic source — sequential, timestamp-derived, short, or from a weak PRNG — so an attacker can predict or brute-force a valid live session and hijack it.',
    procedure:
      'Collect many session ids across fresh sessions and analyse structure: sequential counters, embedded timestamps/PIDs, short length, low character-set, or predictable encoding. Test for statistical bias (Burp Sequencer / entropy estimation). If tokens are guessable, generate candidate ids around observed values and probe authenticated endpoints for one that maps to another user\'s live session.',
    whenToUse:
      'Custom session/token generators, or frameworks configured with weak randomness (< ~64 bits of entropy).',
    confirmationSignal:
      'A session id the attacker PREDICTED or derived (not received from the server for their own session) authenticates as another user — where a CSPRNG-backed id of sufficient entropy makes this infeasible. Successful use of a non-issued, guessed id is the signal, distinct from stealing an issued one.',
    preconditions: ['session id from a weak/predictable source', 'insufficient entropy (< 64 bits)'],
    appliesTo: ['custom auth frameworks', 'legacy web apps', 'homegrown token generators'],
    cwe: [330, 384, 340],
    chainsWith: ['session-fixation', 'token-swapping-identity-confusion'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        title: 'OWASP Session Management Cheat Sheet — session id entropy',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['token-swapping-identity-confusion'],
    title: 'Cookie/JWT swapping — token not bound to a single principal',
    symptom:
      'Auth tokens/cookies are interchangeable across accounts or requests because they are not bound to the identity/context they were issued for — mixing a session cookie from account A with a CSRF/identity token from account B (or reusing one component) causes the server to act on a spliced or mismatched identity.',
    procedure:
      'Log in as two attacker-controlled accounts and collect each account\'s auth artifacts (session cookie, JWT, CSRF token, tenant header, X-User-Id). Send requests with mismatched combinations — cookie of A with token/header of B, or a per-user token from A used in B\'s session. If the server honours the spliced identity (returns/modifies the other account\'s data, or grants the other context), token binding is missing.',
    whenToUse:
      'Multi-credential designs (cookie + bearer + custom identity header) where components are validated independently rather than as a bound set — token sidejacking / context-binding gaps.',
    confirmationSignal:
      'A request assembled from two accounts\' tokens is honoured as one of them and reaches the OTHER account\'s data/functions — a correctly bound implementation rejects the mismatch. The acceptance of a cross-account token combination, versus rejection, isolates the missing binding.',
    preconditions: ['auth components validated independently', 'no binding of the token to a single principal/context'],
    appliesTo: ['multi-tenant SaaS', 'cookie+JWT hybrids', 'API gateways with identity headers'],
    cwe: [287, 639, 384],
    chainsWith: ['jwt-audience-confusion', 'cross-account-token-id', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — token sidejacking & context binding',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['cross-account-token-id'],
    title: 'Cross-account access via guessable identifier embedded in the token',
    symptom:
      'The token (JWT claim, opaque bearer, or API key) carries an account/tenant/org identifier that the server trusts for authorization, and that identifier is guessable or editable — changing it (when the token is forgeable) or reusing a shared token across tenants grants access to other accounts.',
    procedure:
      'Decode the token and locate identity/tenant fields (tenant_id, org_id, account, customer, sub). If the token is forgeable via any signing weakness, substitute another (guessable/sequential) identifier and replay. If the token is opaque but a single shared token is issued per tenant/integration, reuse it against another tenant\'s data. Confirm horizontal movement into a different account\'s resources.',
    whenToUse:
      'Multi-tenant systems that authorize on a token-embedded tenant/account id without an independent server-side ownership check.',
    confirmationSignal:
      'A token bearing a DIFFERENT account/tenant identifier (guessed, or a shared token pointed at another tenant) returns or mutates that other account\'s data — while a per-request server-side ownership check would deny it. Cross-tenant data access driven by the swapped identifier is the signal.',
    preconditions: ['authorization derived from a token-embedded identifier', 'identifier guessable or token shared across tenants'],
    appliesTo: ['multi-tenant APIs', 'B2B integrations', 'partner API keys', 'JWT tenant claims'],
    cwe: [639, 863, 349],
    chainsWith: ['jwt-claim-escalation', 'token-swapping-identity-confusion', 'idor'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html',
        title: 'OWASP JWT Cheat Sheet — do not trust unbound identifiers',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // Account-lifecycle & step-up authentication bypasses
  // -------------------------------------------------------------------------
  {
    namespaces: ['mfa-bypass'],
    title: 'MFA / step-up authentication bypass on a privileged action',
    symptom:
      'A second factor (or step-up prompt) gates login or a sensitive operation, but the protected state/endpoint is reachable without completing it — the MFA step is enforced only in the UI, only at one entry point, or can be skipped by manipulating the flow.',
    procedure:
      'Complete first-factor auth and stop before MFA; probe whether a partially-authenticated session already carries privileges (call post-login/sensitive endpoints directly). Test flow manipulation: replay the "MFA complete" request, force-browse past the challenge, drop the MFA parameter, or change a status field. For step-up on sensitive actions (change email/password, disable MFA, admin ops), invoke the action via API without the step-up token. Also test OTP weaknesses: reuse, no rate limit, or accepting a code for a different user.',
    whenToUse:
      'Any MFA/step-up control where enforcement may be client-side, single-entry-point, or skippable via direct API access (OWASP MFA guidance).',
    confirmationSignal:
      'A sensitive/privileged action or authenticated resource succeeds for a session that did NOT complete the required second factor — where the correct flow blocks until MFA passes. Completing the protected action without the MFA/step-up token, versus being blocked, isolates the bypass.',
    preconditions: ['MFA/step-up enforced inconsistently across entry points', 'protected endpoint reachable pre-MFA or via API'],
    appliesTo: ['web/mobile logins', 'admin consoles', 'sensitive-action flows', 'API backends'],
    cwe: [287, 306, 863],
    chainsWith: ['oauth-device-code-phishing', 'email-change-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
        title: 'OWASP Multifactor Authentication Cheat Sheet',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['pwreset-account-takeover'],
    title: 'Password-reset token resets another user (userid parameter / weak binding)',
    symptom:
      'The password-reset confirmation step does not bind the reset token to the account it was issued for — a userid/email/username parameter alongside the token (or a token not tied to a single user) lets the attacker set a NEW password on a victim account.',
    procedure:
      'Request a reset for the attacker\'s own account to obtain a valid token, then submit the reset-confirm request swapping the account parameter to the victim (userid, email, username, or account id) while keeping the attacker\'s token. Also test: token not invalidated after use/expiry, token guessable/low-entropy, token valid for any account, or the confirm step trusting a client-supplied user field. Success sets the victim\'s password to an attacker value.',
    whenToUse:
      'Password-reset flows where the confirm step takes both a token and an account identifier, or where the token is not strictly linked to one user in the database.',
    confirmationSignal:
      'A reset token issued for the ATTACKER\'s account, combined with the victim\'s identifier, changes the VICTIM\'s password (attacker can then log in as the victim) — a correct flow rejects the token/account mismatch. The cross-account password change is the signal, not merely a 200 on the reset page.',
    preconditions: ['reset token not bound to a single user', 'confirm step trusts a client-supplied account identifier'],
    appliesTo: ['password-reset flows', 'account-recovery endpoints', 'custom auth backends'],
    cwe: [640, 639, 287],
    chainsWith: ['sso-account-linking-takeover', 'email-change-takeover'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
        title: 'OWASP Forgot Password Cheat Sheet — bind tokens to one user',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['email-change-takeover'],
    title: 'Email-change / verification bypass leading to account takeover',
    symptom:
      'Changing the account email does not require re-authentication or confirmation at the NEW address (or the verification can be skipped/forged), so an attacker who briefly controls a session — or can trigger the change — repoints the account to their own email and then owns password reset and recovery.',
    procedure:
      'Attempt to change the account email without a step-up/current-password prompt. Test whether the change takes effect before the new address is verified, whether the verification token is guessable/reusable/not bound to the request, and whether a client-supplied "verified" flag or userid can be manipulated. Once the email is attacker-controlled, trigger password reset to seize the account. Also test IDOR on the change endpoint to alter another user\'s email.',
    whenToUse:
      'Profile/email-change flows lacking step-up auth and proper new-address verification, where email controls recovery.',
    confirmationSignal:
      'The account\'s email is repointed to an attacker address without re-authentication or genuine new-address verification, and a subsequent reset/recovery to that address grants control — a correct flow requires step-up and confirmation at the new address. The uncontested email change enabling takeover is the signal.',
    preconditions: ['email change lacks step-up auth', 'new-address verification skippable/forgeable, or IDOR on the change endpoint'],
    appliesTo: ['account settings flows', 'profile APIs', 'recovery-by-email designs'],
    cwe: [287, 640, 620],
    chainsWith: ['pwreset-account-takeover', 'mfa-bypass', 'idor'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
        title: 'OWASP MFA Cheat Sheet — require step-up for email changes',
        tier: 1,
        kind: 'advisory'
      },
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html',
        title: 'OWASP Forgot Password Cheat Sheet',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['magic-link-otp-reuse'],
    title: 'Magic-link / OTP reuse or race enabling authentication as another user',
    symptom:
      'A one-time login link or OTP is not strictly single-use, not expired promptly, guessable, or not bound to one login attempt/user — so it can be reused, brute-forced, or raced to authenticate as the target.',
    procedure:
      'Request a magic link/OTP and test single-use (redeem twice), TTL (redeem after delay), and binding (use the victim\'s code in the attacker\'s session or vice versa). For OTPs, test entropy and rate limiting — brute-force the code if attempts are unlimited. Race the redemption: fire concurrent redemptions of one code, or request many codes and try them in parallel, to defeat naive single-use checks. Confirm a session is established as the target.',
    whenToUse:
      'Passwordless login (magic link / email OTP / SMS OTP) where the credential\'s single-use, expiry, entropy, or user-binding may be weak.',
    confirmationSignal:
      'A magic link/OTP is successfully used to authenticate MORE than once, after it should have expired, by a session it was not issued to, or via brute force under missing rate limits — establishing a session as the target where a correct one-time, bound, rate-limited credential would fail. The reuse/guess success is the signal.',
    preconditions: ['OTP/magic-link not strictly single-use/expiring/bound', 'weak entropy or missing rate limiting'],
    appliesTo: ['passwordless login', 'email/SMS OTP', 'magic-link flows'],
    cwe: [287, 384, 640, 307],
    chainsWith: ['mfa-bypass', 'predictable-session-token'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html',
        title: 'OWASP MFA Cheat Sheet — OTP single-use, TTL & attempt limits',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
];
