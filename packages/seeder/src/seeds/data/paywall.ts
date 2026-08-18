import type { CorpusRecord } from './types';

/**
 * Paywall / payment-wall / metered-content & entitlement-bypass methodology.
 *
 * A catalog of PUBLICLY DOCUMENTED techniques for AUTHORIZED testing of one's
 * own (or consenting) apps: accessing gated premium content, plus the
 * server-side entitlement / subscription logic flaws behind the bypasses.
 *
 * Grouping (each record is a DISTINCT fundamental technique):
 *  - CLIENT-SIDE: the full content reaches the browser and only a JS/CSS/DOM
 *    layer gates it.
 *  - METERED: a client-tracked article counter.
 *  - REFERER/UA/GEO: trust of a spoofable request signal.
 *  - ARCHIVE/PROXY: a third party already has the ungated copy.
 *  - SERVER-SIDE / API / ENTITLEMENT: the gate is missing, trusts the client,
 *    or is never re-checked.
 *  - MOBILE IAP: purchase / receipt validation done or trusted client-side.
 *
 * Every `confirmationSignal` is DIFFERENTIAL: it contrasts what a *free /
 * un-bypassed* session gets (truncated body, 402/403, blur overlay, entitled:
 * false) against what the technique yields (the full premium body/fields).
 */
export const records: readonly CorpusRecord[] = [
  // -------------------------------------------------------------------------
  // CLIENT-SIDE — the ungated content is already in the browser.
  // -------------------------------------------------------------------------
  {
    namespaces: ['paywall-js-disable'],
    title: 'Disable JavaScript so the paywall overlay never applies',
    symptom:
      'The full article is present in the initial HTML response, but a JavaScript bundle truncates the DOM and paints a subscribe overlay after load. With scripting disabled the truncation/overlay code never runs.',
    procedure:
      'Load the article once normally and confirm the overlay appears only after the page settles (a flash of full text first). Disable JavaScript for the origin (browser setting, NoScript, or DevTools "Disable JavaScript" command) and reload. Read the static server-rendered body that the meter script would otherwise have hidden. Sites that keep the body in HTML for SEO/crawler indexing are the reliable case.',
    whenToUse:
      'Soft paywalls where a first paint shows the full article before JS collapses it; server-rendered news/CMS pages.',
    confirmationSignal:
      'With JS enabled a free session gets a truncated body + subscribe overlay; with JS disabled the SAME URL renders the complete article body (no truncation, no overlay), proving enforcement was purely client-side.',
    preconditions: ['full body delivered in the initial HTML', 'paywall applied by client-side script'],
    appliesTo: ['WordPress', 'server-rendered news sites', 'CMS article pages'],
    cwe: [602, 200],
    chainsWith: ['paywall-overlay-dom-removal', 'paywall-preloaded-json', 'paywall-crawler-ua'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://medium.com/@salt.creative/bypassing-paywalls-with-client-side-javascript-manipulation-a-technical-exploration-0f5759d04488',
        title: 'Bypassing Paywalls with Client-Side JavaScript Manipulation',
        tier: 3,
        kind: 'writeup'
      },
      {
        url: 'https://developers.google.com/search/docs/appearance/structured-data/paywalled-content',
        title: 'Google Search Central: Subscription and Paywalled Content Markup',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['paywall-overlay-dom-removal'],
    title: 'Remove the DOM overlay and un-blur the gated body via CSS',
    symptom:
      'The full text is in the DOM but hidden behind a fixed-position modal, a scroll-lock on <body>, and a blur/`filter`/`max-height` clamp on the article container. Editing those styles reveals the content.',
    procedure:
      'Open DevTools and inspect the subscribe wall element. Delete the overlay node (`element.remove()`), then clear the gating styles on the article container: remove `filter: blur(...)`, `-webkit-mask`, `max-height`/`overflow: hidden`, and any `position: fixed` scroll-lock on `body`/`html` (`overflow`, `pointer-events`). A one-liner deleting the overlay id/class and resetting the container styles is enough. Persist with a bookmarklet or user stylesheet.',
    whenToUse:
      'Overlay/blur "soft" walls where the article HTML is fully present and only cosmetically obscured.',
    confirmationSignal:
      'Before edit the container is blurred/clipped and non-scrollable (free view); after removing the overlay node and clearing blur/clamp styles the entire article is legible and scrollable from the same already-loaded DOM — no new network request was needed.',
    preconditions: ['full text present in the DOM', 'gate is a CSS overlay/blur, not a truncated response'],
    appliesTo: ['news sites', 'Medium-style blogs', 'CSS blur/overlay paywalls'],
    cwe: [602],
    chainsWith: ['paywall-js-disable', 'paywall-view-source-reader'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://medium.com/@salt.creative/bypassing-paywalls-with-client-side-javascript-manipulation-a-technical-exploration-0f5759d04488',
        title: 'Bypassing Paywalls with Client-Side JavaScript Manipulation',
        tier: 3,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-preloaded-json'],
    title: 'Extract the full body from preloaded JSON (__NEXT_DATA__ / __PRELOADED_STATE__)',
    symptom:
      'A framework-hydrated page ships the complete article inside an embedded JSON blob (`__NEXT_DATA__` for Next.js, `window.__PRELOADED_STATE__`, `__APOLLO_STATE__`) even though the rendered DOM only shows a truncated preview.',
    procedure:
      'View source (not the live DOM) and search for `__NEXT_DATA__`, `__PRELOADED_STATE__`, `__NUXT__`, or an inline `application/json` script. Pretty-print the JSON and locate the field holding the article (`body`, `content`, `articleBody`, `bodyHtml`). Read it directly from the blob; the hydration payload frequently carries the full text because the same data feeds subscribers.',
    whenToUse:
      'Next.js / Nuxt / SPA-hydrated news apps that embed initial state for client hydration.',
    confirmationSignal:
      'The rendered page shows a short teaser (free view) while the `__NEXT_DATA__`/preloaded-state JSON in the same HTML contains the full `articleBody`/`content` string — the premium text ships to every visitor and is only hidden at render time.',
    preconditions: ['framework embeds initial state in HTML', 'full content included in that state'],
    appliesTo: ['Next.js', 'Nuxt', 'React/Redux SSR', 'Apollo-hydrated apps'],
    cwe: [602, 200],
    chainsWith: ['paywall-jsonld-articlebody', 'paywall-js-disable', 'paywall-api-no-entitlement'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://nextjs.org/docs/pages/api-reference/functions/get-server-side-props',
        title: 'getServerSideProps — server props serialized into the page (__NEXT_DATA__)',
        tier: 2,
        kind: 'reference'
      }
    ]
  },
  {
    namespaces: ['paywall-jsonld-articlebody'],
    title: 'Read the full text from JSON-LD articleBody / SEO structured data',
    symptom:
      'To index paywalled content, the page emits schema.org structured data (`<script type="application/ld+json">`) with `isAccessibleForFree: false` and a full `articleBody`, while marking only a CSS section as the gated part — the complete text sits in the markup for crawlers.',
    procedure:
      'Fetch the raw HTML and extract every `application/ld+json` block. Parse the `NewsArticle`/`Article` object and read `articleBody` (or the `hasPart` sections). Google’s flexible-sampling/structured-data guidance requires the same body Googlebot indexes to be present, so publishers who mark up paywalled content leak the full text into JSON-LD.',
    whenToUse:
      'News sites that implement Google’s paywalled-content structured data (isAccessibleForFree/hasPart) for SEO.',
    confirmationSignal:
      'The visible page truncates after a few paragraphs (free view), but the JSON-LD `articleBody` in the same response contains the entire article — the differential is teaser-in-DOM vs full-text-in-structured-data.',
    preconditions: ['schema.org paywall markup present', 'articleBody carries full content'],
    appliesTo: ['news publishers', 'Google-indexed paywalls', 'schema.org NewsArticle'],
    cwe: [602, 200],
    chainsWith: ['paywall-preloaded-json', 'paywall-crawler-ua'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://developers.google.com/search/docs/appearance/structured-data/paywalled-content',
        title: 'Google Search Central: Subscription and Paywalled Content Markup',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['paywall-view-source-reader'],
    title: 'View-source / browser reader-mode extraction of the pre-truncation body',
    symptom:
      'The raw HTML (before scripts run) contains more of the article than the rendered page, and the browser’s built-in reader mode reflows the underlying <article> text while stripping the overlay chrome.',
    procedure:
      'Open `view-source:` for the URL (which shows the server response untouched by JS) and read the body text there, or invoke the browser reader view (Firefox Reader, Safari Reader) which parses the article element and discards the overlay/blur wrapper. Reader mode also ignores scroll-lock and modal chrome that only the live DOM enforces.',
    whenToUse:
      'Soft walls where the full text is in the server HTML but visually obscured; quick manual read without tooling.',
    confirmationSignal:
      'Reader mode / view-source renders the complete article while the normal rendered page shows only the metered teaser + overlay — the content difference proves the wall is presentation-layer only.',
    preconditions: ['article text present in server HTML', 'reader-mode-parseable <article> markup'],
    appliesTo: ['Firefox/Safari Reader', 'news sites', 'blog CMS'],
    cwe: [602],
    chainsWith: ['paywall-overlay-dom-removal', 'paywall-js-disable'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://medium.com/@salt.creative/bypassing-paywalls-with-client-side-javascript-manipulation-a-technical-exploration-0f5759d04488',
        title: 'Bypassing Paywalls with Client-Side JavaScript Manipulation',
        tier: 3,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-block-script'],
    title: 'Block the paywall / metering script via request filtering',
    symptom:
      'Gating is loaded from a separable script (a metering vendor like a Poool/Piano-style tag, or an inline paywall.js). If that request is blocked, the body stays visible and the counter never increments.',
    procedure:
      'Watch the network panel while the wall triggers and identify the metering/paywall script or its vendor domain. Add a content-blocker/hosts/DevTools request-blocking rule for that URL (or the analytics tag it rides on) and reload. The article renders because the code that truncates it and records the view never executes.',
    whenToUse:
      'Third-party metering vendors or a clearly separable paywall bundle; also stops the view from counting against the meter.',
    confirmationSignal:
      'With the paywall script allowed, the free session is walled after N views; with just that one request blocked the article renders in full AND the meter counter does not advance — isolating enforcement to that script.',
    preconditions: ['paywall logic in a blockable separate request', 'body not server-side stripped'],
    appliesTo: ['metering SaaS (Poool/Piano-style)', 'client-side paywall bundles'],
    cwe: [602],
    chainsWith: ['paywall-meter-cookie-reset', 'paywall-js-disable'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://developers.google.com/search/docs/appearance/flexible-sampling',
        title: 'Flexible sampling (metering / soft paywall) — Google Search Central',
        tier: 2,
        kind: 'reference'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // METERED — the article counter is tracked on the client.
  // -------------------------------------------------------------------------
  {
    namespaces: ['paywall-meter-cookie-reset'],
    title: 'Reset the metered counter by clearing cookies / localStorage / IndexedDB',
    symptom:
      'A "N free articles per month" meter is tracked entirely in browser storage (cookies such as NYT-style `*-meter`, `localStorage`, or IndexedDB). Deleting that state returns the count to zero.',
    procedure:
      'Read one article, then inspect Application storage for a counter key (cookie/localStorage/IndexedDB entry named like `meter`, `articleCount`, `nyt_meter`). Clear the site’s storage (or delete just the counter key) and reload; the meter restarts. Because state lives only on the client, there is no server record to reconcile against.',
    whenToUse:
      'Client-side metered walls where the server does not bind view counts to an account/IP server-side.',
    confirmationSignal:
      'After hitting the limit a fresh load is walled (free state); after clearing the meter cookie/localStorage key the same account/browser is served full articles again with the counter reset to 0 — the limit lived only in client storage.',
    preconditions: ['view count stored client-side', 'no authoritative server-side per-user/IP metering'],
    appliesTo: ['metered news paywalls', 'localStorage/cookie meters'],
    cwe: [602, 837],
    chainsWith: ['paywall-incognito-reset', 'paywall-meter-client-editable', 'paywall-block-script'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://gist.github.com/carlosabalde/6139924',
        title: 'Bookmarklet to flush New York Times metered-paywall state',
        tier: 2,
        kind: 'exploit'
      }
    ]
  },
  {
    namespaces: ['paywall-incognito-reset'],
    title: 'Reset the meter with a private/incognito window',
    symptom:
      'A private window starts with no cookies or storage, so a client-side meter sees a brand-new visitor and the free allowance resets each session.',
    procedure:
      'When the meter blocks you, open the article in a private/incognito window (or a fresh browser profile/container tab). No prior counter cookie or localStorage entry exists, so the wall treats the request as a first visit. Closing the window discards the state again.',
    whenToUse:
      'Anonymous client-side meters that key solely on browser storage and are not tied to a login or server-side identity.',
    confirmationSignal:
      'The normal profile is walled at the limit while a private window immediately loads the same article in full — the only difference is the absence of the stored counter, confirming the meter is per-browser-storage, not per-user server-side.',
    preconditions: ['meter keyed on browser storage', 'no persistent server-side visitor identity'],
    appliesTo: ['metered news paywalls', 'anonymous soft walls'],
    cwe: [602, 837],
    chainsWith: ['paywall-meter-cookie-reset', 'paywall-device-id-rotate'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://gist.github.com/carlosabalde/6139924',
        title: 'Bookmarklet to flush New York Times metered-paywall state',
        tier: 2,
        kind: 'exploit'
      }
    ]
  },
  {
    namespaces: ['paywall-meter-client-editable'],
    title: 'Edit the client-stored meter counter directly',
    symptom:
      'The remaining-views number is stored as a plain integer in a cookie/localStorage value the client can overwrite, so setting it back to the starting quota (or a large number) restores access without clearing anything.',
    procedure:
      'Locate the counter value (e.g. `localStorage["meter.count"] = "12"`). Overwrite it with 0 (or set the quota field high) and reload; a bookmarklet can do this each time. Some sites store a JSON meter object — reset the `views`/`count` field within it. The server trusts whatever the client reports as its own count.',
    whenToUse:
      'Meters that persist a directly-readable/writable count rather than an opaque server token.',
    confirmationSignal:
      'A walled session becomes un-walled the instant the stored counter is rewritten to below the limit — no cookie deletion, no new session — proving the server accepts the client-reported view count verbatim.',
    preconditions: ['counter stored as editable client value', 'value trusted by the gate without server cross-check'],
    appliesTo: ['localStorage/cookie meters', 'bookmarklet-resettable paywalls'],
    cwe: [602, 807],
    chainsWith: ['paywall-meter-cookie-reset', 'entitlement-client-trusted'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://gist.github.com/carlosabalde/6139924',
        title: 'Bookmarklet to flush New York Times metered-paywall state',
        tier: 2,
        kind: 'exploit'
      }
    ]
  },
  {
    namespaces: ['paywall-device-id-rotate'],
    title: 'Rotate the anonymous device / visitor id to fork a fresh meter',
    symptom:
      'The meter is keyed on a first-party anonymous id (a `deviceId`/`visitorId`/`ajs_anonymous_id` cookie or fingerprint token). Minting a new id gives a new allowance without clearing all storage.',
    procedure:
      'Identify the id the meter increments against (a UUID cookie or a value sent to the metering API). Replace it with a freshly generated UUID (or let the site re-mint one after deleting just that key). Each distinct id is treated as a separate anonymous visitor with its own quota, so rotation multiplies free views.',
    whenToUse:
      'Meters that count per anonymous device id rather than per authenticated account or server-side IP.',
    confirmationSignal:
      'Requests carrying the exhausted id are walled while an identical request with a new device/visitor id returns full content — the id value alone flips walled→open, showing the quota is bound to a client-supplied identifier.',
    preconditions: ['meter keyed on a client-supplied anonymous id', 'no server-side rate binding to IP/account'],
    appliesTo: ['device-id metered walls', 'analytics-anonymous-id meters'],
    cwe: [602, 639],
    chainsWith: ['paywall-incognito-reset', 'free-trial-abuse-reset'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://gist.github.com/carlosabalde/6139924',
        title: 'Bookmarklet to flush New York Times metered-paywall state',
        tier: 2,
        kind: 'exploit'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // REFERER / UA / GEO — trust of a spoofable request signal.
  // -------------------------------------------------------------------------
  {
    namespaces: ['paywall-referer-firstclickfree'],
    title: 'Spoof the Referer to Google/social to trigger "first click free" / free-from-social',
    symptom:
      'The site grants an ungated view when the visitor appears to arrive from a search engine or social network (a legacy "first click free" / flexible-sampling lead-in), gated on the `Referer` header alone.',
    procedure:
      'Send the article request with `Referer: https://www.google.com/` (or a social origin like facebook.com/t.co) via a header-editing extension or proxy. The server’s referral-based exemption unlocks the full article as if you clicked through from search. Combine with a fresh session so the meter treats it as a first-from-search click.',
    whenToUse:
      'Publishers implementing referral exemptions / metering lead-in for search and social traffic.',
    confirmationSignal:
      'The same URL with no/again-visit Referer returns a subscribe wall, while the request carrying a google.com/social Referer returns the full article — the header value is the only variable that flips the gate.',
    preconditions: ['referral-based free-view exemption', 'exemption keyed on client-supplied Referer'],
    appliesTo: ['news paywalls', 'Leaky Paywall / metering plugins', 'flexible-sampling publishers'],
    cwe: [807, 290],
    chainsWith: ['paywall-crawler-ua', 'paywall-meter-cookie-reset'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://docs.leakypaywall.com/article/195-how-to-allow-a-user-to-bypass-the-meter-based-on-referrer-or-url',
        title: 'Leaky Paywall: bypass the meter based on referrer (first click free)',
        tier: 3,
        kind: 'advisory'
      },
      {
        url: 'https://developers.google.com/search/docs/appearance/flexible-sampling',
        title: 'Google Search Central: Flexible Sampling (metering and lead-in)',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['paywall-crawler-ua'],
    title: 'Spoof a search-crawler User-Agent (Googlebot) for the SEO-visible full text',
    symptom:
      'To be indexed, the site serves the complete article to Googlebot/Bingbot while walling normal browsers — the access decision is driven by the `User-Agent` string.',
    procedure:
      'Set the request `User-Agent` to a crawler string (e.g. `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`) with a UA-switcher extension or proxy, optionally pairing a google.com `Referer`. The server returns the full crawler-facing body. This is the same mechanism many reader proxies use server-side.',
    whenToUse:
      'Paywalls that expose full content to search crawlers for indexing and gate on UA rather than verified crawler IP.',
    confirmationSignal:
      'A default browser UA yields the truncated/walled response; the identical request with a Googlebot UA returns the full article — the UA string alone is the differentiator (verified-crawler reverse-DNS is NOT enforced).',
    preconditions: ['full content served to crawlers', 'crawler identity trusted from UA, not verified by reverse DNS'],
    appliesTo: ['news paywalls', 'SEO-indexed gated content'],
    cwe: [807, 290],
    chainsWith: ['paywall-referer-firstclickfree', 'paywall-jsonld-articlebody', 'paywall-reader-proxy'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.ghacks.net/2016/02/26/read-articles-behind-paywalls-by-masquerading-as-googlebot/',
        title: 'Read articles behind paywalls by masquerading as Googlebot',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-geo-xff'],
    title: 'Spoof geo via X-Forwarded-For / proxy to a region with free access',
    symptom:
      'Access rules vary by country (free in some regions, or the wall only applies to certain locales). The geo decision is derived from client-influenced signals (`X-Forwarded-For`, a geo cookie/param, or source IP via VPN).',
    procedure:
      'Determine which region gets free/unwalled access. If the app derives geo from a proxy header, send `X-Forwarded-For` / `X-Real-IP` / a `country` cookie for that region; otherwise route through a VPN/proxy egress in that country. Reload and read the content served under the free-region policy.',
    whenToUse:
      'Geo-tiered paywalls or region-locked free access where geo is taken from headers rather than a trusted GeoIP of the true socket.',
    confirmationSignal:
      'The default-region request is walled while the same request with the free-region XFF/geo signal (or VPN egress) returns full content — geo is the only changed input, and it is client-controllable.',
    preconditions: ['region-dependent access policy', 'geo derived from client-influenced header/IP'],
    appliesTo: ['geo-tiered paywalls', 'region-locked free content'],
    cwe: [807, 290, 348],
    chainsWith: ['paywall-referer-firstclickfree'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // ARCHIVE / PROXY — a third party already holds the ungated copy.
  // -------------------------------------------------------------------------
  {
    namespaces: ['paywall-archive'],
    title: 'Retrieve an ungated snapshot from a web archive',
    symptom:
      'A public archive (Wayback Machine, archive.today) captured the page while it was fully accessible (e.g. crawled as Googlebot or before the wall applied), so the snapshot shows the complete article.',
    procedure:
      'Query the archive for the canonical URL (web.archive.org/web/*/URL, or submit/lookup on archive.today). Open a snapshot dated when the content was ungated. Archives serve a static copy that never runs the live meter or overlay script, so the stored full text is readable.',
    whenToUse:
      'Content that was public/crawlable at capture time and remains in a public archive.',
    confirmationSignal:
      'The live URL returns the subscribe wall while the archived snapshot of the same URL renders the full article — the archive holds the pre-wall/crawler copy that the live site now gates.',
    preconditions: ['a public archive holds an ungated capture', 'article was accessible when archived'],
    appliesTo: ['Wayback Machine', 'archive.today', 'news paywalls'],
    cwe: [602, 200],
    chainsWith: ['paywall-google-cache', 'paywall-crawler-ua'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://www.ghacks.net/2016/02/26/read-articles-behind-paywalls-by-masquerading-as-googlebot/',
        title: 'Read articles behind paywalls by masquerading as Googlebot',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-google-cache'],
    title: 'Read the crawler/search cache copy of the article',
    symptom:
      'The search-engine cache stores the crawler-facing version of the page — which the publisher serves in full for indexing — so the cached copy is ungated even though the live page walls browsers.',
    procedure:
      'Retrieve the cached rendition of the URL from a search engine’s cache (or a cache-backed reader). Because the publisher must serve full text to the crawler to be indexed, the cache holds the complete body, stripped of the live overlay/meter that only runs for real visitors.',
    whenToUse:
      'Pages the publisher serves in full to crawlers for SEO, whose crawler view is retrievable from a cache.',
    confirmationSignal:
      'The live page truncates for a free visitor while the search cache of the same URL contains the full article — the cache preserves the crawler-facing full text that ordinary sessions are denied.',
    preconditions: ['full content served to crawlers', 'a retrievable cached crawler copy exists'],
    appliesTo: ['search-engine caches', 'SEO-indexed paywalls'],
    cwe: [602, 200],
    chainsWith: ['paywall-archive', 'paywall-amp-canonical', 'paywall-crawler-ua'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://developers.google.com/search/docs/appearance/structured-data/paywalled-content',
        title: 'Google Search Central: Subscription and Paywalled Content Markup (crawler must access full content)',
        tier: 1,
        kind: 'advisory'
      }
    ]
  },
  {
    namespaces: ['paywall-amp-canonical'],
    title: 'Fetch the AMP / canonical / print variant that omits the wall',
    symptom:
      'An alternate rendition of the same article — the AMP page, a `?output=amp` variant, a print/`?print=1` view, or the bare canonical URL — is built for distribution and skips the paywall enforcement of the main template.',
    procedure:
      'From the article `<head>` collect `rel="amphtml"`, `rel="canonical"`, and any print/share URLs. Request those variants directly. Lightweight AMP/print templates frequently render the full body without the meter/overlay JS that only the primary template loads.',
    whenToUse:
      'Publishers shipping AMP/print/syndication variants whose templates lack the wall.',
    confirmationSignal:
      'The main article URL is walled while its AMP/print/canonical variant returns the full text — same story, a distribution template that never applies the gate.',
    preconditions: ['an alternate rendition exists', 'that template omits the paywall enforcement'],
    appliesTo: ['AMP pages', 'print/share views', 'news CMS templates'],
    cwe: [602, 284],
    chainsWith: ['paywall-google-cache', 'paywall-api-no-entitlement'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://www.ghacks.net/2016/02/26/read-articles-behind-paywalls-by-masquerading-as-googlebot/',
        title: 'Read articles behind paywalls by masquerading as Googlebot',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-reader-proxy'],
    title: 'Use a reader/de-paywall proxy that fetches as a crawler',
    symptom:
      'A third-party reader service fetches the target server-side while presenting itself as a search crawler (and/or disabling JS), then re-serves the full body — chaining crawler-UA and JS-disable server-side.',
    procedure:
      'Submit the URL to a reader proxy (12ft-style ladder, outline/textance-style reader). The service requests the page with a crawler UA / no JS from its own backend, receives the ungated crawler version, and returns clean text. The technique is the server-side automation of the crawler-UA and JS-disable methods.',
    whenToUse:
      'Quick ungated read when the site serves full text to crawlers; when local UA/JS tricks are inconvenient.',
    confirmationSignal:
      'Your direct browser load is walled while the reader proxy returns the full article — the proxy obtained the crawler-facing copy the publisher exposes for indexing, which your normal session is denied.',
    preconditions: ['site serves full content to crawlers / without JS', 'a functioning reader proxy'],
    appliesTo: ['reader proxies (12ft-style)', 'outline/textance-style readers', 'SEO-indexed paywalls'],
    cwe: [602, 200],
    chainsWith: ['paywall-crawler-ua', 'paywall-js-disable', 'paywall-google-cache'],
    qualityTier: 3,
    sources: [
      {
        url: 'https://www.ghacks.net/2016/02/26/read-articles-behind-paywalls-by-masquerading-as-googlebot/',
        title: 'Read articles behind paywalls by masquerading as Googlebot',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // SERVER-SIDE / API / ENTITLEMENT — the gate is missing, trusts the client,
  // or is never re-checked.
  // -------------------------------------------------------------------------
  {
    namespaces: ['paywall-api-no-entitlement'],
    title: 'Premium content returned by an API/JSON endpoint that omits the entitlement check',
    symptom:
      'The web UI hides premium content, but the underlying API/JSON endpoint that supplies it authenticates the caller yet never checks subscription/plan, returning the full premium payload to any logged-in (or anonymous) request.',
    procedure:
      'Capture the request the page makes for the gated content (the article/feature JSON, a `/content/{id}` or `/premium/*` endpoint). Replay it directly as a free account (and unauthenticated) with the same id. The server verifies who you are but not what you are entitled to, so it returns the premium body the UI would have withheld. Test sibling endpoints (export/print/mobile API) that share the resource.',
    whenToUse:
      'SPA/mobile backends where the paywall is enforced in the UI layer while the data API is not, or an internal endpoint skips the plan check.',
    confirmationSignal:
      'A free/anonymous account calling the content API gets the FULL premium fields (HTTP 200 with complete body) where the gated UI shows only a teaser or a 402/403 — authorization is missing on the API path.',
    preconditions: ['authenticated but not authorized endpoint', 'premium data reachable via direct API call'],
    appliesTo: ['REST APIs', 'GraphQL', 'SPA/mobile backends', 'ASP.NET / Express / Django'],
    cwe: [862, 285, 284],
    chainsWith: ['paywall-graphql-premium-field', 'entitlement-client-trusted', 'paywall-preloaded-json'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://busk3r.medium.com/access-control-bypass-how-i-was-able-to-access-to-premium-user-functionalities-without-paying-c1f53608175',
        title: 'Access Control Bypass — accessing premium functionality without paying',
        tier: 3,
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
    namespaces: ['entitlement-client-trusted'],
    title: 'Entitlement flag trusted from a client-controlled cookie/field',
    symptom:
      'Access is decided from a value stored in a user-controllable location — an `isSubscriber`/`plan=premium` cookie, a hidden form field, or a localStorage flag — that the client can set at will.',
    procedure:
      'Inspect cookies/storage/request bodies for a role/plan/entitlement value (`plan`, `isSubscriber`, `tier`, `premium`). Flip it to the privileged value (`premium`/`true`) and resend. If the server reads its authorization decision from that client-held value rather than an authoritative record, premium unlocks.',
    whenToUse:
      'Apps that persist access rights in a client-controllable cookie/field after login instead of re-deriving them server-side.',
    confirmationSignal:
      'Setting the client `plan`/`isSubscriber` value to the premium tier makes the server return premium content/features that a default free value is denied — the response is decided by the client-supplied flag, not a server-side subscription record.',
    preconditions: ['access right stored in a user-controllable location', 'server trusts it without server-side verification'],
    appliesTo: ['cookie/JWT-flag gated apps', 'SPAs', 'classic web apps'],
    cwe: [807, 639, 602],
    chainsWith: ['entitlement-jwt-claim', 'paywall-api-no-entitlement', 'paywall-meter-client-editable'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control — rights stored in a user-controllable location',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['entitlement-jwt-claim'],
    title: 'Tamperable JWT plan/entitlement claim',
    symptom:
      'The access token carries the subscription tier as a claim (`plan`, `scope`, `entitlements`), and the server reads it without verifying signature integrity (accepts `alg:none`, unsigned, or a forgeable signature), so the claim can be raised to premium.',
    procedure:
      'Decode the session/access JWT and find the plan/entitlement claim. Modify it to the premium value and re-issue the token — via `alg:none`, an unverified signature, or a full algorithm-confusion forge — then send it. If the resource server trusts the claim without a valid signature check, it grants premium.',
    whenToUse:
      'JWT-authenticated apps that encode entitlements in the token and verify it weakly.',
    confirmationSignal:
      'A token whose plan claim is elevated to premium (and whose signature is not properly validated) is accepted and returns premium content that the original free-plan token is denied — same identity, only the tampered claim differs.',
    preconditions: ['entitlement encoded in JWT claim', 'signature not properly verified'],
    appliesTo: ['JWT/OAuth resource servers', 'Node jsonwebtoken', 'PyJWT', 'SPA/mobile backends'],
    cwe: [347, 807, 639],
    chainsWith: ['jwt-alg-confusion', 'entitlement-client-trusted', 'paywall-api-no-entitlement'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-graphql-premium-field'],
    title: 'GraphQL premium field returned to a free account',
    symptom:
      'A GraphQL schema exposes premium fields/types (full `body`, premium `stats`, `downloadUrl`) with authorization enforced per-resolver — and a resolver for a gated field forgets its entitlement check, so a free account can select it.',
    procedure:
      'Introspect (or field-suggest) the schema and enumerate premium-looking fields on the content type. From a free account, craft a query selecting those fields directly (including via aliases/fragments the UI never sends). A resolver missing the plan check returns the premium value inline with the free fields.',
    whenToUse:
      'GraphQL backends where the UI omits premium fields but the resolver does not gate them server-side.',
    confirmationSignal:
      'A free-account query explicitly selecting the premium field returns its full value (200, no error) where the same field is absent/denied in the UI’s default query — the resolver returned gated data to an unentitled caller.',
    preconditions: ['GraphQL endpoint reachable', 'per-field authorization missing on a premium resolver'],
    appliesTo: ['Apollo Server', 'graphql-js', 'Hasura', 'GraphQL Yoga'],
    cwe: [862, 285],
    chainsWith: ['graphql-introspection', 'paywall-api-no-entitlement'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['paywall-feature-flag-param'],
    title: 'Feature-flag / preview override query parameter',
    symptom:
      'A debug/preview/feature-flag parameter (`?preview=true`, `?premium=1`, `?paywall=false`, `?_escaped_fragment_=`) or header short-circuits the wall, intended for editors/QA but reachable by anyone.',
    procedure:
      'Fuzz the article URL and API with override params/headers: `preview`, `premium`, `paywall`, `subscriber`, `debug`, `bypass`, plus known preview tokens leaked in JS. Also test editor/preview routes (`/preview/{id}`). If the server honors the flag without authorization, it renders full content.',
    whenToUse:
      'Sites with editor-preview or feature-flag toggles that gate on a parameter rather than the user’s role.',
    confirmationSignal:
      'Appending the override param/header returns the full article where the unmodified request is walled — an unauthenticated visitor toggling a flag receives premium content, so the flag is not access-controlled.',
    preconditions: ['a preview/feature-flag bypass exists', 'flag honored without an authorization check'],
    appliesTo: ['CMS preview modes', 'feature-flag frameworks', 'news sites'],
    cwe: [284, 472, 639],
    chainsWith: ['paywall-api-no-entitlement', 'entitlement-client-trusted'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['free-trial-abuse-reset'],
    title: 'Free-trial abuse / trial reset via a new identifier',
    symptom:
      'A one-per-user free trial is keyed on an easily-varied identifier (email alias, phone, device id) with no durable dedupe, so a fresh identifier grants a fresh trial repeatedly.',
    procedure:
      'Enumerate what the trial is keyed on. Register again with a plus-alias/disposable email, a new device/anonymous id, or a re-installed app, and claim another trial. Where a single account is expected to trial once, confirm the limit can be exceeded by cycling identifiers (the workflow lacks a durable one-time constraint).',
    whenToUse:
      'Trial/promo entitlements gated by a re-creatable identifier without payment-instrument or hardware-level dedupe.',
    confirmationSignal:
      'After the first trial expires, a second identifier immediately receives a full new trial with premium access — the "one free trial" invariant is broken because eligibility is bound to a cheap-to-rotate key.',
    preconditions: ['trial keyed on a re-creatable identifier', 'no durable one-time-per-user enforcement'],
    appliesTo: ['SaaS free trials', 'streaming/app trials', 'promo entitlements'],
    cwe: [841, 799, 639],
    chainsWith: ['paywall-device-id-rotate', 'coupon-enumeration-stacking'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README',
        title: 'OWASP WSTG: Business Logic Testing (function-use limits, workflow circumvention)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['coupon-enumeration-stacking'],
    title: 'Coupon/discount-code enumeration and stacking',
    symptom:
      'Discount codes are guessable/enumerable and the cart lets the same or multiple codes apply repeatedly, driving the subscription price toward (or below) zero.',
    procedure:
      'Enumerate codes (predictable patterns, leaked lists) against the apply-coupon endpoint and note which validate. Then test stacking: apply the same code multiple times, or combine several, and watch the total. If discounts compound without a one-per-order/one-per-user cap, stack until the payable amount reaches 0 or negative and complete checkout.',
    whenToUse:
      'Checkout/subscription flows with weak coupon uniqueness and no cap on combined discounts.',
    confirmationSignal:
      'The order total drops to 0 (or credits the buyer) after repeated/stacked coupon application, where a single legitimate code only partially discounts — the compounding is the differential, and checkout still completes granting the subscription.',
    preconditions: ['enumerable coupon codes or stackable discounts', 'no per-order/per-user redemption cap'],
    appliesTo: ['e-commerce checkout', 'subscription billing', 'promo engines'],
    cwe: [837, 841, 799],
    chainsWith: ['checkout-price-tampering', 'race-condition', 'free-trial-abuse-reset'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/logic-flaws',
        title: 'PortSwigger: Business logic vulnerabilities',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README',
        title: 'OWASP WSTG: Business Logic Testing',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['checkout-price-tampering'],
    title: 'Price / currency tampering in the checkout request',
    symptom:
      'The amount charged is taken from a client-submitted field (`price`, `amount`, `total`, `currency`) instead of being recomputed server-side, so the buyer can dictate what they pay for the subscription.',
    procedure:
      'Intercept the checkout/subscribe request and modify the price/amount to a low value (or swap `currency` to a weaker one while keeping the numeric amount). Resend and see whether the order is created and the subscription granted at the tampered amount. Excessive trust in client-side pricing is the core flaw.',
    whenToUse:
      'Checkout flows that trust a client-supplied price/amount rather than deriving it from a server-side catalog.',
    confirmationSignal:
      'An order/subscription is created and premium access granted at the attacker-chosen price where the legitimate flow charges full price — the server accepted the client-controlled amount, an externally-controlled assumed-immutable value.',
    preconditions: ['price/amount taken from client input', 'no server-side re-pricing against the catalog'],
    appliesTo: ['e-commerce checkout', 'subscription billing', 'payment integrations'],
    cwe: [472, 841, 602],
    chainsWith: ['checkout-plan-id-tampering', 'checkout-negative-quantity', 'coupon-enumeration-stacking'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://portswigger.net/web-security/logic-flaws',
        title: 'PortSwigger: Business logic — excessive trust in client-side controls',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README',
        title: 'OWASP WSTG: Business Logic Testing (test payment functionality)',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['checkout-plan-id-tampering'],
    title: 'Plan / price-id substitution to a cheaper or free tier',
    symptom:
      'The subscription request carries a `plan_id`/`price_id`/`tier` the server bills from directly; swapping it to a cheaper (or $0/internal) plan while receiving the premium entitlement grants premium for less/nothing.',
    procedure:
      'Enumerate plan/price identifiers (from the pricing page, API, or by incrementing). In the subscribe request, keep the premium entitlement path but substitute a cheaper/free/internal `plan_id`. If the server binds the granted features to a different field than the billed plan, you get premium features billed at the cheaper plan.',
    whenToUse:
      'Billing flows where the granted tier and the charged plan are resolved from separate, client-influenced identifiers.',
    confirmationSignal:
      'The account is provisioned with premium features while billed against the cheaper/free plan_id — the granted-entitlement vs charged-plan mismatch is the signal, versus the legitimate flow where both match the premium plan.',
    preconditions: ['plan/price id supplied by client', 'entitlement not re-derived from the actually-charged plan'],
    appliesTo: ['subscription billing', 'Stripe-style plan/price ids', 'SaaS checkout'],
    cwe: [472, 841, 639],
    chainsWith: ['checkout-price-tampering', 'entitlement-no-revalidate-downgrade'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/logic-flaws',
        title: 'PortSwigger: Business logic vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['checkout-negative-quantity'],
    title: 'Negative quantity / amount to create credit or a free order',
    symptom:
      'A quantity/amount field accepts negative or otherwise out-of-range values, so a negative line offsets the total to zero (free order) or posts positive store credit to the buyer.',
    procedure:
      'In the cart/checkout request set an item quantity (or an add-on amount) to a negative number. Observe the recomputed total: a negative line can zero out the order or, worse, be refunded as credit. Confirm the order completes and the subscription/goods are granted despite the manipulated total.',
    whenToUse:
      'Cart/checkout logic lacking lower-bound (>=1) validation on quantity/amount.',
    confirmationSignal:
      'A negative quantity/amount yields a $0 (or credit) total AND a completed, fulfilled order where a normal positive quantity charges full price — the out-of-range input is accepted and fulfilled.',
    preconditions: ['quantity/amount accepts negative values', 'total computed without bound checks'],
    appliesTo: ['e-commerce checkout', 'wallet/credit systems', 'subscription add-ons'],
    cwe: [472, 841, 20],
    chainsWith: ['checkout-price-tampering', 'coupon-enumeration-stacking'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README',
        title: 'OWASP WSTG: Business Logic Data Validation / test payment functionality',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/logic-flaws',
        title: 'PortSwigger: Business logic vulnerabilities',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['subscription-refund-race'],
    title: 'Subscription-state race: activate, consume, then refund/cancel',
    symptom:
      'Activation and the payment/refund lifecycle are not atomic, so an attacker can activate premium, use it, and refund/cancel before the entitlement is revoked — or fire concurrent requests so a single payment yields multiple activations.',
    procedure:
      'Map the activate→bill→refund lifecycle. Test process-timing gaps: activate premium and immediately request refund/cancel while access persists; or send concurrent activation requests against one payment/coupon so several pass the check-then-act before commit (single-packet/last-byte-sync to minimize jitter). Confirm the entitlement outlives the payment.',
    whenToUse:
      'Payment/entitlement flows with non-atomic check-then-act or a refund path that does not synchronously revoke access.',
    confirmationSignal:
      'Premium access remains active after the payment is refunded/cancelled (or one payment activates premium N times), violating the one-active-paid-subscription invariant that the sequential flow upholds.',
    preconditions: ['non-atomic activation/refund lifecycle', 'endpoint accepts concurrent requests'],
    appliesTo: ['subscription billing', 'wallet/credit flows', 'payment webhooks'],
    cwe: [362, 367, 841],
    chainsWith: ['race-condition', 'entitlement-no-revalidate-downgrade'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README',
        title: 'OWASP WSTG: Business Logic — test for process timing',
        tier: 1,
        kind: 'writeup'
      },
      {
        url: 'https://portswigger.net/web-security/race-conditions',
        title: 'PortSwigger: Race conditions',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['entitlement-no-revalidate-downgrade'],
    title: 'Server never re-validates entitlement after downgrade / expiry',
    symptom:
      'Premium is checked only at upgrade time; after downgrade, cancellation, or subscription expiry the access token/session or feature flag is not re-evaluated, so premium keeps working until re-login.',
    procedure:
      'Upgrade to premium and capture the session/token and a premium-only request. Downgrade/cancel/let it lapse, then replay the same premium request with the existing session. If access still succeeds, the server trusts the stale entitlement snapshot and never re-checks the current subscription state.',
    whenToUse:
      'Apps that cache entitlement in a long-lived token/session/flag and only refresh it at purchase time.',
    confirmationSignal:
      'A premium request continues to return premium content after the subscription is downgraded/expired (on the same un-refreshed session), whereas a freshly authenticated free session is denied — the stale entitlement is honored past its validity.',
    preconditions: ['entitlement cached at upgrade time', 'no re-validation on each request / after state change'],
    appliesTo: ['JWT/session-cached entitlements', 'SaaS subscriptions', 'mobile apps'],
    cwe: [613, 841, 285],
    chainsWith: ['entitlement-jwt-claim', 'subscription-refund-race'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control vulnerabilities and privilege escalation',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['entitlement-response-tamper'],
    title: 'Flip the entitlement flag in the API response the client reads',
    symptom:
      'The client fetches its own entitlement (`{"isPremium": false}`) and unlocks the UI/content based on that response; tampering the response (self-MITM/proxy on your own device) flips the UI to premium.',
    procedure:
      'Proxy your own client and intercept the entitlement/profile response. Rewrite `isPremium`/`plan`/`entitlements` to the premium value before it reaches the app. Observe whether premium content then becomes accessible — this reveals whether the actual content is server-gated or merely UI-gated on a client-trusted response.',
    whenToUse:
      'Diagnosing client-side enforcement: apps that decide access from a client-fetched entitlement response.',
    confirmationSignal:
      'DIFFERENTIAL diagnosis — if flipping the response also yields the real premium DATA, enforcement is purely client-side (the server still serves premium content to a free account); if the UI unlocks but premium requests still return 402/403/empty, the wall is genuinely server-side. The two outcomes distinguish cosmetic vs enforced gating.',
    preconditions: ['client decides access from a fetched entitlement response', 'ability to intercept own client traffic'],
    appliesTo: ['SPAs', 'mobile apps', 'client-gated feature flags'],
    cwe: [602, 807],
    chainsWith: ['entitlement-client-trusted', 'paywall-api-no-entitlement', 'iap-store-callback-forge'],
    qualityTier: 2,
    sources: [
      {
        url: 'https://portswigger.net/web-security/access-control',
        title: 'PortSwigger: Access control — client-side enforcement is insufficient',
        tier: 1,
        kind: 'writeup'
      }
    ]
  },
  // -------------------------------------------------------------------------
  // MOBILE IAP — purchase / receipt validation done or trusted client-side.
  // -------------------------------------------------------------------------
  {
    namespaces: ['iap-receipt-client-validation'],
    title: 'In-app-purchase receipt validated only on the client',
    symptom:
      'The app validates the App Store / Play receipt locally on-device and unlocks premium without a server confirming the purchase, so tampering the local validation (jailbreak/root tweak, patched binary) grants entitlements for free.',
    procedure:
      'Determine where the purchase is verified. If validation is local (parsing the receipt in-app, or trusting a StoreKit/Billing callback) with no server round-trip to Apple/Google, patch or hook the validation result on a jailbroken/rooted device (or with a repackaged binary / IAP-cracking tweak) to return "purchased". Premium unlocks because nothing server-side reconciles the receipt.',
    whenToUse:
      'Mobile apps that gate premium on a device-side receipt/entitlement check rather than server-side validation.',
    confirmationSignal:
      'Premium unlocks on a device where no genuine purchase/receipt exists (or with a forged local receipt), whereas a correctly server-validated app would reject it — the entitlement is granted purely from the tampered on-device check.',
    preconditions: ['receipt/purchase validated on-device', 'no server-side receipt validation with Apple/Google'],
    appliesTo: ['Apple StoreKit', 'Google Play Billing', 'jailbroken/rooted devices'],
    cwe: [603, 602, 345],
    chainsWith: ['iap-receipt-replay-forge', 'iap-store-callback-forge'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.futurice.com/blog/validating-in-app-purchases-in-your-ios-app',
        title: 'Validating in-app purchases in your iOS app (client vs server-side)',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['iap-receipt-replay-forge'],
    title: 'Replayable or forged IAP receipt accepted by validation',
    symptom:
      'Receipt validation accepts a captured/replayed receipt or one for a different product/user because it does not bind the receipt to the transaction (fresh nonce, product id, and account), enabling reuse of a single legitimate receipt or a forged one.',
    procedure:
      'Capture a valid receipt (from a real purchase, or MITM the device-to-store path). Replay it to the app/validation endpoint for another install/account, or submit a receipt for the wrong product. If validation does not check freshness (nonce), product binding, and ownership, it accepts the replayed/forged receipt and grants premium.',
    whenToUse:
      'IAP validation that lacks nonce/product/account binding, or trusts a device-supplied receipt without server verification against the store.',
    confirmationSignal:
      'A replayed/forged receipt grants premium on an install/account that never purchased, where strict validation (fresh nonce + product + account bound, verified against Apple/Google) would reject it — the reused/forged receipt is the differentiator.',
    preconditions: ['receipt not bound to a fresh transaction/product/account', 'validation trusts client-supplied receipt'],
    appliesTo: ['Apple receipt validation', 'Google Play Billing', 'server receipt validators'],
    cwe: [294, 345, 565],
    chainsWith: ['iap-receipt-client-validation', 'iap-store-callback-forge'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.futurice.com/blog/validating-in-app-purchases-in-your-ios-app',
        title: 'Validating in-app purchases in your iOS app (replay / wrong-product receipts)',
        tier: 2,
        kind: 'writeup'
      }
    ]
  },
  {
    namespaces: ['iap-store-callback-forge'],
    title: 'Forge the store purchase callback / MITM entitlement response',
    symptom:
      'The app grants premium from a "purchase succeeded" callback or an entitlement response that a user controlling the device can fake or MITM, without a signature-verified server confirmation.',
    procedure:
      'Intercept the store/purchase callback or the entitlement API response on your own device (proxy or on-device tweak) and return a success/entitled payload without paying. If the SDK/app does not verify a cryptographic signature on the entitlement (e.g. RevenueCat trusted-entitlements or a server webhook), premium is granted from the forged response.',
    whenToUse:
      'IAP/subscription SDKs that unlock on a client-visible callback/response lacking integrity verification.',
    confirmationSignal:
      'A MITM/forged "entitled" response unlocks premium without a real purchase, whereas signature-verified entitlements (trusted-entitlements / server webhook) would reject the tampered response — the missing integrity check is the signal.',
    preconditions: ['premium granted from a client-visible callback/response', 'no cryptographic signature / server webhook verification'],
    appliesTo: ['RevenueCat', 'StoreKit/Play Billing callbacks', 'subscription SDKs'],
    cwe: [345, 347, 602],
    chainsWith: ['iap-receipt-client-validation', 'iap-receipt-replay-forge', 'entitlement-response-tamper'],
    qualityTier: 1,
    sources: [
      {
        url: 'https://www.revenuecat.com/docs/customers/trusted-entitlements',
        title: 'RevenueCat: Trusted Entitlements (MITM entitlement grant + signature verification)',
        tier: 2,
        kind: 'advisory'
      },
      {
        url: 'https://www.futurice.com/blog/validating-in-app-purchases-in-your-ios-app',
        title: 'Validating in-app purchases in your iOS app',
        tier: 2,
        kind: 'writeup'
      }
    ]
  }
];
