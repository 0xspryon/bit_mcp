# bit — UI Design Brief

## What this is

**bit** is a curated knowledge base of *vulnerability methodologies* — structured
write-ups of how to find and confirm a class of security bug — served to AI
coding/pentest agents over MCP, backed by a hybrid RAG retrieval pipeline.

Humans curate; agents consume. A record describes a repeatable technique: the
symptom that hints at it, the procedure to test it, and the signal that confirms
it. Agents query the corpus in natural language and get back ranked, cited
methodology chunks.

This brief covers the **human web console**. Agents never touch it — they reach
the corpus over MCP with an API key.

## Audiences

The two roles use this product for genuinely different reasons. Design them as
two different applications that happen to share a sign-in.

**Admin** — the first user to ever sign up is auto-promoted; everyone after is
`user`. Admins are curators: they author records, review the ingest queue,
search the corpus directly, retire records, and manage users.

**User** — an *agent operator*, not a reader. They never query the corpus through
the web app; their agent does that over MCP. Their entire reason to open this
site is to obtain and manage the API key that connects their agent, then leave.

Read the user side as an onboarding-and-credentials surface, not a reduced
version of the admin console. Success for a user is being connected in under a
minute and rarely needing to come back.

## Auth

- **Discord OAuth** is the only way an account comes into existence in production.
  No self-serve email signup, no invite flow, and no admin-created account that
  can actually sign in. Users appear because they signed in with Discord.
- Email + password exists only when `ENVIRONMENT != production`, for local dev.
- Sign-in is a POST returning a redirect URL — not a plain link.
- The first-ever account becomes `admin`. Give this a distinct first-run moment:
  "You're the first user, so you're the administrator."

## The domain model

### Record — the core object

| Field | Type | Notes |
|---|---|---|
| `namespaces` | string[] | **≥1 required**, max 32, each ≤128 chars. Vuln classes (`ssrf`, `web`, `authz`). Retrieval filters by array *overlap*, not equality. |
| `title` | string | ≤300 |
| `symptom` | string | ≤8000. What you observe that suggests this bug. |
| `whenToUse` | string? | ≤4000 |
| `procedure` | string | ≤20000. **The long one** — multi-step instructions, often with payloads/code. Needs real long-form authoring and rendering (markdown + code blocks). |
| `confirmationSignal` | string? | ≤4000. How you know it actually fired. |
| `preconditions` | string[] | ≤32 items, ≤500 each |
| `appliesTo` | string[] | ≤32 items, ≤256 each. Products/stacks. |
| `cwe` | int[] | ≤32 items, each 1–2000 |
| `vrt` | string[] | ≤32 items, ≤256 each. Bugcrowd VRT taxonomy ids. |
| `chainsWith` | string[] | ≤32 items. Related classes this pivots into — **render as navigable links**, it's the most interesting relationship in the model. |
| `qualityTier` | int | **1 = best, 5 = worst.** Inverted from star-rating intuition. Do not use stars. |
| `status` | enum | `staging` \| `active` — only these two. |
| `version` | int | ≥1 |
| `contentHash` | string | Unique; the dedup key. |
| `deletedAt` | timestamp? | Soft delete. NULL = live. **Deleted is not a status** — it's a second, independent axis. A record can be `active` *and* deleted. |

### Source — citation

`url` (unique, http/https, ≤2048), `title?`, `qualityTier` 1–5, `kind?`,
`addedAt`. Many-to-many with records, deduped by URL, so one source can back many
methodologies.

### API key

Two rate-limit tiers, **assigned from the account's role, never chosen**:
- `default` — 20 requests / 60s
- `admin` — 100 requests / 60s

Show the tier as a read-only property. The UI must not imply it is selectable —
the server overwrites any client-supplied value.

## Screens — both roles

### 1. Sign in
The Discord button is the primary and, in production, only action. The
email/password form appears only in dev builds — mark it clearly as development
only so it never reads as a primary path.

### 2. Connect an agent  *(the user's entire application)*
API key management plus the MCP connection details needed to use it: endpoint
URL and the `x-api-key` header, copy-paste ready, ideally as a ready-made client
config block.

For a `user`, this is the whole product. Treat it as a guided first-run — land
them here immediately after their first sign-in with the key-creation step
foregrounded, rather than dropping them on an empty dashboard. For an admin it's
an ordinary settings page.

List, create, revoke. Show tier and its rate limit.

**On creation the secret is shown exactly once** — design that handoff carefully.

**"Refresh" is not an atomic operation.** There is no rotate endpoint; the API
offers create, get, list, update, and delete only. Rotating means creating the
replacement, moving agents over, then revoking the old one. Design it as that
deliberate sequence so nobody bricks a running agent by rotating in place.

## Screens — admin only

### 3. Search console
Admin-only by design: the corpus is read by agents over MCP, and this screen is
the curator's window into what those agents will see.

Natural-language query box plus hard filters: namespaces (multi-select, overlap
semantics), `cwe[]`, `product`, `minTier`, and `k` (1–50, default 5).

Results are ranked chunks: title, namespaces, procedure, confirmation signal,
`chains_with`, sources, quality tier, and a relevance `score`.

**The distinctive design problem on this screen.** Every response carries
retrieval diagnostics, and one is a genuine trust warning:

- `semantic_search_k` (30) vs `semantic_search_count` — candidates the vector leg
  was asked for vs actually returned
- `semantic_search_degraded` — **true means recall was degraded**: the approximate
  index ran out of candidates under the active filters, so the ranking was drawn
  from a thinner pool than intended. Results may look fine but be misleadingly
  sparse.
- `lexical_search_k` (30) vs `lexical_search_count` — an exact scan, so a short
  count here honestly means "no more matches exist"

Those two shortfalls mean opposite things and must not look alike. One says "your
filters were too narrow to trust this ranking"; the other says "the corpus really
is thin here." A funnel visualisation of the pipeline — 30 dense ∥ 30 lexical →
20 fused → reranked → top k — would carry this well. This deserves real design,
not a debug panel.

### 4. Review queue  *(default admin landing)*
Newly ingested records land in `staging` and a human decides whether they're good.
This is the daily driver: scannable list with title, namespaces, quality tier,
CWEs, source count, age. Fast promote-to-active. Open a record without losing
your place.

An empty queue is the success state, not a sad state.

### 5. Record detail
Every field, its sources, status control, version, and deleted state. `procedure`
dominates the page — treat it as the primary content with metadata in a sidebar,
not a header block. `chainsWith` lets the curator pivot to related classes.

This view deliberately still returns soft-deleted records so they can be
inspected. Give "deleted" a clear, distinct treatment.

### 6. Create record
A structured form mirroring the schema, with every length limit enforced inline.
`procedure` needs a large authoring surface with markdown/code support.

Critical response state: ingest is **content-hash deduped**. A submission can come
back `deduped: true`, meaning an identical record already exists. Show *which*
record it collided with and that record's current status — never a generic
"saved" toast.

### 7. Deleted records
A browsable archive of soft-deleted records, separate from the staging/active
queue, with restore. Deletion is reversible by design (`deletedAt` back to NULL),
so present it as retirement rather than destruction.

### 8. Users
List, role, ban/unban with reason and expiry, active sessions, revoke sessions,
set role.

**Impersonation is the headline feature here.** The API supports it directly
(`impersonate-user` / `stop-impersonating`), and sessions record who is
impersonating whom.

Design implications, because this is the most dangerous control in the product:
- Entering impersonation needs explicit confirmation naming the target user.
- While impersonating, a **persistent, unmissable banner** must appear on every
  screen — an admin who forgets they are impersonating will take actions
  attributed to someone else.
- "Stop impersonating" must be reachable from that banner on any screen, always.
- The impersonated session should visibly become the target's app. An admin
  impersonating a `user` should see the user's world — the connect-an-agent
  screen, no curation — which is also the main way an admin can experience what
  a user actually sees.

Note: an admin-created account cannot sign in under production settings
(Discord-only, no password path), so do not design an invite or create-user flow.
Users arrive via Discord; admins manage them afterwards.

### 9. System health
`GET /api/v1/health`, plus embedding and reranker service status. The API refuses to boot
if either is unreachable, so this is a reassurance and diagnostics surface.

## Visual direction

Audience is security researchers and engineers. Information-dense, keyboard-
friendly, no decorative chrome. Dark-first with a working light mode.

Monospace for technical values (CWE ids, hashes, namespaces, payloads).
Proportional for prose (symptom, procedure narrative).

Quality tier needs a scale that reads correctly while being inverted (1 = best).
Avoid stars; avoid green-means-5.

`status` (staging/active) and deleted are **independent axes** and must stay
visually distinguishable rather than collapsing into one badge.

## Constraints

- **No pagination.** Record listing takes `limit` (max 100) and nothing else — no
  cursor, no offset, no total count. Page numbers and infinite scroll are both
  unbuildable as specified. Design for a bounded, capped list.
- **No record editing.** Curators can change status but cannot fix a typo.
- **No sources index** — sources are reachable only nested inside a record.
- Request bodies cap at 1 MiB.
- Errors return `{ error: { code, message } }`; validation failures add
  `issues: [{ path, message }]`, so per-field error placement is achievable.

## Stack

SvelteKit (`apps/web`), currently an untouched starter. `packages/ui` is a stub
with a demo counter. Effectively greenfield — no design system to match.

## Out of scope

The MCP client experience.
