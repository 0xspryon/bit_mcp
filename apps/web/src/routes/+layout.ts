/**
 * Turns the whole app into a client-rendered SPA.
 *
 * `ssr = false` is what lets `adapter-static` emit a single fallback shell
 * rather than demanding every route be prerenderable — the app is behind a
 * login and reads per-user API state, so there is nothing meaningful to render
 * ahead of time.
 *
 * `prerender = false` is deliberate rather than redundant: without it the
 * adapter would try to crawl and freeze routes like `/admin/users` at build
 * time, which would bake a logged-out shell into a path that must always be
 * resolved live.
 */
export const ssr = false;
export const prerender = false;
