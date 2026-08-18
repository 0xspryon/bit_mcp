import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// A single-page app: one `index.html` shell that every unmatched path
		// falls back to, with routing resolved client-side. Nothing here renders
		// on a server — see `src/routes/+layout.ts` — so the production artifact
		// is a directory of static files that any file server can host.
		//
		// `fallback` is what makes deep links work: a cold GET of `/admin/users`
		// has no file on disk, so the server must return the shell and let the
		// client router take over. Caddy's `try_files` does that half.
		adapter: adapter({
			fallback: 'index.html',
			// Emit .br/.gz siblings at build time so Caddy serves precompressed
			// bytes instead of compressing the same assets on every request.
			precompress: true
		}),
		alias: {
			'@/web': './src'
		}
	}
};

export default config;
