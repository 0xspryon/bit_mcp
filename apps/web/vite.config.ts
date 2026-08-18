import { fileURLToPath } from 'node:url';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defaultClientConditions, defineConfig } from 'vite';

export default defineConfig(({ mode }) => ({
	resolve: {
		alias: {
			'@/web': fileURLToPath(new URL('./src', import.meta.url))
		},
		// Component tests mount Svelte pages under jsdom; the browser condition
		// makes `mount` resolve to the client runtime instead of the server stub.
		...(mode === 'test' ? { conditions: ['browser', ...defaultClientConditions] } : {})
	},
	server: {
		// Honor the port assigned by the host; vite ignores PORT on its own.
		port: process.env.PORT ? Number(process.env.PORT) : undefined,
		// Same-origin API in dev: the RPC client fetches relative /api/* URLs,
		// which vite forwards to the local API container. Production does the
		// same routing behind a reverse proxy, so CORS is never needed — and
		// the better-auth session cookie stays first-party either way.
		proxy: {
			'/api': {
				target: process.env.API_PROXY_TARGET ?? 'http://localhost:3000',
				changeOrigin: true
			}
		}
	},
	plugins: [tailwindcss(), sveltekit()]
}));
