<script lang="ts">
	// Only the weights the design actually uses — serif 400/500 plus its
	// italic, sans 400/500/600, mono 400/500/600/700. Self-hosted rather than
	// pulled from the Google Fonts CDN the hand-off links, so an
	// unauthenticated visitor to a security tool makes no third-party request.
	import '@fontsource/ibm-plex-serif/400.css';
	import '@fontsource/ibm-plex-serif/400-italic.css';
	import '@fontsource/ibm-plex-serif/500.css';
	import '@fontsource/ibm-plex-sans/400.css';
	import '@fontsource/ibm-plex-sans/500.css';
	import '@fontsource/ibm-plex-sans/600.css';
	import '@fontsource/ibm-plex-mono/400.css';
	import '@fontsource/ibm-plex-mono/500.css';
	import '@fontsource/ibm-plex-mono/600.css';
	import '@fontsource/ibm-plex-mono/700.css';
	import '../app.css';

	import { onMount } from 'svelte';
	import ImpersonationBanner from '$lib/components/ImpersonationBanner.svelte';
	import { fetchSession, sessionStore } from '$lib/api/session.svelte';

	let { children } = $props();

	/**
	 * The banner lives at the ROOT so an active impersonation is visible on
	 * every route — that is the whole point of it.
	 *
	 * It reads the shared session store rather than re-reading on navigation:
	 * impersonation starts from /admin/users and stops from the banner, and
	 * both of those already call `fetchSession()`, which publishes here. An
	 * effect keyed on the route would have to both read and write the session,
	 * which re-triggers itself — a request flood, not a refresh.
	 */
	onMount(() => {
		void fetchSession();
	});

	const session = $derived(sessionStore.current);
	const impersonating = $derived(session?.impersonatedBy != null);
</script>

{#if session && impersonating}
	<ImpersonationBanner {session} />
{/if}

{@render children()}
