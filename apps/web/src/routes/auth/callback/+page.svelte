<script lang="ts">
	/**
	 * Fallback landing for a completed OAuth sign-in.
	 *
	 * The API rewrites the callback's 302 to the role's real home, so this page
	 * is normally never seen. It exists so the flow degrades gracefully rather
	 * than breaking if that hook ever stops firing: re-read the session, route
	 * accordingly, and cost one extra hop instead of stranding the user.
	 */
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { fetchSession, homeFor } from '$lib/api/session.svelte';

	onMount(() => {
		void fetchSession().then((session) => {
			void goto(session ? homeFor(session.role) : '/auth/error', { replaceState: true });
		});
	});
</script>

<div class="flex min-h-screen items-center justify-center bg-paper px-gutter">
	<p class="font-mono text-[11px] tracking-[2px] text-meta">SIGNING_YOU_IN…</p>
</div>
