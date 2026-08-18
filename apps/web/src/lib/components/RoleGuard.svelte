<script lang="ts">
	/**
	 * Renders its children only once the better-auth session has been read and
	 * matches `require`. Anything else is redirected away.
	 *
	 * This is chrome, not security: every privileged call is gated server-side
	 * regardless. Its job is to avoid painting an admin screen at a user, and
	 * to avoid flashing a signed-out landing at someone who is signed in.
	 */
	import { onMount, type Snippet } from 'svelte';
	import { goto } from '$app/navigation';
	import { fetchSession, homeFor, type Session, type SessionRole } from '$lib/api/session.svelte';

	interface Props {
		/** Role this subtree demands. Omit to allow any signed-in caller. */
		require?: SessionRole;
		children: Snippet<[Session]>;
	}

	let { require: requiredRole, children }: Props = $props();

	let session = $state<Session | null>(null);

	onMount(() => {
		void fetchSession().then((fresh) => {
			if (!fresh) {
				void goto('/', { replaceState: true });
				return;
			}
			if (requiredRole && fresh.role !== requiredRole) {
				// Signed in, wrong door — send them to their own home rather
				// than the landing, which would read as a failed sign-in.
				void goto(homeFor(fresh.role), { replaceState: true });
				return;
			}
			session = fresh;
		});
	});
</script>

{#if session}
	{@render children(session)}
{:else}
	<div class="flex min-h-screen items-center justify-center bg-paper px-gutter">
		<p class="font-mono text-[11px] tracking-[2px] text-meta">LOADING…</p>
	</div>
{/if}
