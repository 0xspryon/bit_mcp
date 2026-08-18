<script lang="ts">
	/**
	 * The persistent black bar shown while an admin is driving another account.
	 *
	 * Rendered by the ROOT layout, on every route, so there is no screen where
	 * an impersonation is invisible — the design's "banner is global and sticky"
	 * note. Sticky rather than fixed so it never covers content, and it sits
	 * above the header at every breakpoint including 390.
	 */
	import { goto, invalidateAll } from '$app/navigation';
	import { stopImpersonating } from '$lib/api/admin-users';
	import { fetchSession, type Session } from '$lib/api/session.svelte';

	interface Props {
		session: Session;
	}

	let { session }: Props = $props();

	let stopping = $state(false);
	let failed = $state(false);

	async function stop() {
		if (stopping) return;
		stopping = true;
		failed = false;
		await stopImpersonating();
		// Whether the call reported success or the session had already lapsed,
		// re-read who we are — the session is the source of truth for whether
		// the impersonation actually ended.
		const fresh = await fetchSession();
		if (fresh?.impersonatedBy != null) {
			failed = true;
			stopping = false;
			return;
		}
		await invalidateAll();
		void goto('/admin/users', { replaceState: true });
	}

	const who = $derived(session.name || session.email);
</script>

<div
	class="sticky top-0 z-50 flex items-center justify-between gap-4 bg-ink px-gutter py-3
		text-rule-soft lg:gap-6 lg:px-5"
>
	<span class="flex min-w-0 items-center gap-3 font-mono text-[11.5px] tracking-[1.5px]">
		<i aria-hidden="true" class="inline-block h-2 w-2 flex-none bg-rule-soft"></i>
		<span class="truncate">
			IMPERSONATING @{who.toUpperCase()}<span class="hidden sm:inline"
				>{' — ACTIONS ARE ATTRIBUTED TO THEM'}</span
			>
		</span>
	</span>
	<button
		type="button"
		onclick={stop}
		disabled={stopping}
		class="flex-none bg-rule-soft px-3 py-2 font-mono text-[10.5px] font-bold tracking-[2px]
			text-ink transition-opacity hover:opacity-85 disabled:opacity-45 lg:px-[15px]"
	>
		{stopping ? 'STOPPING…' : 'STOP'}<span class="hidden lg:inline">_IMPERSONATING</span>
	</button>
</div>
{#if failed}
	<p
		role="alert"
		class="bg-ink px-gutter pb-3 font-mono text-[10.5px] tracking-[1px] text-rule-soft lg:px-5"
	>
		Could not stop impersonating. Please try again.
	</p>
{/if}
