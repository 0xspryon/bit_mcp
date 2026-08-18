<script lang="ts">
	/**
	 * The signed-in header: brand, nav, who you are, sign out.
	 *
	 * Nav items are passed in rather than derived from the role here, because
	 * of the impersonation rule: while an admin is driving someone else's
	 * account they must see THAT account's navigation, not their own with the
	 * curation entries greyed out. Callers decide; this only draws.
	 */
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { signOut, type Session } from '$lib/api/session.svelte';

	interface Props {
		session: Session;
		items?: Array<{ href: string; label: string }>;
	}

	let { session, items = [] }: Props = $props();

	let signingOut = $state(false);

	async function out() {
		if (signingOut) return;
		signingOut = true;
		await signOut();
		void goto('/', { replaceState: true });
	}
</script>

<header
	class="flex items-center justify-between gap-4 border-b border-hairline px-gutter py-[18px]
		lg:gap-8 lg:px-gutter-lg lg:py-5"
>
	<span class="flex flex-none items-baseline gap-2 lg:gap-[9px]">
		<span class="font-mono text-xs text-meta lg:text-[13px]">~/</span>
		<span class="font-serif text-[17px] font-medium text-ink italic lg:text-[21px]">bit</span>
	</span>

	{#if items.length}
		<nav class="mr-auto hidden items-center gap-[30px] lg:flex">
			{#each items as item (item.href)}
				{@const active = page.url.pathname.startsWith(item.href)}
				<a
					href={item.href}
					class="inline-flex items-center gap-[9px] font-mono text-[11.5px] font-medium
						tracking-[2px] no-underline {active ? 'text-ink' : 'text-meta hover:text-ink'}"
				>
					{#if active}<i class="inline-block h-[7px] w-[7px] flex-none bg-ink"></i>{/if}
					{item.label}
				</a>
			{/each}
		</nav>
	{/if}

	<span class="flex flex-none items-center gap-3 lg:gap-[14px]">
		<span class="hidden font-mono text-[10.5px] tracking-[1.5px] text-meta sm:inline">
			@{session.name || session.email} · {session.role.toUpperCase()}
		</span>
		<button
			type="button"
			onclick={out}
			disabled={signingOut}
			class="border border-hairline px-3 py-[7px] font-mono text-[10.5px] tracking-[1.5px]
				text-muted transition-colors hover:border-ink hover:text-ink disabled:opacity-45"
		>
			{signingOut ? 'SIGNING_OUT…' : 'SIGN_OUT'}
		</button>
	</span>
</header>

{#if items.length}
	<!-- The 390 companion has no room for the desktop nav row, so it rides
	     below the header as a scrollable strip rather than behind a drawer. -->
	<nav
		class="flex items-center gap-6 overflow-x-auto border-b border-hairline px-gutter py-3 lg:hidden"
	>
		{#each items as item (item.href)}
			{@const active = page.url.pathname.startsWith(item.href)}
			<a
				href={item.href}
				class="inline-flex flex-none items-center gap-2 font-mono text-[11px] font-medium
					tracking-[2px] no-underline {active ? 'text-ink' : 'text-meta'}"
			>
				{#if active}<i class="inline-block h-[6px] w-[6px] flex-none bg-ink"></i>{/if}
				{item.label}
			</a>
		{/each}
	</nav>
{/if}
