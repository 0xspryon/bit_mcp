<script lang="ts">
	/**
	 * A modal over its backdrop.
	 *
	 * Built on the native `<dialog>` element deliberately: `showModal()` gives
	 * focus trapping, Esc-to-close, an inert background and `::backdrop` from
	 * the platform, so none of that has to be reimplemented (or forgotten). The
	 * only styling the element needs is its own reset — browsers give `dialog`
	 * a default border, padding and `max-width`.
	 */
	import type { Snippet } from 'svelte';

	interface Props {
		open: boolean;
		/** Mono uppercase heading, e.g. `BAN_USER · @throwaway_11`. */
		title: string;
		/** Called for Esc, backdrop click, and any close the browser initiates —
		 * the parent owns `open`, so it must be told when the element closes. */
		onclose: () => void;
		children: Snippet;
		/** Footer buttons, right-aligned. */
		actions?: Snippet;
	}

	let { open, title, onclose, children, actions }: Props = $props();

	let el = $state<HTMLDialogElement | null>(null);

	$effect(() => {
		if (!el) return;
		if (open && !el.open) el.showModal();
		else if (!open && el.open) el.close();
	});

	/** A click landing on the dialog element itself (not its content box) is a
	 * backdrop click — the element fills the viewport while the panel does not. */
	function onBackdropClick(event: MouseEvent) {
		if (event.target === el) onclose();
	}
</script>

<dialog
	bind:this={el}
	onclose={onclose}
	onclick={onBackdropClick}
	aria-label={title}
	class="m-auto max-w-[min(92vw,520px)] border border-ink bg-paper p-0 text-body
		backdrop:bg-ink/45"
>
	<div class="border-b border-hairline px-5 py-3.5">
		<h2 class="font-mono text-[11px] font-bold tracking-[2px] text-ink">{title}</h2>
	</div>
	<div class="px-5 py-5">
		{@render children()}
	</div>
	{#if actions}
		<div class="flex flex-wrap items-center justify-end gap-3 border-t border-hairline px-5 py-4">
			{@render actions()}
		</div>
	{/if}
</dialog>
