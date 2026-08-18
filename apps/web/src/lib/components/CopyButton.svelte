<script lang="ts">
	/** The small ink COPY chip that sits on code blocks and secret values.
	 * Confirms in place for a beat, because the design has no toast surface. */
	interface Props {
		/** Text placed on the clipboard. */
		value: string;
		/** Accessible name — "Copy" alone is ambiguous with several on a page. */
		label: string;
	}

	let { value, label }: Props = $props();

	let state = $state<'idle' | 'copied' | 'failed'>('idle');
	let resetTimer: ReturnType<typeof setTimeout> | undefined;

	$effect(() => () => clearTimeout(resetTimer));

	async function copy() {
		try {
			await navigator.clipboard.writeText(value);
			state = 'copied';
		} catch {
			// Clipboard is unavailable over plain http on some browsers, and
			// permission can be refused outright — say so rather than claiming
			// a copy that did not happen.
			state = 'failed';
		}
		clearTimeout(resetTimer);
		resetTimer = setTimeout(() => (state = 'idle'), 2000);
	}
</script>

<button
	type="button"
	onclick={copy}
	aria-label={label}
	class="bg-ink text-paper font-mono text-[10px] font-bold tracking-[2px] px-2.5 py-1
		transition-opacity hover:opacity-85"
>
	{state === 'copied' ? 'COPIED' : state === 'failed' ? 'COPY_FAILED' : 'COPY'}
</button>
<span aria-live="polite" class="sr-only">
	{state === 'copied' ? `${label} copied` : state === 'failed' ? `${label} could not be copied` : ''}
</span>
