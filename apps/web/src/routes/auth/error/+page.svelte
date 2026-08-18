<script lang="ts">
	/** Where better-auth's OAuth error redirect lands. Deliberately terse: the
	 * provider's own reason is not ours to paraphrase, and the only useful next
	 * action is to try again. */
	import { page } from '$app/state';

	const reason = $derived(page.url.searchParams.get('error'));
</script>

<div class="flex min-h-screen flex-col items-center justify-center gap-6 bg-paper px-gutter text-center">
	<p class="font-mono text-[11px] tracking-[2px] text-meta">SIGN_IN_FAILED</p>
	<h1 class="font-serif text-[40px] leading-[1.08] text-ink">That didn't go through.</h1>
	<p class="max-w-[46ch] text-[15px] leading-[1.75] text-muted">
		Discord didn't complete the sign-in{reason ? ` (${reason})` : ''}. Nothing was created — you can
		try again.
	</p>
	<a href="/" class="btn-ink no-underline">BACK_TO_START <span aria-hidden="true">→</span></a>
</div>
