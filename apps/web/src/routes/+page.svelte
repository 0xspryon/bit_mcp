<script lang="ts">
	/**
	 * 01_SIGN_IN — the public landing, which doubles as the sign-in.
	 *
	 * One responsive page rather than two: the hand-off ships a 1440 artboard
	 * and a 390 companion, and their differences are all layout and scale —
	 * the hero's right-hand CTA column collapses into STEP 01, the three-step
	 * grid and the ask/response pair stack, and the type steps down. Copy that
	 * differs between the two is picked per-breakpoint below.
	 */
	import CopyButton from '$lib/components/CopyButton.svelte';
	import JsonValue from '$lib/components/JsonValue.svelte';
	import {
		DEMO_CHUNKS,
		DEMO_QUERY,
		DEMO_QUERY_MOBILE,
		DEMO_QUERY_PARAMS,
		DEMO_QUERY_PARAMS_MOBILE
	} from '$lib/demo-response';
	import { signInWithDiscord } from '$lib/api/session.svelte';

	let signingIn = $state(false);
	let signInError = $state('');

	async function signIn() {
		if (signingIn) return;
		signingIn = true;
		signInError = '';
		const result = await signInWithDiscord();
		// On success the browser is already navigating to Discord; only a
		// failure returns control here.
		if (!result.ok) {
			signInError = result.message;
			signingIn = false;
		}
	}

	let index = $state(0);
	const chunk = $derived(DEMO_CHUNKS[index]!);
	const atFirst = $derived(index === 0);
	const atLast = $derived(index === DEMO_CHUNKS.length - 1);

	const chunkJson = $derived(JSON.stringify(chunk, null, 2));
</script>

<svelte:head>
	<title>bit — methodologies, not findings</title>
	<meta
		name="description"
		content="A curated bank of vulnerability methodologies — symptom, procedure, confirmation signal — served to coding and pentest agents over MCP."
	/>
</svelte:head>

<div class="min-h-screen bg-paper">
	<header
		class="flex items-center justify-between border-b border-hairline px-gutter py-[18px]
			lg:items-baseline lg:px-gutter-lg lg:py-[22px]"
	>
		<span class="flex items-baseline gap-2 lg:gap-[9px]">
			<span class="font-mono text-xs text-meta lg:text-[13px]">~/</span>
			<span class="font-serif text-[17px] font-medium text-ink italic lg:text-[21px]">bit</span>
		</span>
		<span class="font-mono text-[10px] tracking-[1.5px] text-meta lg:text-[11px]">
			BIT.0XSPRYON.WORK
		</span>
	</header>

	<!-- Row one is the claim. Full width so the headline can run a line longer
	     and the Discord action sits at the right edge, unmissable. -->
	<section
		class="border-b border-hairline px-gutter pt-[46px] pb-[38px] lg:flex lg:items-end
			lg:justify-between lg:gap-16 lg:px-gutter-lg lg:pt-[74px] lg:pb-[60px]"
	>
		<div>
			<p class="mb-[18px] font-mono text-[13px] text-meta lg:mb-6 lg:text-sm">
				<span class="lg:hidden">$ bit auth login</span>
				<span class="hidden lg:inline">$ bit auth login --provider discord</span>
			</p>
			<h1
				class="mb-5 font-serif text-[40px] leading-[1.08] font-normal tracking-[-0.8px] text-ink
					lg:mb-[26px] lg:text-[76px] lg:leading-[1.03] lg:tracking-[-1.7px]"
			>
				Methodologies, <em class="italic">not findings.</em>
			</h1>
			<p class="mb-6 max-w-[62ch] text-[15px] leading-[1.75] text-pretty text-muted lg:mb-0 lg:text-[16.5px] lg:leading-[1.8]">
				<span class="lg:hidden">
					Curated vulnerability methodologies — symptom, procedure, confirmation signal — served to
					your agents over MCP.
				</span>
				<span class="hidden lg:inline">
					A curated bank of vulnerability methodologies — symptom, procedure, confirmation signal —
					served to coding and pentest agents over MCP. Humans curate; agents consume.
				</span>
			</p>
			<p class="font-mono text-[11px] tracking-[1px] text-meta lg:hidden">
				214 records · 38 namespaces
			</p>
		</div>

		<!-- Desktop only: on the 390 companion this action lives in STEP 01
		     instead, so the hero stays a single column of type. -->
		<div class="hidden flex-none text-right lg:block">
			<button type="button" class="btn-ink" onclick={signIn} disabled={signingIn}>
				{signingIn ? 'REDIRECTING…' : 'CONTINUE_WITH_DISCORD'}
				<span aria-hidden="true">→</span>
			</button>
			<p class="mt-4 font-mono text-[11px] leading-[1.75] tracking-[0.5px] text-meta">
				The only way in.<br />214 records · 38 namespaces
			</p>
		</div>
	</section>

	{#if signInError}
		<p
			role="alert"
			class="border-b border-hairline bg-code-bg px-gutter py-4 font-mono text-[11px]
				tracking-[1px] text-ink lg:px-gutter-lg"
		>
			{signInError}
		</p>
	{/if}

	<section
		class="border-b border-hairline px-gutter pt-8 pb-9 lg:px-gutter-lg lg:pt-10 lg:pb-11"
	>
		<div class="mb-[22px] flex items-baseline justify-between gap-3 lg:mb-6 lg:gap-6">
			<span class="bit-label text-[10.5px] lg:text-[11px]">
				<i class="bit-marker"></i>
				<span class="lg:hidden">THREE STEPS</span>
				<span class="hidden lg:inline">THREE STEPS TO A CONNECTED AGENT</span>
			</span>
			<span class="bit-meta text-[9.5px] lg:text-[10.5px]">
				<span class="lg:hidden">FREE</span>
				<span class="hidden lg:inline">UNDER A MINUTE · FREE</span>
			</span>
		</div>

		<div class="grid gap-7 lg:grid-cols-3 lg:gap-12">
			<div class="flex flex-col gap-[11px] lg:gap-[14px]">
				<span class="font-mono text-[9.5px] tracking-[2px] text-meta lg:text-[10px]">STEP 01</span>
				<p class="font-serif text-[22px] leading-[1.2] text-ink lg:text-2xl">
					Sign in with Discord.
				</p>
				<p class="text-[13.5px] leading-[1.7] text-muted">
					The only way an account comes into existence.<span class="hidden lg:inline">
						No email signup, no invites.</span
					>
				</p>
				<button
					type="button"
					class="btn-ink mt-auto w-full px-[18px] py-[15px] text-[11px] lg:py-[14px]"
					onclick={signIn}
					disabled={signingIn}
				>
					{signingIn ? 'REDIRECTING…' : 'CONTINUE_WITH_DISCORD'}
					<span aria-hidden="true">→</span>
				</button>
			</div>

			<div class="flex flex-col gap-[11px] lg:gap-[14px]">
				<span class="font-mono text-[9.5px] tracking-[2px] text-meta lg:text-[10px]">STEP 02</span>
				<p class="font-serif text-[22px] leading-[1.2] text-ink lg:text-2xl">Create your API key.</p>
				<p class="text-[13.5px] leading-[1.7] text-muted">
					Shown once, free, 20 requests / 60s. Rotating<span class="hidden lg:inline"> later</span> is
					create → move agents → revoke<span class="hidden lg:inline">, never in place</span>.
				</p>
				<span
					class="mt-auto bg-code-bg px-[14px] py-3 font-mono text-[11.5px] break-all text-ink"
				>
					bit_sk_7f2c91ae…
				</span>
			</div>

			<div class="flex flex-col gap-[11px] lg:gap-[14px]">
				<span class="font-mono text-[9.5px] tracking-[2px] text-meta lg:text-[10px]">STEP 03</span>
				<p class="font-serif text-[22px] leading-[1.2] text-ink lg:text-2xl">
					Point your MCP client at bit.
				</p>
				<p class="text-[13.5px] leading-[1.7] text-muted">
					One endpoint, one header — then your agent researches with a curated corpus behind it.<span
						class="hidden lg:inline"
					>
						Free.</span
					>
				</p>
				<span
					class="mt-auto bg-code-bg px-[14px] py-3 font-mono text-[11px] leading-[1.7] break-all text-ink"
				>
					url: bit.0xspryon.work/api/v1/mcp<br />x-api-key: bit_sk_7f2c…
				</span>
			</div>
		</div>
	</section>

	<!-- Row two is the proof. Ask and response sit side by side inside the band
	     so reading left to right mirrors request → response. -->
	<section
		class="grid grid-cols-1 items-start gap-9 px-gutter pt-9 pb-10 lg:grid-cols-2 lg:gap-14
			lg:px-gutter-lg lg:pt-[52px] lg:pb-[60px]"
	>
		<!-- min-w-0 on both tracks: grid items default to `min-width:auto`, so
		     without it the response block's `min-w-max` code widens the column
		     (and the page) instead of scrolling inside its own overflow box. -->
		<div class="min-w-0">
			<span class="bit-label mb-[18px]">
				<i class="bit-marker"></i>
				<span class="lg:hidden">WHAT AN AGENT ASKS</span>
				<span class="hidden lg:inline">WHAT AN AGENT ASKS FOR</span>
			</span>
			<div class="bg-ink px-5 pt-5 pb-[22px] text-rule-soft">
				<div class="mb-4 border-b border-ink-soft pb-3">
					<span class="font-mono text-[10.5px] font-semibold tracking-[2px]">MCP · bit.search</span>
				</div>
				<p class="relative mb-3 pl-[18px] font-mono text-[12.5px] leading-[1.8]">
					<span aria-hidden="true" class="absolute left-0 text-meta">&gt;</span>
					<span class="lg:hidden">"{DEMO_QUERY_MOBILE}"</span>
					<span class="hidden lg:inline">"{DEMO_QUERY}"</span>
				</p>
				<p class="relative pl-[18px] font-mono text-[12.5px] leading-[1.8] text-meta">
					<span aria-hidden="true" class="absolute left-0">&gt;</span>
					<span class="lg:hidden">{DEMO_QUERY_PARAMS_MOBILE}</span>
					<span class="hidden lg:inline">{DEMO_QUERY_PARAMS}</span>
				</p>
			</div>
		</div>

		<div class="min-w-0">
			<div class="mb-[18px] flex items-center justify-between gap-4">
				<span class="bit-label"><i class="bit-marker"></i>WHAT COMES BACK</span>
				<!-- Steps through the five ranked chunks. Client-side only: no
				     request, so the ends disable rather than wrap. -->
				<span class="flex flex-none items-center gap-2.5">
					<button
						type="button"
						aria-label="Previous chunk"
						disabled={atFirst}
						onclick={() => (index -= 1)}
						class="border px-2.5 py-1.5 font-mono text-xs leading-none transition-colors
							{atFirst
							? 'cursor-not-allowed border-hairline text-faint'
							: 'border-ink text-ink hover:bg-ink hover:text-paper'}"
					>
						←
					</button>
					<span class="font-mono text-[11px] font-semibold tracking-[1.5px] text-ink">
						{index + 1} / {DEMO_CHUNKS.length}
					</span>
					<button
						type="button"
						aria-label="Next chunk"
						disabled={atLast}
						onclick={() => (index += 1)}
						class="border px-2.5 py-1.5 font-mono text-xs leading-none transition-colors
							{atLast
							? 'cursor-not-allowed border-hairline text-faint'
							: 'border-ink text-ink hover:bg-ink hover:text-paper'}"
					>
						→
					</button>
				</span>
			</div>

			<div class="border border-hairline">
				<div
					class="flex items-center justify-between gap-4 border-b border-hairline px-4 py-[11px]"
				>
					<span class="font-mono text-[10px] tracking-[2px] text-meta">
						<span class="lg:hidden">RESPONSE · JSON</span>
						<span class="hidden lg:inline">RESPONSE · application/json</span>
					</span>
					<span class="flex items-center gap-3">
						<span class="hidden font-mono text-[10px] tracking-[2px] text-meta lg:inline">
							SCROLL
						</span>
						<CopyButton value={chunkJson} label="Response JSON" />
					</span>
				</div>
				<div class="max-h-[440px] overflow-auto bg-code-bg">
					<pre class="m-0 pt-4 pb-[18px]"><code
							class="block min-w-max px-4 font-mono text-xs leading-[1.75]"
							><JsonValue value={chunk} /></code
						></pre>
				</div>
				<div
					class="flex items-center justify-between gap-4 border-t border-hairline px-4 py-[11px]"
				>
					<span class="font-mono text-[10px] tracking-[1.5px] text-meta">
						{index + 1} OF {DEMO_CHUNKS.length} CHUNKS
					</span>
					<span class="font-mono text-[10px] tracking-[1.5px] text-meta">
						score {chunk.score} · tier {chunk.qualityTier}
					</span>
				</div>
			</div>
		</div>
	</section>

	<footer
		class="flex items-center justify-between border-t border-hairline px-gutter py-[26px]
			font-mono text-[11px] tracking-[1px] text-meta lg:px-gutter-lg"
	>
		<span class="hidden lg:inline">STATUS: OPERATIONAL&nbsp;&nbsp;|&nbsp;&nbsp;CORPUS: 214_RECORDS</span>
		<span class="lg:hidden">STATUS: OPERATIONAL</span>
		<span>BIT // 2026</span>
	</footer>
</div>
