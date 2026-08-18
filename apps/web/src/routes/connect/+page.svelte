<script lang="ts">
	/**
	 * 02_CONNECT_AN_AGENT — for a plain user this IS the entire application.
	 *
	 * The hand-off draws states 01 and 02 as two labelled bands on one artboard;
	 * at runtime they are one page branching on whether the account holds a key.
	 *
	 * The secret lives in component state and nowhere else: it arrives once from
	 * create/refresh, is never persisted, and is gone the moment this component
	 * unmounts — matching the "leave this screen and the secret is gone" note,
	 * and matching reality, since the server only ever stores its hash.
	 */
	import { onMount } from 'svelte';
	import CopyButton from '$lib/components/CopyButton.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import AppHeader from '$lib/components/AppHeader.svelte';
	import RoleGuard from '$lib/components/RoleGuard.svelte';
	import {
		createKey,
		fetchCurrentKey,
		formatCalls,
		formatTier,
		mcpClientConfig,
		refreshKey,
		revokeKey,
		type ApiKeyInfo
	} from '$lib/api/keys';
	import { formatRelative, formatStamp } from '$lib/time';
	import type { Session } from '$lib/api/session.svelte';

	const RETRY = 'Something went wrong. Please try again.';

	let key = $state<ApiKeyInfo | null>(null);
	let secret = $state<string | null>(null);
	let loading = $state(true);
	let busy = $state(false);
	let errorMessage = $state('');
	let loadFailed = $state(false);
	let confirmRevoke = $state(false);
	let confirmRefresh = $state(false);
	let dismissedFirstAccount = $state(false);

	/** Origin the MCP client should point at — the deployment's own. */
	let origin = $state('https://bit.0xspryon.work');
	onMount(() => {
		origin = window.location.origin;
		void load();
	});

	async function load() {
		const result = await fetchCurrentKey();
		if (result.ok) {
			key = result.data;
			loadFailed = false;
		} else {
			// Distinct from "you have no key": telling a user who DOES hold one
			// that they have none invites them to press create, which the
			// one-key server guard then rejects.
			loadFailed = true;
			errorMessage = result.error.message || RETRY;
		}
		loading = false;
	}

	async function create() {
		if (busy) return;
		busy = true;
		errorMessage = '';
		const result = await createKey();
		if (result.ok) {
			secret = result.data.key;
			key = result.data;
		} else {
			errorMessage = result.error.message || RETRY;
		}
		busy = false;
	}

	async function doRefresh() {
		if (busy) return;
		busy = true;
		errorMessage = '';
		confirmRefresh = false;
		const result = await refreshKey();
		if (result.ok) {
			secret = result.data.key;
			// The refresh response is the new key's metadata; re-read anyway so
			// the band reflects exactly what the server now holds.
			await load();
		} else {
			errorMessage = result.error.message || RETRY;
			// The old key may already be revoked at this point — re-read rather
			// than leaving stale metadata on screen.
			await load();
		}
		busy = false;
	}

	async function doRevoke() {
		if (busy || !key) return;
		busy = true;
		errorMessage = '';
		confirmRevoke = false;
		const result = await revokeKey(key.id, key.configId);
		if (result.ok) {
			key = null;
			secret = null;
		} else {
			errorMessage = result.error.message || RETRY;
		}
		busy = false;
	}

	const keyDisplay = $derived(key?.start ? `${key.start}…` : 'bit_sk_…');
	/** Without the live secret the config carries a PLACEHOLDER, never the
	 * truncated prefix — copying a config with `bit_sk_7f2c…` in it produces a
	 * file that silently fails to authenticate. */
	const configJson = $derived(mcpClientConfig(secret ?? '<YOUR_API_KEY>', origin));
</script>

<svelte:head><title>bit — connect your agent</title></svelte:head>

<RoleGuard>
	{#snippet children(session: Session)}
		<div class="min-h-screen bg-paper">
			<!-- While impersonating a user, better-auth swaps the session to THEIR
			     role — so this naturally collapses to the user's own navigation,
			     which is exactly the design's "become their app" rule. -->
			<AppHeader
				{session}
				items={session.role === 'admin'
					? [
							{ href: '/admin/users', label: 'USERS' },
							{ href: '/connect', label: 'CONNECT' }
						]
					: [{ href: '/connect', label: 'CONNECT' }]}
			/>

			<!-- The hand-off words this as "you're the first user, so you're the
			     administrator", but nothing in the session distinguishes the
			     first account from one promoted later via SET_ROLE — and telling
			     a promoted admin they were the first user is simply false. Same
			     purpose (explain why curation is unlocked), accurate wording. -->
			{#if session.role === 'admin' && !dismissedFirstAccount}
				<div
					class="flex items-center justify-between gap-6 border-b border-hairline bg-code-bg
						px-gutter py-5 lg:px-gutter-lg"
				>
					<span class="flex flex-col gap-1">
						<span class="font-mono text-[11px] font-bold tracking-[2px] text-ink">
							ROLE: ADMIN
						</span>
						<span class="text-[14.5px] text-muted">
							You're an administrator, so the curation screens are unlocked for you.
						</span>
					</span>
					<button
						type="button"
						onclick={() => (dismissedFirstAccount = true)}
						class="flex-none border border-rule px-3.5 py-2 font-mono text-[10.5px] tracking-[2px]
							text-muted transition-colors hover:border-ink hover:text-ink"
					>
						UNDERSTOOD
					</button>
				</div>
			{/if}

			{#if errorMessage}
				<p
					role="alert"
					class="border-b border-hairline px-gutter py-4 font-mono text-[11px] tracking-[1px]
						text-ink lg:px-gutter-lg"
				>
					{errorMessage}
				</p>
			{/if}

			{#if loading}
				<p class="px-gutter py-24 font-mono text-[11px] tracking-[2px] text-meta lg:px-gutter-lg">
					LOADING…
				</p>
			{:else if loadFailed}
				<section class="px-gutter py-24 lg:px-gutter-lg">
					<span class="bit-label mb-4"><i class="bit-marker"></i>COULD_NOT_LOAD</span>
					<p class="mb-6 max-w-[52ch] text-[15px] leading-[1.8] text-muted">
						We couldn't read your key just now, so this page can't tell you whether you hold one.
						Nothing has changed on your account.
					</p>
					<button
						type="button"
						class="btn-hairline"
						onclick={() => {
							loading = true;
							void load();
						}}
					>
						RETRY
					</button>
				</section>
			{:else if !key}
				<!-- STATE 01 — nothing is issued automatically. -->
				<section class="px-gutter pt-10 pb-10 lg:px-gutter-lg lg:pt-[52px] lg:pb-10">
					<div class="mb-6 flex items-baseline justify-between gap-6 lg:mb-[26px]">
						<span class="bit-label"><i class="bit-marker"></i>NO KEY YET</span>
						<span class="bit-meta">NOTHING IS ISSUED AUTOMATICALLY</span>
					</div>
					<div class="grid items-start gap-8 lg:grid-cols-[1fr_470px] lg:gap-16">
						<div class="min-w-0">
							<p class="mb-5 font-mono text-sm text-meta">$ bit keys create</p>
							<h1
								class="mb-5 font-serif text-[34px] leading-[1.1] font-normal tracking-[-0.7px]
									text-ink lg:text-[50px] lg:tracking-[-1.1px]"
							>
								Connect your agent.
							</h1>
							<p class="mb-8 max-w-[52ch] text-[15px] leading-[1.8] text-pretty text-muted lg:text-base">
								You hold one key at a time. Create it, paste it into your MCP client, and you're
								done — nothing here needs revisiting until you refresh it.
							</p>
							<button type="button" class="btn-ink" onclick={create} disabled={busy}>
								{busy ? 'CREATING…' : 'CREATE_MY_KEY'}
								<span aria-hidden="true">→</span>
							</button>
							<p class="mt-4 font-mono text-[11px] tracking-[0.5px] text-meta">
								Free · default tier · 20 requests / 60s.
							</p>
						</div>
						<aside class="border border-dashed border-rule px-[22px] pt-[22px] pb-6">
							<span
								class="mb-4 block font-mono text-[11px] font-bold tracking-[2px] text-ink"
							>
								YOUR_KEY
							</span>
							<p class="mb-4 font-mono text-xs leading-[1.8] tracking-[1px] text-faint">
								NONE ISSUED
							</p>
							<p class="text-[13.5px] leading-[1.75] text-muted">
								A key is never minted for you at signup. This panel stays empty until you press
								create — then it becomes the metadata band.
							</p>
						</aside>
					</div>
				</section>
			{:else}
				<!-- STATE 02 — secret once, metadata forever. -->
				<section class="px-gutter pt-10 pb-12 lg:px-gutter-lg lg:pt-11 lg:pb-[60px]">
					<div class="mb-6 flex items-baseline justify-between gap-6 lg:mb-[26px]">
						<span class="bit-label"><i class="bit-marker"></i>YOUR KEY</span>
						<span class="bit-meta">SECRET ONCE · METADATA FOREVER</span>
					</div>

					{#if secret}
						<div class="mb-[34px] border border-ink">
							<div
								class="flex items-center justify-between gap-5 border-b border-hairline px-5 py-3.5"
							>
								<span class="font-mono text-[11px] font-bold tracking-[2px] text-ink">
									SECRET_SHOWN_ONCE
								</span>
								<span class="font-mono text-[10.5px] tracking-[1.5px] text-faint">
									NOT RECOVERABLE — STORE IT NOW
								</span>
							</div>
							<div class="px-5 pt-[22px] pb-6">
								<div class="bg-ink px-5 pt-[18px] pb-5 text-rule-soft">
									<div
										class="mb-4 flex items-center justify-between border-b border-ink-soft pb-3"
									>
										<span class="font-mono text-[10.5px] font-semibold tracking-[2px]">
											BIT_API_KEY
										</span>
										<span class="[&_button]:bg-rule-soft [&_button]:text-ink">
											<CopyButton value={secret} label="API key" />
										</span>
									</div>
									<p
										class="m-0 font-mono text-sm leading-[1.6] tracking-[0.5px] break-all text-rule-soft"
									>
										{secret}
									</p>
								</div>
								<p class="mt-4 max-w-[56ch] text-sm leading-[1.75] text-muted">
									Leave this screen and the secret is gone — the metadata band below is all that
									remains. There is no history and no way to read it again.
								</p>
							</div>
						</div>
					{/if}

					<div class="mb-[34px] border border-hairline">
						<div
							class="flex items-baseline justify-between gap-5 border-b border-hairline px-5 py-3.5"
						>
							<span class="font-mono text-[11px] font-bold tracking-[2px] text-ink">YOUR_KEY</span>
							<span class="font-mono text-[10.5px] tracking-[1.5px] text-meta">
								ONE PER ACCOUNT · NO HISTORY
							</span>
						</div>
						<dl class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
							{#each [['PREFIX', keyDisplay], ['TIER', formatTier(key)], ['CREATED', formatStamp(key.createdAt)], ['LAST_USED', formatRelative(key.lastRequest)], ['CALLS_60S', formatCalls(key)]] as [label, value] (label)}
								<div
									class="border-b border-hairline px-5 pt-4 pb-[18px] last:border-b-0
										sm:[&:nth-last-child(-n+2)]:border-b-0 lg:border-b-0 lg:border-r
										lg:last:border-r-0"
								>
									<span
										class="mb-[7px] block font-mono text-[10px] tracking-[1.5px] text-meta"
									>
										{label}
									</span>
									<span class="font-mono text-[12.5px] break-all text-ink">{value}</span>
								</div>
							{/each}
						</dl>
						<div
							class="flex flex-wrap items-center gap-3 border-t border-hairline px-5 pt-4 pb-[18px]"
						>
							<button
								type="button"
								class="btn-hairline px-4 py-[11px] text-[10.5px]"
								onclick={() => (confirmRefresh = true)}
								disabled={busy}
							>
								REFRESH_KEY
							</button>
							<button
								type="button"
								onclick={() => (confirmRevoke = true)}
								disabled={busy}
								class="border border-rule px-4 py-[11px] font-mono text-[10.5px] tracking-[2px]
									text-muted transition-colors hover:border-ink hover:text-ink disabled:opacity-45"
							>
								REVOKE_KEY
							</button>
							<span class="font-mono text-[10px] leading-[1.7] tracking-[0.5px] text-faint">
								Tier follows your account role — read-only. Revoking leaves you with no agent
								access.
							</span>
						</div>
					</div>

					<div
						class="mb-4 flex items-center gap-3 font-mono text-[13px] font-semibold tracking-[1.5px]
							text-ink"
					>
						<i class="bit-marker"></i>OPENCODE_CONFIG
					</div>
					<div class="border border-hairline">
						<div
							class="flex items-center justify-between gap-4 border-b border-hairline px-4 py-[11px]"
						>
							<span class="font-mono text-[10px] tracking-[2px] text-meta">
								FILE: opencode.json
							</span>
							<span class="flex items-center gap-3">
								<span class="hidden font-mono text-[10px] tracking-[2px] text-meta lg:inline">
									JSON
								</span>
								<CopyButton value={configJson} label="opencode config" />
							</span>
						</div>
						<div class="overflow-auto bg-code-bg">
							<pre class="m-0 px-4 py-4 font-mono text-xs leading-[1.75] text-ink">{configJson}</pre>
						</div>
					</div>
					<p class="mt-3 font-mono text-[10px] leading-[1.7] tracking-[0.5px] text-faint">
						Goes in <span class="text-muted">opencode.json</span> at your project root, or
						<span class="text-muted">~/.config/opencode/opencode.json</span> to reach every project.
					</p>
					{#if !secret}
						<p class="mt-2 font-mono text-[10px] leading-[1.7] tracking-[0.5px] text-faint">
							Your secret is not recoverable, so the config carries a placeholder — replace
							&lt;YOUR_API_KEY&gt; with the key you saved, or refresh to mint a new one.
						</p>
					{/if}
				</section>
			{/if}
		</div>

		<Dialog
			open={confirmRefresh}
			title="REFRESH_KEY"
			onclose={() => (confirmRefresh = false)}
		>
			<p class="text-[14.5px] leading-[1.75] text-muted">
				This revokes your current key and issues a new one. Any agent still using the old key stops
				working immediately, and the new secret is shown once.
			</p>
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (confirmRefresh = false)}>
					CANCEL
				</button>
				<button type="button" class="btn-ink" onclick={doRefresh} disabled={busy}>
					{busy ? 'REFRESHING…' : 'REFRESH_KEY'}
				</button>
			{/snippet}
		</Dialog>

		<Dialog open={confirmRevoke} title="REVOKE_KEY" onclose={() => (confirmRevoke = false)}>
			<p class="text-[14.5px] leading-[1.75] text-muted">
				This revokes your key without issuing a replacement. Every agent using it loses access to
				the corpus until you create a new one.
			</p>
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (confirmRevoke = false)}>
					CANCEL
				</button>
				<button type="button" class="btn-ink" onclick={doRevoke} disabled={busy}>
					{busy ? 'REVOKING…' : 'REVOKE_KEY'}
				</button>
			{/snippet}
		</Dialog>
	{/snippet}
</RoleGuard>
