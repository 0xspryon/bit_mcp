<script lang="ts">
	/**
	 * 08_USERS_AND_IMPERSONATION — admin only, and the most dangerous control
	 * in the product.
	 *
	 * Two design rules drive the shape of this screen:
	 *
	 *  - "Become their app." Impersonating hides curation entirely and lands on
	 *    /connect. We never draw admin chrome with disabled entries; the point
	 *    of impersonation is to see exactly what the user sees.
	 *  - "No invite flow." Accounts only exist because someone signed in with
	 *    Discord, so there is deliberately no create-user affordance anywhere.
	 */
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import AppHeader from '$lib/components/AppHeader.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import RoleGuard from '$lib/components/RoleGuard.svelte';
	import {
		banUser,
		resolveBanExpiry,
		impersonateUser,
		listAdminUsers,
		revokeUserSessions,
		setRole,
		unbanUser,
		type AdminUser
	} from '$lib/api/admin-users';
	import { fetchSession, type Session } from '$lib/api/session.svelte';
	import { formatDate, formatRelative } from '$lib/time';

	const RETRY = 'Something went wrong. Please try again.';

	let users = $state<AdminUser[]>([]);
	let loading = $state(true);
	let loadFailed = $state(false);
	let busy = $state(false);
	let errorMessage = $state('');

	let impersonateTarget = $state<AdminUser | null>(null);
	let banTarget = $state<AdminUser | null>(null);
	let unbanTarget = $state<AdminUser | null>(null);
	let revokeTarget = $state<AdminUser | null>(null);
	let roleTarget = $state<AdminUser | null>(null);

	let banReason = $state('');
	let banExpires = $state('');
	let banError = $state('');

	onMount(() => void load());

	async function load() {
		errorMessage = '';
		const result = await listAdminUsers();
		if (result.ok) {
			users = result.data.users;
			loadFailed = false;
		} else {
			// Kept distinct from a genuinely empty directory — "no accounts yet"
			// is a very different claim from "we could not read the accounts".
			loadFailed = true;
			errorMessage =
				result.error.code === 'FORBIDDEN' || result.error.code === 'UNAUTHORIZED'
					? 'You need admin access to view users.'
					: RETRY;
		}
		loading = false;
	}

	/** Run an action, then re-read the directory so counts and state stay true. */
	async function run(action: () => Promise<{ ok: boolean; error?: { message: string } }>) {
		if (busy) return false;
		busy = true;
		errorMessage = '';
		const result = await action();
		if (!result.ok) {
			errorMessage = result.error?.message || RETRY;
			busy = false;
			return false;
		}
		await load();
		busy = false;
		return true;
	}

	async function confirmImpersonate() {
		const target = impersonateTarget;
		if (!target) return;
		busy = true;
		errorMessage = '';
		const result = await impersonateUser(target.id);
		if (!result.ok) {
			errorMessage = result.error.message || RETRY;
			busy = false;
			return;
		}
		impersonateTarget = null;
		// Re-read before navigating: the session cookie now belongs to the
		// target, and the layout's banner keys off `impersonatedBy`.
		await fetchSession();
		await goto('/connect', { replaceState: true, invalidateAll: true });
	}

	async function confirmBan() {
		const target = banTarget;
		if (!target) return;
		const expiry = resolveBanExpiry(banExpires);
		if (!expiry.ok) {
			// Refuse rather than quietly converting a bad date into a permanent ban.
			banError = expiry.message;
			return;
		}
		banError = '';
		const ok = await run(() =>
			banUser(target.id, banReason.trim() || undefined, expiry.seconds)
		);
		if (ok) {
			banTarget = null;
			banReason = '';
			banExpires = '';
		}
	}

	const roleOf = (u: AdminUser): 'admin' | 'user' => (u.role === 'admin' ? 'admin' : 'user');

	/**
	 * The first account is the oldest one — that is what "first user" means, and
	 * it is NOT the same as "is an admin" (SET_ROLE can promote anyone) nor
	 * "is me". Derived from the data rather than asserted about the viewer.
	 */
	const firstAccountId = $derived(
		users.length === 0
			? null
			: users.reduce((oldest, u) =>
					Date.parse(u.createdAt) < Date.parse(oldest.createdAt) ? u : oldest
				).id
	);

	/** The sub-line under an account name. Ban reason wins — it is the most
	 * important thing about a row — then key usage, then the join date. */
	function subline(u: AdminUser): string {
		if (u.banned) {
			const reason = u.banReason ? `"${u.banReason}"` : 'BANNED';
			const until = u.banExpires ? ` · UNTIL ${formatDate(u.banExpires)}` : ' · INDEFINITE';
			return `${reason}${until}`;
		}
		const lead = u.id === firstAccountId ? 'FIRST ACCOUNT · ' : '';
		if (u.apiKeys > 0) {
			return `${lead}${u.apiKeys} KEY${u.apiKeys === 1 ? '' : 'S'} · LAST SEEN ${formatRelative(u.lastSeen).toUpperCase()}`;
		}
		return `${lead}NO KEY · JOINED ${formatDate(u.createdAt)}`;
	}

	/** The 390 card's single meta line, which folds keys, sessions and last-seen
	 * into one row — the desktop table has separate columns for these. */
	function mobileMeta(u: AdminUser, isSelf: boolean): string {
		if (u.banned) {
			const reason = u.banReason ? `"${u.banReason}"` : 'BANNED';
			const until = u.banExpires ? ` · UNTIL ${formatDate(u.banExpires)}` : ' · INDEFINITE';
			return `${reason}${until}`;
		}
		const parts = [
			`${u.apiKeys} KEY${u.apiKeys === 1 ? '' : 'S'}`,
			`${u.activeSessions} SESSION${u.activeSessions === 1 ? '' : 'S'}`
		];
		if (u.id === firstAccountId) parts.unshift('FIRST ACCOUNT');
		if (isSelf) parts.push('YOU');
		else if (u.lastSeen) parts.push(`LAST SEEN ${formatRelative(u.lastSeen).toUpperCase()}`);
		return parts.join(' · ');
	}

	/** Today in UTC, for the date input's `min`. */
	function todayIso(): string {
		return new Date().toISOString().slice(0, 10);
	}

	/** A zero count cannot distinguish "revoked" from "never signed in" or
	 * "expired", so it says 0 rather than asserting a cause. */
	function sessionsLabel(u: AdminUser): string {
		return u.activeSessions > 0 ? `${u.activeSessions} ACTIVE` : '0';
	}
</script>

<svelte:head><title>bit — users</title></svelte:head>

<RoleGuard require="admin">
	{#snippet children(session: Session)}
		<div class="min-h-screen bg-paper">
			<AppHeader
				{session}
				items={[
					{ href: '/admin/users', label: 'USERS' },
					{ href: '/connect', label: 'CONNECT' }
				]}
			/>

			<section class="px-gutter pt-10 pb-16 lg:px-gutter-lg lg:pt-11 lg:pb-[70px]">
				<div
					class="flex items-baseline justify-between gap-6 border-b border-hairline pb-[18px]"
				>
					<span
						class="flex items-center gap-3 font-mono text-sm font-semibold tracking-[1.5px] text-ink"
					>
						<i class="bit-marker"></i>USERS
					</span>
					<span class="font-mono text-[11.5px] tracking-[1.5px] text-meta">
						{users.length} ACCOUNT{users.length === 1 ? '' : 'S'}<span
							class="hidden sm:inline">{' · ARRIVED VIA DISCORD · NO INVITES'}</span
						>
					</span>
				</div>

				{#if errorMessage}
					<p role="alert" class="mt-5 font-mono text-[11px] tracking-[1px] text-ink">
						{errorMessage}
					</p>
				{/if}

				{#if loading}
					<p class="mt-8 font-mono text-[11px] tracking-[2px] text-meta">LOADING…</p>
				{:else if loadFailed}
					<button
						type="button"
						class="btn-hairline mt-8"
						onclick={() => {
							loading = true;
							void load();
						}}
					>
						RETRY
					</button>
				{:else if users.length === 0}
					<p class="mt-8 font-mono text-[11px] tracking-[1px] text-meta">
						No accounts yet. They appear here as people sign in with Discord.
					</p>
				{:else}
					<!-- The 390 companion stacks each account into a card instead of
					     scrolling the table sideways — actions stay thumb-reachable. -->
					<div class="mt-[22px] lg:hidden">
						{#each users as u (u.id)}
							{@const isSelf = u.id === session.userId}
							<div class="border-b border-hairline pb-5 last:border-b-0 [&+div]:mt-5">
								<div class="mb-2 flex items-center justify-between gap-3">
									<span
										class="truncate font-mono text-[13.5px] {u.banned ? 'text-meta' : 'text-ink'}"
									>
										@{u.name || u.email}
									</span>
									{#if u.banned}
										<span
											class="chip-banned flex-none px-2 py-[3px] font-mono text-[10px] tracking-[1.5px]"
										>
											BANNED
										</span>
									{:else if roleOf(u) === 'admin'}
										<span
											class="flex-none bg-ink px-2 py-[3px] font-mono text-[10px] tracking-[1.5px]
												text-paper"
										>
											ADMIN
										</span>
									{:else}
										<span
											class="flex-none border border-rule px-2 py-[3px] font-mono text-[10px]
												tracking-[1.5px] text-muted"
										>
											USER
										</span>
									{/if}
								</div>
								<p
									class="mb-3.5 font-mono text-[10px] leading-[1.7] tracking-[1px]
										{u.banned ? 'text-faint' : 'text-meta'}"
								>
									{mobileMeta(u, isSelf)}
								</p>
								{#if !isSelf}
									<div class="grid gap-2">
										{#if u.banned}
											<button
												type="button"
												class="btn-hairline w-full py-3 text-[10.5px]"
												onclick={() => (unbanTarget = u)}
												disabled={busy}
											>
												UNBAN
											</button>
										{:else}
											<button
												type="button"
												class="btn-ink w-full py-3 text-[10.5px]"
												onclick={() => (impersonateTarget = u)}
												disabled={busy}
											>
												IMPERSONATE
											</button>
											<div class="flex gap-2">
												<button
													type="button"
													class="flex-1 border border-rule py-3 font-mono text-[10.5px]
														tracking-[1.5px] text-muted disabled:opacity-45"
													onclick={() => (roleTarget = u)}
													disabled={busy}
												>
													SET_ROLE
												</button>
												<button
													type="button"
													class="flex-1 border border-rule py-3 font-mono text-[10.5px]
														tracking-[1.5px] text-muted disabled:opacity-45"
													onclick={() => {
														banTarget = u;
														banReason = '';
														banExpires = '';
														banError = '';
													}}
													disabled={busy}
												>
													BAN
												</button>
											</div>
										{/if}
									</div>
								{/if}
							</div>
						{/each}
					</div>

					<div class="mt-[26px] hidden overflow-x-auto lg:block">
						<table class="w-full border-collapse">
							<thead>
								<tr class="text-left font-mono text-[10px] tracking-[1.5px] text-meta">
									<th class="border-b border-hairline pb-3 font-normal">ACCOUNT</th>
									<th class="border-b border-hairline pb-3 font-normal">ROLE</th>
									<th class="border-b border-hairline pb-3 font-normal">SESSIONS</th>
									<th class="border-b border-hairline pb-3 font-normal">STATE</th>
									<th class="border-b border-hairline pb-3 text-right font-normal">ACTIONS</th>
								</tr>
							</thead>
							<tbody>
								{#each users as u (u.id)}
									{@const isSelf = u.id === session.userId}
									<tr>
										<td class="border-b border-hairline py-[18px] pr-4">
											<span class="flex flex-col gap-1">
												<span class="font-mono text-sm text-ink">@{u.name || u.email}</span>
												<span class="font-mono text-[10.5px] tracking-[1px] text-meta">
													{subline(u)}
												</span>
											</span>
										</td>
										<td class="border-b border-hairline py-[18px] pr-4">
											{#if roleOf(u) === 'admin'}
												<span
													class="bg-ink px-[9px] py-1 font-mono text-[10.5px] tracking-[1.5px]
														text-paper"
												>
													ADMIN
												</span>
											{:else}
												<span
													class="border border-rule px-[9px] py-1 font-mono text-[10.5px]
														tracking-[1.5px] text-muted"
												>
													USER
												</span>
											{/if}
										</td>
										<td
											class="border-b border-hairline py-[18px] pr-4 font-mono text-xs
												whitespace-nowrap text-muted"
										>
											{sessionsLabel(u)}
											{#if u.activeSessions > 0 && !isSelf}
												<button
													type="button"
													onclick={() => (revokeTarget = u)}
													disabled={busy}
													class="ml-1 text-meta underline underline-offset-[3px]
														hover:text-ink disabled:opacity-45"
												>
													REVOKE
												</button>
											{/if}
										</td>
										<td
											class="border-b border-hairline py-[18px] pr-4 font-mono text-[11px]
												tracking-[1px] text-meta"
										>
											{isSelf ? 'YOU' : u.banned ? 'BANNED' : 'OK'}
										</td>
										<td class="border-b border-hairline py-[18px] text-right">
											{#if isSelf}
												<span class="font-mono text-[10.5px] tracking-[1.5px] text-faint">—</span>
											{:else}
												<span class="flex flex-wrap justify-end gap-2">
													{#if u.banned}
														<button
															type="button"
															class="btn-hairline px-3 py-2 text-[10px]"
															onclick={() => (unbanTarget = u)}
															disabled={busy}
														>
															UNBAN
														</button>
													{:else}
														<button
															type="button"
															class="btn-hairline px-3 py-2 text-[10px]"
															onclick={() => (roleTarget = u)}
															disabled={busy}
														>
															SET_ROLE
														</button>
														<button
															type="button"
															class="btn-hairline px-3 py-2 text-[10px]"
															onclick={() => {
																banTarget = u;
																banReason = '';
																banExpires = '';
															}}
															disabled={busy}
														>
															BAN
														</button>
													{/if}
													<button
														type="button"
														class="btn-hairline px-3 py-2 text-[10px]"
														onclick={() => (impersonateTarget = u)}
														disabled={busy}
													>
														IMPERSONATE
													</button>
												</span>
											{/if}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</section>
		</div>

		<!-- The most dangerous control in the product gets the most explicit
		     confirm: what will be recorded, and against whom. -->
		<Dialog
			open={impersonateTarget !== null}
			title="CONFIRM_IMPERSONATE"
			onclose={() => (impersonateTarget = null)}
		>
			{#if impersonateTarget}
				<p class="mb-4 text-[15px] leading-[1.75] text-body">
					You are about to act as
					<span class="bg-code-bg px-1.5 py-px font-mono text-sm">
						@{impersonateTarget.name || impersonateTarget.email}
					</span>. Every request, key creation and revocation you make will be recorded against their
					account, with your id stored as the impersonator.
				</p>
				<ul class="list-disc pl-[18px] text-[13.5px] leading-[1.8] text-muted">
					<li>You will see their world — the connect screen only, no curation.</li>
					<li>A black banner stays on every screen until you stop.</li>
					<li>Sessions record who impersonated whom.</li>
				</ul>
			{/if}
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (impersonateTarget = null)}>
					CANCEL
				</button>
				<button type="button" class="btn-ink" onclick={confirmImpersonate} disabled={busy}>
					{busy ? 'SWITCHING…' : 'IMPERSONATE'}
				</button>
			{/snippet}
		</Dialog>

		<Dialog
			open={banTarget !== null}
			title={banTarget ? `BAN_USER · @${banTarget.name || banTarget.email}` : 'BAN_USER'}
			onclose={() => (banTarget = null)}
		>
			<div class="grid gap-4">
				<label class="block">
					<span class="mb-1.5 block font-mono text-[10px] tracking-[1.5px] text-meta">
						REASON — RECORDED ON THE ACCOUNT
					</span>
					<input
						type="text"
						bind:value={banReason}
						placeholder="scripted key churn"
						class="block w-full border border-hairline bg-code-bg px-3 py-2.5 text-sm text-ink
							placeholder:text-faint"
					/>
				</label>
				<label class="block">
					<span class="mb-1.5 block font-mono text-[10px] tracking-[1.5px] text-meta">
						EXPIRES — BLANK MEANS INDEFINITE
					</span>
					<input
						type="date"
						bind:value={banExpires}
						min={todayIso()}
						class="block w-full border border-hairline bg-code-bg px-3 py-2.5 font-mono text-[13px]
							text-ink"
					/>
				</label>
				{#if banError}
					<p role="alert" class="font-mono text-[10px] leading-[1.7] tracking-[1px] text-ink">
						{banError}
					</p>
				{/if}
				<p class="font-mono text-[10px] tracking-[1px] text-faint">
					Keys stop authenticating immediately.
				</p>
			</div>
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (banTarget = null)}>
					CANCEL
				</button>
				<button type="button" class="btn-ink" onclick={confirmBan} disabled={busy}>
					{busy ? 'BANNING…' : 'BAN_AND_REVOKE_SESSIONS'}
				</button>
			{/snippet}
		</Dialog>

		<Dialog
			open={unbanTarget !== null}
			title={unbanTarget ? `UNBAN · @${unbanTarget.name || unbanTarget.email}` : 'UNBAN'}
			onclose={() => (unbanTarget = null)}
		>
			<p class="text-[14.5px] leading-[1.75] text-muted">
				This restores the account. They can sign in again and create a new key; the old one is not
				restored.
			</p>
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (unbanTarget = null)}>
					CANCEL
				</button>
				<button
					type="button"
					class="btn-ink"
					disabled={busy}
					onclick={async () => {
						const target = unbanTarget;
						if (target && (await run(() => unbanUser(target.id)))) unbanTarget = null;
					}}
				>
					{busy ? 'UNBANNING…' : 'UNBAN'}
				</button>
			{/snippet}
		</Dialog>

		<Dialog
			open={revokeTarget !== null}
			title={revokeTarget
				? `REVOKE_SESSIONS · @${revokeTarget.name || revokeTarget.email}`
				: 'REVOKE_SESSIONS'}
			onclose={() => (revokeTarget = null)}
		>
			<p class="text-[14.5px] leading-[1.75] text-muted">
				This signs the account out everywhere. Their API key keeps working — revoking sessions is
				not the same as revoking agent access.
			</p>
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (revokeTarget = null)}>
					CANCEL
				</button>
				<button
					type="button"
					class="btn-ink"
					disabled={busy}
					onclick={async () => {
						const target = revokeTarget;
						if (target && (await run(() => revokeUserSessions(target.id)))) revokeTarget = null;
					}}
				>
					{busy ? 'REVOKING…' : 'REVOKE_SESSIONS'}
				</button>
			{/snippet}
		</Dialog>

		<Dialog
			open={roleTarget !== null}
			title={roleTarget ? `SET_ROLE · @${roleTarget.name || roleTarget.email}` : 'SET_ROLE'}
			onclose={() => (roleTarget = null)}
		>
			{#if roleTarget}
				<p class="text-[14.5px] leading-[1.75] text-muted">
					{roleOf(roleTarget) === 'admin'
						? 'Demoting this account to USER removes curation access immediately. Their existing API key keeps the tier it was issued with — refresh or revoke it separately to change that.'
						: 'Promoting this account to ADMIN unlocks curation immediately. Their existing API key keeps the tier it was issued with; only a newly created key picks up the admin tier. Grant it sparingly.'}
				</p>
			{/if}
			{#snippet actions()}
				<button type="button" class="btn-hairline" onclick={() => (roleTarget = null)}>
					CANCEL
				</button>
				<button
					type="button"
					class="btn-ink"
					disabled={busy}
					onclick={async () => {
						const target = roleTarget;
						if (!target) return;
						const next = roleOf(target) === 'admin' ? 'user' : 'admin';
						if (await run(() => setRole(target.id, next))) roleTarget = null;
					}}
				>
					{#if busy}
						UPDATING…
					{:else}
						MAKE_{roleTarget && roleOf(roleTarget) === 'admin' ? 'USER' : 'ADMIN'}
					{/if}
				</button>
			{/snippet}
		</Dialog>
	{/snippet}
</RoleGuard>
