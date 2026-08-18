<script lang="ts">
	/**
	 * One JSON value, rendered in the design's two-tone scheme: keys in `meta`,
	 * long string values in `muted`, everything else in `ink`. Recurses into
	 * itself for arrays and objects.
	 *
	 * Built as a component walk rather than a regex over `JSON.stringify` so the
	 * output is escaped by Svelte and never needs `{@html}` — this renders API
	 * response shapes, which is exactly the content you do not want to inject.
	 *
	 * Literal spacing goes through `{' '}`-style expressions rather than source
	 * whitespace: the markup sits inside a `<pre>`, and Svelte collapses
	 * whitespace between tags, which would silently eat the space after every
	 * colon and add one after every brace.
	 */
	import Self from './JsonValue.svelte';

	interface Props {
		value: unknown;
		/** Nesting depth, used for indentation. */
		depth?: number;
		/** Rendered after the value — a comma when this is not the last entry. */
		trailing?: string;
	}

	let { value, depth = 0, trailing = '' }: Props = $props();

	const pad = (level: number) => '  '.repeat(level);

	const isObject = (v: unknown): v is Record<string, unknown> =>
		typeof v === 'object' && v !== null && !Array.isArray(v);

	/** Long prose reads as body copy rather than a literal, matching the
	 * hand-off — short strings stay ink so ids and enums keep their weight. */
	const LONG_STRING = 60;

	const entries = $derived(isObject(value) ? Object.entries(value) : []);
	const items = $derived(Array.isArray(value) ? value : []);
	/** Arrays of primitives stay on one line; arrays of objects break. */
	const inlineArray = $derived(
		Array.isArray(value) && value.every((v) => typeof v !== 'object' || v === null)
	);
</script>

{#if Array.isArray(value)}{#if inlineArray}<span class="text-ink">[</span>{#each items as item, i}<Self
				value={item}
				depth={0}
				trailing={i < items.length - 1 ? ', ' : ''}
			/>{/each}<span class="text-ink">]{trailing}</span>{:else}<span class="text-ink"
			>[</span
		>{#each items as item, i}{'\n' + pad(depth + 1)}<Self
				value={item}
				depth={depth + 1}
				trailing={i < items.length - 1 ? ',' : ''}
			/>{/each}{'\n' + pad(depth)}<span class="text-ink">]{trailing}</span>{/if}{:else if isObject(value) && entries.length === 0}<span class="text-ink">&#123;&#125;{trailing}</span
	>{:else if isObject(
	value
)}<span class="text-ink">&#123;</span>{#each entries as [key, entryValue], i}{'\n' +
		pad(depth + 1)}<span class="text-meta">"{key}"</span><span class="text-ink">{': '}</span><Self
			value={entryValue}
			depth={depth + 1}
			trailing={i < entries.length - 1 ? ',' : ''}
		/>{/each}{'\n' + pad(depth)}<span class="text-ink">&#125;{trailing}</span>{:else if typeof value ===
	'string'}<span class={value.length > LONG_STRING ? 'text-muted' : 'text-ink'}
		>"{value}"{trailing}</span
	>{:else}<span class="text-ink">{JSON.stringify(value)}{trailing}</span>{/if}
