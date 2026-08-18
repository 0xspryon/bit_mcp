import { describe, expect, it } from 'vitest';
import { mcpClientConfig } from './keys';

// The shape here is dictated by opencode, not by us — these assertions exist so
// a well-meaning edit cannot quietly drift back toward the `mcpServers` shape
// that Claude Desktop uses, which opencode ignores entirely.
describe('mcpClientConfig', () => {
	const parsed = (secret = 'bit_sk_test', origin = 'https://bit.example') =>
		JSON.parse(mcpClientConfig(secret, origin));

	it('nests servers under `mcp`, the key opencode reads', () => {
		const config = parsed();
		expect(Object.keys(config.mcp)).toEqual(['bit']);
		expect(config.mcpServers).toBeUndefined();
	});

	it('declares the server remote, or opencode tries to spawn it as a command', () => {
		expect(parsed().mcp.bit.type).toBe('remote');
	});

	it('points at the MCP doorway on the caller\'s own origin', () => {
		expect(parsed('k', 'https://bit.example').mcp.bit.url).toBe('https://bit.example/api/v1/mcp');
	});

	it('carries the key as the x-api-key header the doorway authenticates on', () => {
		expect(parsed('bit_sk_live').mcp.bit.headers).toEqual({ 'x-api-key': 'bit_sk_live' });
	});

	it('renders the placeholder verbatim when no secret is recoverable', () => {
		expect(parsed('<YOUR_API_KEY>').mcp.bit.headers['x-api-key']).toBe('<YOUR_API_KEY>');
	});
})
