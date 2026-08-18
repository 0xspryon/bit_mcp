import { describe, expect, it } from 'vitest';
import { resolveBanExpiry } from './admin-users';

// 2026-08-18 11:30Z — mid-afternoon in Europe, so "today" is genuinely still
// in progress. This is exactly the case that used to become a permanent ban.
const NOW = Date.parse('2026-08-18T11:30:00Z');

describe('resolveBanExpiry', () => {
	it('treats a blank date as an indefinite ban', () => {
		expect(resolveBanExpiry('', NOW)).toEqual({ ok: true, seconds: undefined });
	});

	it('anchors to the end of the chosen day, so picking today still bans today', () => {
		const result = resolveBanExpiry('2026-08-18', NOW);
		expect(result.ok).toBe(true);
		// 11:30Z → 23:59:59Z is 12h29m59s.
		expect(result.ok && result.seconds).toBe(44999);
	});

	it('resolves a future date to a positive duration', () => {
		const result = resolveBanExpiry('2026-09-30', NOW);
		expect(result.ok && result.seconds).toBeGreaterThan(0);
	});

	// The regression: a past date must NOT silently collapse to "indefinite".
	it('refuses a past date rather than making the ban permanent', () => {
		const result = resolveBanExpiry('2026-08-17', NOW);
		expect(result.ok).toBe(false);
		expect(result.ok === false && result.message).toMatch(/past/i);
	});

	it('refuses an unparseable date', () => {
		const result = resolveBanExpiry('not-a-date', NOW);
		expect(result.ok).toBe(false);
	});
});
