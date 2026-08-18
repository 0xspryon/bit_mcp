import { createHash } from 'node:crypto';

/**
 * Deterministic, pure content hash used as the dedup key for records.
 *
 * The hash is insensitive to leading/trailing whitespace, internal whitespace
 * runs, and case — two inputs that differ only in those respects produce the
 * same hash and therefore dedupe to the same record.
 */

/** Collapse a string to its canonical form for hashing. */
export const normalize = (s: string): string => s.trim().toLowerCase().replace(/\s+/g, ' ');

/**
 * Stable SHA-256 hex digest over the normalized (title, symptom, procedure)
 * triple.
 *
 * The fields are joined with `'\n'`. Because {@link normalize} collapses every
 * whitespace run (including newlines) to a single space, a `'\n'` can never
 * appear *inside* a normalized field — so it is an unambiguous field delimiter.
 * Joining with a space would let a boundary coincide with an internal space and
 * make distinct records ({title:"sql", symptom:"injection"} vs
 * {title:"sql injection", symptom:""}) collide, silently deduping them.
 */
export const contentHash = (input: {
  title: string;
  symptom: string;
  procedure: string;
}): string => {
  const canonical = [
    normalize(input.title),
    normalize(input.symptom),
    normalize(input.procedure)
  ].join('\n');
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
};
