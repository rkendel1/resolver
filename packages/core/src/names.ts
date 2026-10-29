/**
 * Reference names: `ref://<namespace>/<name>[/<name>...]`, e.g. `ref://prod/chat/model`.
 *
 * A name identifies what a value is for, not where it lives or which version it is. The namespace is
 * usually an environment (`prod`, `staging`). Names are lowercase so they can't be confused by case.
 */

export type RefName = `ref://${string}`;

const SEGMENT = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const MAX_LENGTH = 256;

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

export interface ParsedRef {
  ref: RefName;
  namespace: string;
  path: readonly string[];
}

export function parseRef(input: unknown): Parsed<ParsedRef> {
  if (typeof input !== 'string') return { ok: false, error: 'a reference must be a string' };
  if (input.length > MAX_LENGTH) return { ok: false, error: `a reference must be at most ${MAX_LENGTH} characters` };
  if (!input.startsWith('ref://')) return { ok: false, error: 'a reference starts with ref://' };
  const segments = input.slice('ref://'.length).split('/');
  if (segments.length < 2) return { ok: false, error: 'a reference is ref://<namespace>/<name>' };
  const bad = segments.find((s) => !SEGMENT.test(s));
  if (bad !== undefined) {
    return { ok: false, error: `"${bad}" is not a valid segment: lowercase letters, digits, ".", "_" and "-"` };
  }
  return { ok: true, value: { ref: input as RefName, namespace: segments[0]!, path: segments.slice(1) } };
}

export function isRef(input: unknown): input is RefName {
  return parseRef(input).ok;
}

/**
 * A grant pattern: `*` (everything), an exact reference, or a prefix ending in `/*`
 * (`ref://prod/payments/*` matches every reference below `ref://prod/payments/`).
 */
export function isPattern(pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('/*')) return parseRef(`${pattern.slice(0, -2)}/x`).ok || pattern === 'ref://*';
  return isRef(pattern);
}

export function matches(ref: string, pattern: string): boolean {
  if (pattern === '*' || pattern === 'ref://*') return true;
  if (pattern.endsWith('/*')) return ref.startsWith(pattern.slice(0, -1));
  return ref === pattern;
}
