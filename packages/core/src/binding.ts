/**
 * Bindings and traffic steering.
 *
 * A binding is what a reference currently resolves to: one target, a weighted split (canaries, A/B,
 * gradual migration), or an ordered failover list. Selection is deterministic for a given key, so
 * a user stays on the same target while the split is unchanged ("sticky"), and it runs identically
 * in the resolver and in the client.
 */

import { checkTarget, type Kind, type Target } from './kinds.js';
import type { Parsed } from './names.js';

export const STRATEGIES = ['single', 'weighted', 'failover'] as const;
export type Strategy = (typeof STRATEGIES)[number];

export interface WeightedTarget<T = Target> {
  value: T;
  /** Relative weight for `weighted` (a positive integer). Ignored otherwise. */
  weight?: number;
  /** Optional human label shown in history and selection results (e.g. "canary"). */
  label?: string;
}

export interface Binding<T = Target> {
  strategy: Strategy;
  targets: WeightedTarget<T>[];
}

export const MAX_TARGETS = 16;
const MAX_WEIGHT = 1_000_000;

/** Accepts `{ value }` or `{ strategy, targets }` and validates every target against the kind. */
export function checkBinding(kind: Kind, input: unknown): Parsed<Binding> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { ok: false, error: 'a binding is { value } or { strategy, targets }' };
  }
  const raw = input as Record<string, unknown>;
  if ('value' in raw) {
    if ('targets' in raw || 'strategy' in raw) return { ok: false, error: 'give either value, or strategy and targets' };
    const target = checkTarget(kind, raw['value']);
    return target.ok ? { ok: true, value: { strategy: 'single', targets: [{ value: target.value }] } } : target;
  }
  const strategy = raw['strategy'];
  if (typeof strategy !== 'string' || !(STRATEGIES as readonly string[]).includes(strategy)) {
    return { ok: false, error: `strategy must be one of ${STRATEGIES.join(', ')}` };
  }
  const targets = raw['targets'];
  if (!Array.isArray(targets) || targets.length === 0 || targets.length > MAX_TARGETS) {
    return { ok: false, error: `targets must list 1 to ${MAX_TARGETS} targets` };
  }
  if (strategy === 'single' && targets.length !== 1) return { ok: false, error: 'a single binding has exactly one target' };
  const out: WeightedTarget[] = [];
  for (const [i, entry] of targets.entries()) {
    if (typeof entry !== 'object' || entry === null || !('value' in entry)) {
      return { ok: false, error: `targets[${i}] must be { value, weight?, label? }` };
    }
    const { value, weight, label } = entry as Record<string, unknown>;
    const target = checkTarget(kind, value);
    if (!target.ok) return { ok: false, error: `targets[${i}]: ${target.error}` };
    const item: WeightedTarget = { value: target.value };
    if (strategy === 'weighted') {
      if (!Number.isSafeInteger(weight) || (weight as number) < 0 || (weight as number) > MAX_WEIGHT) {
        return { ok: false, error: `targets[${i}].weight must be an integer from 0 to ${MAX_WEIGHT}` };
      }
      item.weight = weight as number;
    }
    if (label !== undefined) {
      if (typeof label !== 'string' || label.length > 64) return { ok: false, error: `targets[${i}].label must be a short string` };
      item.label = label;
    }
    out.push(item);
  }
  if (strategy === 'weighted' && !out.some((t) => (t.weight ?? 0) > 0)) {
    return { ok: false, error: 'a weighted binding needs at least one target with a weight above 0' };
  }
  return { ok: true, value: { strategy: strategy as Strategy, targets: out } };
}

/** FNV-1a over UTF-8: small, fast, identical in every runtime. Used for bucketing, not security. */
export function bucketHash(text: string): number {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(text)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

export interface Selection<T = Target> {
  /** The target to use. */
  value: T;
  /** Its index in the binding's targets. */
  index: number;
  label?: string;
  /** Every target in the order to try them: the selection first, then the rest (failover order). */
  order: WeightedTarget<T>[];
}

/**
 * Picks a target.
 *
 * - `single`: the only target.
 * - `weighted`: with a `key` (user id, tenant id, session id...), the same key always lands on the same
 *   target while the weights are unchanged; without one, the choice is random per call.
 * - `failover`: the first target; `order` is the list to fall back through.
 */
export function select<T>(binding: Binding<T>, options: { ref: string; key?: string; random?: () => number } = { ref: '' }): Selection<T> {
  const targets = binding.targets;
  if (binding.strategy !== 'weighted') {
    const first = targets[0]!;
    return { value: first.value, index: 0, ...(first.label ? { label: first.label } : {}), order: [...targets] };
  }
  const total = targets.reduce((sum, t) => sum + (t.weight ?? 0), 0);
  const point =
    options.key !== undefined
      ? bucketHash(`${options.ref}\u0000${options.key}`) % total
      : Math.floor((options.random ?? Math.random)() * total);
  let cursor = 0;
  let index = 0;
  for (const [i, t] of targets.entries()) {
    cursor += t.weight ?? 0;
    if (point < cursor) {
      index = i;
      break;
    }
  }
  const chosen = targets[index]!;
  const rest = targets
    .map((t, i) => ({ t, i }))
    .filter(({ i, t }) => i !== index && (t.weight ?? 0) > 0)
    .sort((a, b) => (b.t.weight ?? 0) - (a.t.weight ?? 0) || a.i - b.i)
    .map(({ t }) => t);
  return { value: chosen.value, index, ...(chosen.label ? { label: chosen.label } : {}), order: [chosen, ...rest] };
}
