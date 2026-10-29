/**
 * The resolver's AppPort contract: capability names, inputs and outputs, shared by the host and its clients.
 * Every capability is served over AppPort (`/.well-known/appport`), so any AppPort client can call it.
 */

import type { Binding, WeightedTarget } from './binding.js';
import type { Json, Kind, Target } from './kinds.js';
import type { RefName } from './names.js';

export const CAPABILITIES = {
  resolve: 'resolver.resolve',
  put: 'resolver.put',
  history: 'resolver.history',
  rollback: 'resolver.rollback',
  revoke: 'resolver.revoke',
  list: 'resolver.list',
  watch: 'resolver.watch',
  grant: 'resolver.grant',
  ungrant: 'resolver.ungrant',
  grants: 'resolver.grants',
  createKey: 'resolver.keys.create',
  revokeKey: 'resolver.keys.revoke',
  listKeys: 'resolver.keys.list',
} as const;

/**
 * What a grant allows on references matching its pattern.
 * - `read`: resolve, list, history and watch. For secrets, metadata only.
 * - `reveal`: read secret material. Implies nothing else.
 * - `write`: put, rollback, revoke.
 * - `admin`: grants and API keys (pattern `*`).
 */
export const ACTIONS = ['read', 'reveal', 'write', 'admin'] as const;
export type Action = (typeof ACTIONS)[number];

export type ReferenceState = 'active' | 'revoked';

export interface ResolveInput {
  ref: string;
  /** Resolve the binding as it was at this revision (an immutable pin). */
  revision?: number;
  /** Steering key for weighted bindings (user id, tenant id...). Same key, same target. */
  key?: string;
  /** Secrets only: return the material. Needs the `reveal` action. */
  reveal?: boolean;
}

export interface ResolveResult {
  ref: RefName;
  kind: Kind;
  revision: number;
  /** The newest revision, so a pinned caller can see it is behind. */
  currentRevision: number;
  strategy: Binding['strategy'];
  targets: WeightedTarget[];
  /** The target chosen for this caller (and `key`). */
  selected: { value: Target; index: number; label?: string };
  /** How long a client may serve this without asking again, absent a change notification. */
  ttlSeconds: number;
  updatedAt: string;
  /** For a revealed secret: the material. Never stored, logged or included otherwise. */
  secret?: string;
}

export interface PutInput {
  ref: string;
  /** Required when creating; must match when updating (a reference's kind never changes). */
  kind?: Kind;
  /** `value` references only, at creation: a JSON Schema every binding must satisfy. */
  schema?: Json;
  /** The new binding: `{ value }` or `{ strategy, targets }`. Not for secrets. */
  binding?: unknown;
  /** Secrets only: the material. Sent to custody, never stored as a field. */
  secret?: string;
  /** The revision this change is based on: 0 to create, otherwise the current revision. */
  expectedRevision: number;
  reason?: string;
  /** Seconds a client may cache resolutions (default 30, 0 to 86400). */
  ttlSeconds?: number;
}

export interface WriteResult {
  ref: RefName;
  revision: number;
}

export interface RollbackInput {
  ref: string;
  toRevision: number;
  expectedRevision: number;
  reason?: string;
}

export interface RevokeInput {
  ref: string;
  expectedRevision: number;
  reason?: string;
}

export interface HistoryEntry {
  revision: number;
  action: 'create' | 'update' | 'rollback' | 'revoke';
  strategy?: Binding['strategy'];
  /** For secrets: the custody pointer and version, never the material. */
  targets?: WeightedTarget[];
  actor: string;
  reason?: string;
  at: string;
  /** For a rollback: the revision whose binding was restored. */
  restoredFrom?: number;
}

export interface ReferenceSummary {
  ref: RefName;
  kind: Kind;
  revision: number;
  state: ReferenceState;
  updatedAt: string;
}

export interface WatchInput {
  /** Exact references to watch. */
  refs?: string[];
  /** Or every reference under a prefix (`ref://prod/` or `ref://prod/payments/`). */
  prefix?: string;
}

/** A change notification. It names what changed; the client re-resolves with its own authority. */
export interface ChangeEvent {
  ref: RefName;
  kind: Kind;
  revision: number;
  state: ReferenceState;
  at: string;
}

export interface Grant {
  id: string;
  subject: string;
  actions: Action[];
  pattern: string;
  createdBy: string;
  createdAt: string;
}

/** `details.reason` on resolver errors (AppPort error codes carry the class, this the cause). */
export const REASONS = {
  notFound: 'resolver.not-found',
  revoked: 'resolver.revoked',
  stale: 'resolver.stale-revision',
  kindMismatch: 'resolver.kind-mismatch',
  invalidBinding: 'resolver.invalid-binding',
  incompatible: 'resolver.incompatible-target',
  forbidden: 'resolver.forbidden',
  custody: 'resolver.custody-unavailable',
} as const;
