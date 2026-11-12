/**
 * The resolver's AppPort contract: capability names, inputs and outputs, shared by the host and its clients.
 * Every capability is served over AppPort (`/.well-known/appport`), so any AppPort client can call it.
 */

import type { Binding, WeightedTarget } from './binding.js';
import type { Json, Kind, Target } from './kinds.js';
import type { RefName } from './names.js';
import type { GovernanceEvent, MutationPolicy, RevisionGovernance, SigningKey } from './governance.js';

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
  // Governance (read-only over AppPort: policies and signing keys are changed by the host operator only).
  policies: 'resolver.policies.list',
  signingKeys: 'resolver.signingkeys.list',
  governanceEvents: 'resolver.governance.events',
  // Consumers and adoption.
  register: 'resolver.consumers.register',
  updateRegistration: 'resolver.consumers.update',
  deregister: 'resolver.consumers.deregister',
  consumers: 'resolver.consumers.list',
  report: 'resolver.consumers.report',
  adoption: 'resolver.adoption',
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
  /** The caller's consumer registration (`resolver.consumers.register`): the resolution is recorded under it. */
  consumer?: string;
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
  /**
   * A change authorization (compact JWS, Ed25519) from an issuer the reference's mutation policy trusts. Required
   * when a policy governs this reference and operation; consumed by the write that it admits.
   */
  authorization?: string;
  /** Host operator only: write under a mutation policy without an authorization. Recorded as a governance event. */
  breakGlass?: { reason: string };
}

export interface WriteResult {
  ref: RefName;
  revision: number;
  /**
   * Revocation only: active references whose current binding still names the revoked one (a model's
   * credential), among those the caller may read. They keep resolving, and fail when the dependency is used.
   */
  dependents?: RefName[];
}

export interface RollbackInput {
  ref: string;
  toRevision: number;
  expectedRevision: number;
  reason?: string;
  /**
   * A change authorization (compact JWS, Ed25519) from an issuer the reference's mutation policy trusts. Required
   * when a policy governs this reference and operation; consumed by the write that it admits.
   */
  authorization?: string;
  /** Host operator only: write under a mutation policy without an authorization. Recorded as a governance event. */
  breakGlass?: { reason: string };
}

export interface RevokeInput {
  ref: string;
  expectedRevision: number;
  reason?: string;
  /**
   * A change authorization (compact JWS, Ed25519) from an issuer the reference's mutation policy trusts. Required
   * when a policy governs this reference and operation; consumed by the write that it admits.
   */
  authorization?: string;
  /** Host operator only: write under a mutation policy without an authorization. Recorded as a governance event. */
  breakGlass?: { reason: string };
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
  /** The authority that admitted this revision under a mutation policy (absent when none governed it). */
  governance?: RevisionGovernance;
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
  /** The caller's consumer registration: the open stream keeps it live. */
  consumer?: string;
}

/** A change notification. It names what changed; the client re-resolves with its own authority. */
export interface ChangeEvent {
  ref: RefName;
  kind: Kind;
  revision: number;
  state: ReferenceState;
  at: string;
  /** How a governed revision was admitted: by an authorization, or by operator break-glass. Absent otherwise. */
  governance?: 'authorized' | 'break-glass';
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
  /** A mutation policy governs this reference and operation; the write carried no authorization. */
  authorizationRequired: 'resolver.authorization-required',
  /** The authorization does not admit this write (signature, key, issuer, time, or a claim that does not match). */
  authorizationInvalid: 'resolver.authorization-invalid',
  /** The authorization was already used by an earlier write. */
  authorizationConsumed: 'resolver.authorization-consumed',
  /** Break-glass is the host operator's alone, and needs a reason. */
  breakGlassRefused: 'resolver.break-glass-refused',
} as const;

export type { GovernanceEvent, MutationPolicy, RevisionGovernance, SigningKey };
