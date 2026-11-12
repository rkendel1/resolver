/**
 * Governance shared by the resolver and the services that authorize changes to it: what a change
 * authorization claims, and the exact request it is bound to.
 *
 * A change authorization is a compact JWS (`header.payload.signature`, base64url, Ed25519) that an issuer
 * (an approval service such as Resolver Control) signs once a change is approved. Under a mutation policy the
 * resolver verifies it locally and consumes it in the same transaction as the revision it admits.
 *
 * Pure: the canonical form and the claims are defined here, so issuers and the resolver cannot disagree about
 * what was approved. Hashing and signing use `node:crypto` (resolver server; `@appport/resolver-client/authorization`).
 */

import { checkBinding } from './binding.js';
import { isKind, type Json, type Kind } from './kinds.js';

/** The mutations a policy can govern. A secret write is `put-secret`: it is bound to everything but the material. */
export const GOVERNED_OPERATIONS = ['put', 'put-secret', 'rollback', 'revoke'] as const;
export type GovernedOperation = (typeof GOVERNED_OPERATIONS)[number];

export const AUTHORIZATION_TYPE = 'resolver-change+jws';
export const AUTHORIZATION_VERSION = 1;

/** The signed claims of a change authorization. Every field the resolver compares is signed. */
export interface ChangeAuthorizationClaims {
  v: typeof AUTHORIZATION_VERSION;
  /** The issuer, as registered with its signing keys. */
  iss: string;
  /** Unique per issuer: consumed once. */
  jti: string;
  tenant: string;
  ref: string;
  op: GovernedOperation;
  /** The revision the change is based on (0 to create). The write must find exactly this revision. */
  expectedRevision: number;
  /** `sha256:<hex>` of `canonicalChange(op, request)`. */
  digest: string;
  /** Seconds since the epoch. */
  iat: number;
  nbf: number;
  exp: number;
  /** The issuer's decision this implements (e.g. a change id), recorded as evidence. */
  decision?: string;
  /** Who approved it, as the issuer recorded (evidence, not checked by the resolver). */
  approvers?: string[];
}

/** The parts of a mutation request an authorization is bound to. Never secret material. */
export interface GovernedRequest {
  kind?: Kind | undefined;
  schema?: Json | undefined;
  binding?: unknown;
  ttlSeconds?: number | undefined;
  toRevision?: number | undefined;
}

/** JSON with object keys sorted and `undefined` members dropped: one string per value, in every runtime. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('canonicalJson: numbers must be finite');
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/**
 * The canonical text an authorization's digest covers, for one operation:
 * - `put`: kind, schema, the binding as the resolver normalizes it (`checkBinding`), ttlSeconds;
 * - `put-secret`: kind and ttlSeconds (never the material);
 * - `rollback`: the revision restored;
 * - `revoke`: nothing beyond the signed ref, op and expected revision.
 * Throws when the request is not one the resolver would accept, so an issuer cannot sign something unwritable.
 */
export function canonicalChange(op: GovernedOperation, request: GovernedRequest): string {
  switch (op) {
    case 'put': {
      const kind = request.kind;
      if (kind === undefined || !isKind(kind) || kind === 'secret') throw new TypeError('canonicalChange(put): kind must be a non-secret kind');
      const checked = checkBinding(kind, request.binding);
      if (!checked.ok) throw new TypeError(`canonicalChange(put): ${checked.error}`);
      return canonicalJson({ op, kind, schema: request.schema ?? null, binding: checked.value, ttlSeconds: request.ttlSeconds ?? null });
    }
    case 'put-secret':
      return canonicalJson({ op, kind: 'secret', ttlSeconds: request.ttlSeconds ?? null });
    case 'rollback':
      if (!Number.isSafeInteger(request.toRevision) || (request.toRevision as number) < 1) throw new TypeError('canonicalChange(rollback): toRevision must be a positive integer');
      return canonicalJson({ op, toRevision: request.toRevision });
    case 'revoke':
      return canonicalJson({ op });
  }
}

/** A mutation policy as the resolver reports it. Managed by the host operator only. */
export interface MutationPolicy {
  id: string;
  /** A grant pattern: `*`, an exact ref, or a prefix ending in `/*`. The most specific matching policy applies. */
  pattern: string;
  operations: GovernedOperation[];
  /** Issuers whose active signing keys are trusted for references this policy covers. */
  issuers: string[];
  /** The longest an authorization may live (exp - nbf), in seconds. */
  maxValiditySeconds: number;
  createdBy: string;
  createdAt: string;
  reason: string;
}

export type SigningKeyState = 'active' | 'retired' | 'revoked';

/** A registered issuer public key. `retired` verifies tokens issued before `retiredAt`; `revoked` verifies none. */
export interface SigningKey {
  kid: string;
  issuer: string;
  /** Ed25519 public key, base64url of the raw 32 bytes. */
  publicKey: string;
  state: SigningKeyState;
  createdAt: string;
  createdBy: string;
  retiredAt?: string;
  revokedAt?: string;
  reason?: string;
}

/** What a revision records about the authority that admitted it. Never secret material, never the token. */
export type RevisionGovernance =
  | { mode: 'authorized'; issuer: string; kid: string; jti: string; decision?: string; approvers?: string[] }
  | { mode: 'break-glass'; actor: string; reason: string };

/** An append-only governance event: a break-glass write, or a change to a policy or signing key. */
export interface GovernanceEvent {
  seq?: number;
  type: 'break-glass' | 'policy.set' | 'policy.removed' | 'signing-key.added' | 'signing-key.retired' | 'signing-key.revoked';
  actor: string;
  reason: string;
  at: string;
  ref?: string;
  revision?: number;
  operation?: GovernedOperation;
  policyId?: string;
  pattern?: string;
  kid?: string;
  issuer?: string;
}
