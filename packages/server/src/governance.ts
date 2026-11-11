/**
 * Mutation governance: which policy covers a reference, and whether a change authorization admits a write.
 *
 * A change authorization is a compact JWS signed with Ed25519 by an issuer whose public keys the host operator
 * registered (`resolver_signing_keys`). Verification is local: no network call, no service to be up. Every claim
 * the resolver compares is signed: tenant, reference, operation, expected revision and the digest of the exact
 * request (`canonicalChange` in @appport/resolver-core). Consumption (single use) is not decided here: the
 * resolver writes the consumed-authorization row in the same transaction as the revision (`store.commit`).
 *
 * Key states: `active` verifies; `retired` (rotation) verifies tokens issued before it was retired; `revoked`
 * (compromise) verifies nothing, including tokens issued before.
 */

import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import {
  AUTHORIZATION_TYPE,
  AUTHORIZATION_VERSION,
  canonicalChange,
  GOVERNED_OPERATIONS,
  matches,
  REASONS,
  type ChangeAuthorizationClaims,
  type GovernedOperation,
  type GovernedRequest,
  type MutationPolicy,
  type SigningKey,
} from '@appport/resolver-core';

/** Clock skew tolerated on `nbf`, `exp` and `iat`. */
export const CLOCK_SKEW_SECONDS = 30;
/** Without a policy (an authorization presented voluntarily), the longest validity accepted. */
export const DEFAULT_MAX_VALIDITY_SECONDS = 3600;
const MAX_TOKEN_LENGTH = 8192;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;

export class GovernanceError extends Error {
  constructor(
    readonly reason: (typeof REASONS)['authorizationRequired' | 'authorizationInvalid' | 'authorizationConsumed' | 'breakGlassRefused'],
    message: string,
  ) {
    super(message);
  }
}

/** `sha256:<hex>` of the canonical request. Never includes secret material (canonicalChange does not take it). */
export function changeDigest(op: GovernedOperation, request: GovernedRequest): string {
  return `sha256:${createHash('sha256').update(canonicalChange(op, request)).digest('hex')}`;
}

/** Specificity of a matching pattern: exact beats any prefix, a longer prefix beats a shorter one, `*` is last. */
function specificity(pattern: string): number {
  if (pattern === '*' || pattern === 'ref://*') return 0;
  if (pattern.endsWith('/*')) return pattern.length;
  return Number.MAX_SAFE_INTEGER;
}

/**
 * The one policy that governs `ref` for `op`, if any: among the policies whose pattern matches and that list the
 * operation, the most specific. A narrower policy therefore never un-governs an operation a broader one governs;
 * it can only change who is trusted (its issuers) and for how long (its validity) for the operations it lists.
 */
export function policyFor(policies: readonly MutationPolicy[], ref: string, op: GovernedOperation): MutationPolicy | null {
  let best: MutationPolicy | null = null;
  for (const policy of policies) {
    if (!policy.operations.includes(op) || !matches(ref, policy.pattern)) continue;
    if (!best || specificity(policy.pattern) > specificity(best.pattern) || (specificity(policy.pattern) === specificity(best.pattern) && policy.id < best.id)) best = policy;
  }
  return best;
}

/** Raw Ed25519 public key (32 bytes, base64url) as a KeyObject. */
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
export function ed25519PublicKey(raw: string): KeyObject {
  const bytes = Buffer.from(raw, 'base64url');
  if (bytes.length !== 32) throw new TypeError('an Ed25519 public key is 32 bytes (base64url)');
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519, bytes]), format: 'der', type: 'spki' });
}

function decodeJson(part: string, what: string): Record<string, unknown> {
  try {
    const value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch {
    throw new GovernanceError(REASONS.authorizationInvalid, `the authorization's ${what} is not valid JSON`);
  }
}

export interface Expected {
  tenantId: string;
  ref: string;
  op: GovernedOperation;
  expectedRevision: number;
  digest: string;
  /** The policy governing the write, or null when the authorization was presented voluntarily. */
  policy: MutationPolicy | null;
  now: Date;
}

export interface Verified {
  claims: ChangeAuthorizationClaims;
  kid: string;
}

/**
 * Verifies a change authorization against the request it must admit. Every failure is
 * `resolver.authorization-invalid` with a reason that names the mismatch, never the token's contents.
 */
export function verifyAuthorization(token: unknown, expected: Expected, keyFor: (kid: string) => SigningKey | null): Verified {
  const invalid = (message: string) => new GovernanceError(REASONS.authorizationInvalid, message);
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) throw invalid('the authorization is not a compact JWS');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw invalid('the authorization is not a compact JWS');
  const [h, p, s] = parts as [string, string, string];
  const header = decodeJson(h, 'header');
  if (header['alg'] !== 'EdDSA' || header['typ'] !== AUTHORIZATION_TYPE) throw invalid(`the authorization must be alg EdDSA, typ ${AUTHORIZATION_TYPE}`);
  const kid = header['kid'];
  if (typeof kid !== 'string' || !ID.test(kid)) throw invalid('the authorization names no valid key id');

  const key = keyFor(kid);
  if (!key) throw invalid(`signing key ${kid} is not registered in this tenant`);
  if (key.state === 'revoked') throw invalid(`signing key ${kid} is revoked`);
  const signature = Buffer.from(s, 'base64url');
  let ok = false;
  try {
    ok = signature.length === 64 && verify(null, Buffer.from(`${h}.${p}`), ed25519PublicKey(key.publicKey), signature);
  } catch {
    ok = false;
  }
  if (!ok) throw invalid(`the signature does not verify with key ${kid}`);

  // Only now, with a verified signature, are the claims trusted enough to compare.
  const c = decodeJson(p, 'payload') as unknown as ChangeAuthorizationClaims;
  if (c.v !== AUTHORIZATION_VERSION) throw invalid(`unsupported authorization version ${String(c.v)}`);
  if (typeof c.iss !== 'string' || c.iss !== key.issuer) throw invalid(`key ${kid} belongs to issuer ${key.issuer}, not ${String(c.iss)}`);
  if (typeof c.jti !== 'string' || !ID.test(c.jti)) throw invalid('the authorization has no valid jti');
  if (c.tenant !== expected.tenantId) throw invalid('the authorization is for another tenant');
  if (c.ref !== expected.ref) throw invalid('the authorization is for another reference');
  if (!(GOVERNED_OPERATIONS as readonly string[]).includes(c.op) || c.op !== expected.op) throw invalid(`the authorization is for ${String(c.op)}, not ${expected.op}`);
  if (c.expectedRevision !== expected.expectedRevision) throw invalid(`the authorization is for revision ${String(c.expectedRevision)}, not ${expected.expectedRevision}`);
  if (c.digest !== expected.digest) throw invalid('the authorization was issued for a different change (digest mismatch)');

  const now = Math.floor(expected.now.getTime() / 1000);
  for (const field of ['iat', 'nbf', 'exp'] as const) {
    if (!Number.isSafeInteger(c[field])) throw invalid(`the authorization has no valid ${field}`);
  }
  if (c.nbf - CLOCK_SKEW_SECONDS > now) throw invalid('the authorization is not valid yet');
  if (c.exp + CLOCK_SKEW_SECONDS < now) throw invalid('the authorization has expired');
  if (c.iat - CLOCK_SKEW_SECONDS > now) throw invalid('the authorization was issued in the future');
  const maxValidity = expected.policy?.maxValiditySeconds ?? DEFAULT_MAX_VALIDITY_SECONDS;
  if (c.exp <= c.nbf || c.exp - c.nbf > maxValidity) throw invalid(`the authorization's validity exceeds ${maxValidity} s`);
  if (key.state === 'retired') {
    const retired = Math.floor(Date.parse(key.retiredAt ?? '') / 1000);
    if (!Number.isFinite(retired) || c.iat >= retired) throw invalid(`signing key ${kid} was retired before this authorization was issued`);
  }
  if (expected.policy && !expected.policy.issuers.includes(c.iss)) throw invalid(`the policy for ${expected.ref} does not trust issuer ${c.iss}`);
  return { claims: c, kid };
}

/** The consumed-authorization row's id: one per (tenant, issuer, jti), whichever key signed it. */
export function authorizationId(tenantId: string, issuer: string, jti: string): string {
  return createHash('sha256').update(`${tenantId}\u0000${issuer}\u0000${jti}`).digest('hex').slice(0, 40);
}
