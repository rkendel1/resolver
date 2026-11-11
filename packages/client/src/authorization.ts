/**
 * For issuers (approval services such as Resolver Control): sign a change authorization the resolver verifies
 * locally under a mutation policy. Node only (`node:crypto`); the main client entry stays free of it.
 *
 *   const token = signChangeAuthorization({
 *     privateKey, kid: 'rc-2026-11', issuer: 'resolver-control', tenant: 'acme',
 *     ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 7,
 *     request: { kind: 'model', binding: { value: { provider: 'anthropic', model: 'claude-sonnet-5-5' } } },
 *     decision: 'CHG-12', approvers: ['linus'], validitySeconds: 900,
 *   });
 *   await resolver.put({ ref, binding, expectedRevision: 7, authorization: token });
 *
 * The digest covers exactly what the resolver will compare (`canonicalChange`): sign the same request you send.
 * A secret write (`put-secret`) is bound to kind and ttl, never to the material: never pass material here.
 */
import { createHash, createPrivateKey, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { AUTHORIZATION_TYPE, AUTHORIZATION_VERSION, canonicalChange, type ChangeAuthorizationClaims, type GovernedOperation, type GovernedRequest } from '@appport/resolver-core';

export interface SignChangeAuthorization {
  /** The issuer's Ed25519 private key (KeyObject or PKCS#8 PEM). */
  privateKey: KeyObject | string;
  kid: string;
  issuer: string;
  tenant: string;
  ref: string;
  op: GovernedOperation;
  expectedRevision: number;
  request: GovernedRequest;
  /** Default 900; the policy's maxValiditySeconds caps it. */
  validitySeconds?: number;
  jti?: string;
  decision?: string;
  approvers?: string[];
  now?: Date;
}

export function changeDigest(op: GovernedOperation, request: GovernedRequest): string {
  return `sha256:${createHash('sha256').update(canonicalChange(op, request)).digest('hex')}`;
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

export function signChangeAuthorization(input: SignChangeAuthorization): string {
  const now = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const claims: ChangeAuthorizationClaims = {
    v: AUTHORIZATION_VERSION,
    iss: input.issuer,
    jti: input.jti ?? randomUUID(),
    tenant: input.tenant,
    ref: input.ref,
    op: input.op,
    expectedRevision: input.expectedRevision,
    digest: changeDigest(input.op, input.request),
    iat: now,
    nbf: now,
    exp: now + (input.validitySeconds ?? 900),
    ...(input.decision ? { decision: input.decision } : {}),
    ...(input.approvers?.length ? { approvers: input.approvers } : {}),
  };
  const signingInput = `${b64({ alg: 'EdDSA', typ: AUTHORIZATION_TYPE, kid: input.kid })}.${b64(claims)}`;
  const key = typeof input.privateKey === 'string' ? createPrivateKey(input.privateKey) : input.privateKey;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), key).toString('base64url')}`;
}

/** A new Ed25519 key pair: the public key as the resolver registers it (raw 32 bytes, base64url), the private key as PEM. */
export function generateSigningKey(): { publicKey: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey: Buffer.from(raw).toString('base64url'), privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() };
}
