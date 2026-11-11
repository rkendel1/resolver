// Enforced mutation authority: mutation policies, Ed25519 change authorizations consumed in the revision's own
// transaction, and explicit operator break-glass. Adversarial: every way an authorization could be stretched to admit
// a write it was not issued for is tried, through the real resolver over AppPort, and must be refused.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, COLLECTIONS, type ResolverRuntime } from '@appport/resolver';
import { ResolverClient, ResolverClientError } from '@appport/resolver-client';
import { generateSigningKey, signChangeAuthorization, type SignChangeAuthorization } from '@appport/resolver-client/authorization';
import { AUTHORIZATION_TYPE, REASONS, type GovernedOperation, type GovernedRequest } from '@appport/resolver-core';
import { startResolver, TENANT, waitFor, type Harness } from './harness.js';

const ISSUER = 'resolver-control';
const MODEL_A = { provider: 'openai', model: 'gpt-4o' };
const MODEL_B = { provider: 'anthropic', model: 'claude-sonnet-5-5' };

async function refusal(work: Promise<unknown>): Promise<{ code: string; reason: string | undefined }> {
  try {
    await work;
  } catch (error) {
    const e = error as ResolverClientError & { reason?: string; code: string };
    return { code: e.code, reason: e.reason };
  }
  throw new Error('expected a refusal, but the write succeeded');
}

interface Gov {
  h: Harness;
  privateKeyPem: string;
  /** Signs for this tenant and issuer with key rc-1 unless overridden. */
  token(op: GovernedOperation, ref: string, expectedRevision: number, request: GovernedRequest, extra?: Partial<SignChangeAuthorization>): string;
  writer: ResolverClient;
}

async function governed(): Promise<Gov> {
  const h = await startResolver();
  const op = h.runtime.operator(TENANT);
  // Before any policy: references that exist in prod and staging.
  await h.admin.set('ref://prod/chat/model', { kind: 'value', binding: { value: MODEL_A } });
  await h.admin.set('ref://staging/chat/model', { kind: 'value', binding: { value: MODEL_A } });
  const { publicKey, privateKeyPem } = generateSigningKey();
  await h.runtime.resolver.addSigningKey(op, { kid: 'rc-1', issuer: ISSUER, publicKey, reason: 'Resolver Control approvals' });
  await h.runtime.resolver.setPolicy(op, { id: 'prod', pattern: 'ref://prod/*', operations: ['put', 'put-secret', 'rollback', 'revoke'], issuers: [ISSUER], maxValiditySeconds: 900, reason: 'production changes need an approved change' });
  // A key that could write anything: grants alone are no longer enough on prod.
  const { client: writer } = await h.clientWith([[['read', 'write', 'reveal'], '*']], { live: false });
  return {
    h,
    privateKeyPem,
    writer,
    token: (op, ref, expectedRevision, request, extra = {}) =>
      signChangeAuthorization({ privateKey: privateKeyPem, kid: 'rc-1', issuer: ISSUER, tenant: TENANT, ref, op, expectedRevision, request, decision: 'CHG-1', approvers: ['linus'], ...extra }),
  };
}

describe('mutation policies', () => {
  let g: Gov;
  beforeEach(async () => {
    g = await governed();
  });
  afterEach(async () => g.h.close());

  it('leaves ungoverned references exactly as before: no authorization needed, none recorded', async () => {
    const write = await g.writer.put({ ref: 'ref://staging/chat/model', binding: { value: MODEL_B }, expectedRevision: 1 });
    expect(write.revision).toBe(2);
    const history = (await g.writer.history('ref://staging/chat/model')).entries;
    expect(history.every((e) => e.governance === undefined)).toBe(true);
  });

  it('refuses every governed operation without an authorization, whatever the grants', async () => {
    const r1 = await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1 }));
    expect(r1).toEqual({ code: 'FORBIDDEN', reason: REASONS.authorizationRequired });
    expect((await refusal(g.writer.rollback('ref://prod/chat/model', 1, 1))).reason).toBe(REASONS.authorizationRequired);
    expect((await refusal(g.writer.revoke('ref://prod/chat/model', 1))).reason).toBe(REASONS.authorizationRequired);
    expect((await refusal(g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: 'sk-material-0001', expectedRevision: 0 }))).reason).toBe(REASONS.authorizationRequired);
    // Creating under a governed prefix is governed too.
    expect((await refusal(g.writer.put({ ref: 'ref://prod/new/thing', kind: 'value', binding: { value: 1 }, expectedRevision: 0 }))).reason).toBe(REASONS.authorizationRequired);
    // Even the admin key: admin governs grants and keys, not references.
    expect((await refusal(g.h.admin.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1 }))).reason).toBe(REASONS.authorizationRequired);
    expect((await g.writer.resolve('ref://prod/chat/model')).revision).toBe(1);
  });

  it('admits the write an authorization was issued for, records it on the revision, and tells watchers', async () => {
    const { client: watcher } = await g.h.clientWith([[['read'], 'ref://prod/*']]);
    const events: Array<{ revision: number; governance?: string }> = [];
    watcher.watch('ref://prod/chat/model', (e) => events.push(e));
    await new Promise((r) => setTimeout(r, 200));
    const token = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_B } });
    const write = await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: token, reason: 'CHG-1' });
    expect(write.revision).toBe(2);
    const entry = (await g.writer.history('ref://prod/chat/model')).entries.at(-1)!;
    expect(entry.governance).toMatchObject({ mode: 'authorized', issuer: ISSUER, kid: 'rc-1', decision: 'CHG-1', approvers: ['linus'] });
    expect(JSON.stringify(entry)).not.toContain(token.split('.')[2]); // the signature is not stored
    expect(await waitFor(() => events.find((e) => e.revision === 2))).toMatchObject({ governance: 'authorized' });
  });

  it('a consumed authorization admits nothing more, even re-signed by the issuer for the next revision with the same jti', async () => {
    const jti = 'chg-1-attempt-1';
    const first = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_B } }, { jti });
    await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: first });
    // Replaying the same token: the revision it was bound to is gone, so it is stale before anything else.
    expect(await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: first }))).toEqual({ code: 'CONFLICT', reason: REASONS.stale });
    // A token that matches revision 2 perfectly but reuses the jti: consumption refuses it, atomically.
    const reused = g.token('put', 'ref://prod/chat/model', 2, { kind: 'value', binding: { value: MODEL_A } }, { jti });
    expect(await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_A }, expectedRevision: 2, authorization: reused }))).toEqual({ code: 'FORBIDDEN', reason: REASONS.authorizationConsumed });
    expect((await g.writer.resolve('ref://prod/chat/model')).revision).toBe(2);
  });

  it('binds the reference, tenant, operation, revision and exact change', async () => {
    const forB = { kind: 'value' as const, binding: { value: MODEL_B } };
    const put = (authorization: string, input: Partial<Parameters<ResolverClient['put']>[0]> = {}) =>
      refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization, ...input }));
    // another reference
    await g.writer.put({ ref: 'ref://staging/chat/model', binding: { value: MODEL_B }, expectedRevision: 1 });
    expect((await put(g.token('put', 'ref://prod/other', 1, forB))).reason).toBe(REASONS.authorizationInvalid);
    // another tenant
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, forB, { tenant: 'globex' }))).reason).toBe(REASONS.authorizationInvalid);
    // another operation (a rollback token presented on a put, a put token on a revoke)
    expect((await put(g.token('rollback', 'ref://prod/chat/model', 1, { toRevision: 1 }))).reason).toBe(REASONS.authorizationInvalid);
    expect((await refusal(g.writer.revoke('ref://prod/chat/model', 1, undefined, { authorization: g.token('put', 'ref://prod/chat/model', 1, forB) }))).reason).toBe(REASONS.authorizationInvalid);
    // another revision: the token says 0, the write says 1
    expect((await put(g.token('put', 'ref://prod/chat/model', 0, forB))).reason).toBe(REASONS.authorizationInvalid);
    // another binding, another ttl: the digest covers both
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_A } }))).reason).toBe(REASONS.authorizationInvalid);
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, forB), { ttlSeconds: 5 })).reason).toBe(REASONS.authorizationInvalid);
    // the same binding written differently (key order, single vs explicit strategy) is the same change
    const ok = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { strategy: 'single', targets: [{ value: { model: 'claude-sonnet-5-5', provider: 'anthropic' } }] } });
    expect((await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: ok })).revision).toBe(2);
  });

  it('a stale revision is refused as stale, even with a valid authorization for the old revision', async () => {
    const t1 = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_B } });
    const t2 = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_A } });
    await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: t1 });
    expect(await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_A }, expectedRevision: 1, authorization: t2 }))).toEqual({ code: 'CONFLICT', reason: REASONS.stale });
  });

  it('refuses expired, not-yet-valid, over-long and future-issued authorizations', async () => {
    const req = { kind: 'value' as const, binding: { value: MODEL_B } };
    const put = (authorization: string) => refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization }));
    const hourAgo = new Date(Date.now() - 3600_000);
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, req, { now: hourAgo, validitySeconds: 600 }))).reason).toBe(REASONS.authorizationInvalid);
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, req, { now: new Date(Date.now() + 3600_000) }))).reason).toBe(REASONS.authorizationInvalid);
    // the policy allows 900 s
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, req, { validitySeconds: 7200 }))).reason).toBe(REASONS.authorizationInvalid);
  });

  it('refuses forged, tampered, unsigned, wrongly-typed and untrusted authorizations', async () => {
    const req = { kind: 'value' as const, binding: { value: MODEL_B } };
    const put = (authorization: string) => refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization }));
    const good = g.token('put', 'ref://prod/chat/model', 1, req);
    const [h, p, s] = good.split('.') as [string, string, string];
    // tampered payload (revision changed), original signature
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...claims, ref: 'ref://prod/payments' })).toString('base64url')}.${s}`;
    expect((await put(tampered)).reason).toBe(REASONS.authorizationInvalid);
    // alg none, and garbage
    const none = `${Buffer.from(JSON.stringify({ alg: 'none', typ: AUTHORIZATION_TYPE, kid: 'rc-1' })).toString('base64url')}.${p}.`;
    expect((await put(none)).reason).toBe(REASONS.authorizationInvalid);
    expect((await put('not-a-token')).reason).toBe(REASONS.authorizationInvalid);
    // signed by a key nobody registered, claiming a registered kid
    const stranger = generateKeyPairSync('ed25519').privateKey;
    expect((await put(signChangeAuthorization({ privateKey: stranger, kid: 'rc-1', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 1, request: req }))).reason).toBe(REASONS.authorizationInvalid);
    // an unregistered kid
    expect((await put(g.token('put', 'ref://prod/chat/model', 1, req, { kid: 'rc-404' }))).reason).toBe(REASONS.authorizationInvalid);
    // a registered key whose issuer the policy does not trust
    const other = generateSigningKey();
    await g.h.runtime.resolver.addSigningKey(g.h.runtime.operator(TENANT), { kid: 'other-1', issuer: 'someone-else', publicKey: other.publicKey, reason: 'another service' });
    expect((await put(signChangeAuthorization({ privateKey: other.privateKeyPem, kid: 'other-1', issuer: 'someone-else', tenant: TENANT, ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 1, request: req }))).reason).toBe(REASONS.authorizationInvalid);
    // a token claiming to be from the trusted issuer, signed with the other issuer's key
    expect((await put(signChangeAuthorization({ privateKey: other.privateKeyPem, kid: 'other-1', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 1, request: req }))).reason).toBe(REASONS.authorizationInvalid);
    expect((await g.writer.resolve('ref://prod/chat/model')).revision).toBe(1);
  });

  it('rotation: a retired key verifies only what it signed before; revocation: a revoked key verifies nothing', async () => {
    const op = g.h.runtime.operator(TENANT);
    const req = { kind: 'value' as const, binding: { value: MODEL_B } };
    const before = g.token('put', 'ref://prod/chat/model', 1, req, { now: new Date(Date.now() - 5000) });
    const next = generateSigningKey();
    await g.h.runtime.resolver.addSigningKey(op, { kid: 'rc-2', issuer: ISSUER, publicKey: next.publicKey, reason: 'rotation' });
    await g.h.runtime.resolver.retireSigningKey(op, { kid: 'rc-1', reason: 'rotation' });
    const after = g.token('put', 'ref://prod/chat/model', 1, req, { now: new Date(Date.now() + 2000) });
    expect((await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: after }))).reason).toBe(REASONS.authorizationInvalid);
    // issued before retirement: still honoured (approvals in flight survive a rotation)
    expect((await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: before })).revision).toBe(2);
    // the new key signs
    const withNew = signChangeAuthorization({ privateKey: next.privateKeyPem, kid: 'rc-2', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 2, request: { kind: 'value', binding: { value: MODEL_A } } });
    const unused = signChangeAuthorization({ privateKey: next.privateKeyPem, kid: 'rc-2', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/chat/model', op: 'put', expectedRevision: 3, request: { kind: 'value', binding: { value: MODEL_B } } });
    expect((await g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_A }, expectedRevision: 2, authorization: withNew })).revision).toBe(3);
    // compromise: revoke rc-2; its outstanding authorization is dead at once
    await g.h.runtime.resolver.revokeSigningKey(op, { kid: 'rc-2', reason: 'key leaked' });
    expect((await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 3, authorization: unused }))).reason).toBe(REASONS.authorizationInvalid);
    const trail = (await g.h.admin.governanceEvents()).events.map((e) => e.type);
    expect(trail).toEqual(expect.arrayContaining(['signing-key.added', 'signing-key.retired', 'signing-key.revoked', 'policy.set']));
  });

  it('secrets: authorized without the material; the material is in no token, row, event or history; a refused write stores nothing', async () => {
    const material = `sk-live-${randomBytes(16).toString('hex')}`;
    // refused: nothing reaches custody
    await refusal(g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: material, expectedRevision: 0 }));
    const token = g.token('put-secret', 'ref://prod/llm/key', 0, { kind: 'secret' });
    expect(token).not.toContain(material);
    // a put token cannot authorize a secret write, and a secret token is not a put token
    expect((await refusal(g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: material, expectedRevision: 0, authorization: g.token('put', 'ref://prod/llm/key', 0, { kind: 'value', binding: { value: 1 } }) }))).reason).toBe(REASONS.authorizationInvalid);
    expect((await g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: material, expectedRevision: 0, authorization: token })).revision).toBe(1);
    expect(await g.writer.secret('ref://prod/llm/key')).toBe(material);
    // a consumed token for a secret: the stored version of the losing write is discarded (no orphan)
    const again = g.token('put-secret', 'ref://prod/llm/key', 1, { kind: 'secret' }, { jti: 'secret-jti' });
    await g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: `${material}-2`, expectedRevision: 1, authorization: again });
    const reuse = g.token('put-secret', 'ref://prod/llm/key', 2, { kind: 'secret' }, { jti: 'secret-jti' });
    expect((await refusal(g.writer.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: `${material}-3`, expectedRevision: 2, authorization: reuse }))).reason).toBe(REASONS.authorizationConsumed);
    // Everything governance returns: no material anywhere.
    const dump = JSON.stringify([await g.h.admin.history('ref://prod/llm/key'), await g.h.admin.governanceEvents()]);
    expect(dump).not.toContain(material);
    const integrity = await g.h.runtime.integrity();
    expect(integrity.problems).toEqual([]);
    expect(integrity.warnings.filter((w) => /orphan|unreferenced/i.test(JSON.stringify(w)))).toEqual([]);
  });

  it('the operator: refused like anyone without break-glass; break-glass needs a reason, is the operator\'s alone, and is recorded loudly', async () => {
    const op = g.h.runtime.operator(TENANT);
    const r = g.h.runtime.resolver;
    const { client: watcher } = await g.h.clientWith([[['read'], 'ref://prod/*']]);
    const events: Array<{ revision: number; governance?: string }> = [];
    watcher.watch('ref://prod/chat/model', (e) => events.push(e));
    await new Promise((res) => setTimeout(res, 200));
    await expect(r.put(op, { ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1 })).rejects.toMatchObject({ reason: REASONS.authorizationRequired });
    await expect(r.put(op, { ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, breakGlass: { reason: '  ' } })).rejects.toMatchObject({ reason: REASONS.breakGlassRefused });
    // break-glass where nothing governs is refused, so the trail never fills with meaningless entries
    await expect(r.put(op, { ref: 'ref://staging/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, breakGlass: { reason: 'x' } })).rejects.toMatchObject({ reason: REASONS.breakGlassRefused });
    // an API key cannot break glass, over AppPort
    expect((await refusal(g.writer.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, breakGlass: { reason: 'incident 4411' } }))).reason).toBe(REASONS.breakGlassRefused);
    const write = await r.put(op, { ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, breakGlass: { reason: 'incident 4411: provider outage, Resolver Control down' } });
    expect(write.revision).toBe(2);
    const entry = (await g.writer.history('ref://prod/chat/model')).entries.at(-1)!;
    expect(entry.governance).toEqual({ mode: 'break-glass', actor: 'resolver-operator:operator', reason: 'incident 4411: provider outage, Resolver Control down' });
    const trail = (await g.h.admin.governanceEvents()).events.find((e) => e.type === 'break-glass')!;
    expect(trail).toMatchObject({ ref: 'ref://prod/chat/model', revision: 2, operation: 'put', policyId: 'prod', actor: 'resolver-operator:operator' });
    expect(await waitFor(() => events.find((e) => e.revision === 2))).toMatchObject({ governance: 'break-glass' });
    // the operator can still act with a proper authorization, like anyone
    const token = g.token('rollback', 'ref://prod/chat/model', 2, { toRevision: 1 });
    expect((await r.rollback(op, { ref: 'ref://prod/chat/model', toRevision: 1, expectedRevision: 2, authorization: token })).revision).toBe(3);
  });

  it('policies and signing keys are the host operator\'s: an admin key can read them, never change them', async () => {
    const { principal } = await g.h.clientWith([[['admin'], '*']]);
    const asAdmin = { principalId: principal, principalType: 'api_key', tenantId: TENANT, verifiedBy: 'appport-services' } as never;
    await expect(g.h.runtime.resolver.removePolicy(asAdmin, { id: 'prod', reason: 'nope' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(g.h.runtime.resolver.addSigningKey(asAdmin, { kid: 'mine', issuer: ISSUER, publicKey: generateSigningKey().publicKey, reason: 'nope' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(g.h.runtime.resolver.setPolicy(g.h.runtime.operator(TENANT), { pattern: 'ref://prod/*', operations: ['put'], issuers: [ISSUER], reason: '' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((await g.h.admin.policies()).policies.map((p) => p.id)).toEqual(['prod']);
    expect((await g.h.admin.signingKeys()).keys.map((k) => [k.kid, k.state])).toEqual([['rc-1', 'active']]);
    // a narrower policy for one reference never un-governs an operation the broader one governs
    await g.h.runtime.resolver.setPolicy(g.h.runtime.operator(TENANT), { id: 'model-only', pattern: 'ref://prod/chat/model', operations: ['put'], issuers: [ISSUER], reason: 'narrow' });
    expect((await refusal(g.writer.revoke('ref://prod/chat/model', 1))).reason).toBe(REASONS.authorizationRequired);
  });
});

describe('concurrency and failure', () => {
  it('one authorization presented concurrently by many writers commits exactly once', async () => {
    const g = await governed();
    try {
      const token = g.token('put', 'ref://prod/chat/model', 1, { kind: 'value', binding: { value: MODEL_B } });
      const writers = await Promise.all([0, 1, 2, 3].map(() => g.h.clientWith([[['read', 'write'], '*']], { live: false })));
      const results = await Promise.allSettled(writers.map(({ client }) => client.put({ ref: 'ref://prod/chat/model', binding: { value: MODEL_B }, expectedRevision: 1, authorization: token })));
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      expect((await g.writer.history('ref://prod/chat/model')).entries.map((e) => e.revision)).toEqual([1, 2]);
    } finally {
      await g.h.close();
    }
  });

  it('two resolver instances over one state: the same authorization on both commits once', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-gov-pair-'));
    const db = createFeltDB({ namespace: `resolver-gov-${randomBytes(4).toString('hex')}`, memory: true });
    const options = { state: { db }, environment: 'development' as const, vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex'), multiInstance: false };
    const a = await createResolverRuntime(options);
    const b = await createResolverRuntime(options);
    try {
      const op = a.operator(TENANT);
      await a.resolver.put(op, { ref: 'ref://prod/x', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      const { publicKey, privateKeyPem } = generateSigningKey();
      await a.resolver.addSigningKey(op, { kid: 'k', issuer: ISSUER, publicKey, reason: 'r' });
      await a.resolver.setPolicy(op, { pattern: 'ref://prod/*', operations: ['put'], issuers: [ISSUER], reason: 'r' });
      const token = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'k', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/x', op: 'put', expectedRevision: 1, request: { kind: 'value', binding: { value: 2 } } });
      const results = await Promise.allSettled([a, b].map((rt) => rt.resolver.put(rt.operator(TENANT), { ref: 'ref://prod/x', binding: { value: 2 }, expectedRevision: 1, authorization: token })));
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      const consumed = await db.collection(COLLECTIONS.authorizations).find({});
      expect(consumed).toHaveLength(1);
      expect(consumed[0]).toMatchObject({ revision: 2, issuer: ISSUER });
    } finally {
      await a.close();
      await b.close();
      await db.close?.();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a commit that fails leaves the authorization unconsumed: the same authorization succeeds on retry', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-gov-fail-'));
    const real = createFeltDB({ namespace: `resolver-gov-${randomBytes(4).toString('hex')}`, memory: true });
    let failNext = false;
    const db = new Proxy(real, {
      get(target, prop, receiver) {
        if (prop === 'transaction') {
          return async (request: { operations: Array<{ collection: string }> }) => {
            if (failNext && request.operations.some((o) => o.collection === COLLECTIONS.authorizations)) {
              failNext = false;
              throw new Error('state store unavailable');
            }
            return target.transaction(request as never);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const rt: ResolverRuntime = await createResolverRuntime({ state: { db }, environment: 'development', vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') });
    try {
      const op = rt.operator(TENANT);
      await rt.resolver.put(op, { ref: 'ref://prod/x', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      const { publicKey, privateKeyPem } = generateSigningKey();
      await rt.resolver.addSigningKey(op, { kid: 'k', issuer: ISSUER, publicKey, reason: 'r' });
      await rt.resolver.setPolicy(op, { pattern: 'ref://prod/*', operations: ['put'], issuers: [ISSUER], reason: 'r' });
      const token = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'k', issuer: ISSUER, tenant: TENANT, ref: 'ref://prod/x', op: 'put', expectedRevision: 1, request: { kind: 'value', binding: { value: 2 } } });
      failNext = true;
      await expect(rt.resolver.put(op, { ref: 'ref://prod/x', binding: { value: 2 }, expectedRevision: 1, authorization: token })).rejects.toThrow(/unavailable/);
      expect(await real.collection(COLLECTIONS.authorizations).find({})).toHaveLength(0);
      expect((await rt.resolver.put(op, { ref: 'ref://prod/x', binding: { value: 2 }, expectedRevision: 1, authorization: token })).revision).toBe(2);
    } finally {
      await rt.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
