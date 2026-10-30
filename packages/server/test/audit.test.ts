// Defects found in the production-readiness review, each reproduced against a real resolver.
// Every test here failed before its fix (docs/production-readiness-review.md, defect register).
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, createVault, type ResolverRuntime } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';
import { startResolver, TENANT, waitFor, type Harness } from './harness.js';

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task().catch(() => undefined);
});
const track = <T extends { close(): Promise<unknown> }>(thing: T): T => {
  cleanup.push(() => thing.close());
  return thing;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('client: revocation reaches pinned resolutions', () => {
  it('a pinned resolution fails once the reference is revoked (live client)', async () => {
    const h = track(await startResolver());
    await h.admin.put({ ref: 'ref://prod/cfg/pinned', kind: 'value', binding: { value: 'v1' }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']]);
    expect((await client.resolve('ref://prod/cfg/pinned', { revision: 1 })).selected.value).toBe('v1');
    await h.admin.revoke('ref://prod/cfg/pinned', 1, 'compromised');
    await waitFor(async () => (await client.resolve('ref://prod/cfg/pinned', { revision: 1 }).then(() => undefined, (e) => e)));
    await expect(client.resolve('ref://prod/cfg/pinned', { revision: 1 })).rejects.toMatchObject({ reason: 'resolver.revoked' });
  });

  it('a pinned resolution is revalidated after its TTL (no live connection)', async () => {
    const h = track(await startResolver());
    await h.admin.put({ ref: 'ref://prod/cfg/pinned2', kind: 'value', binding: { value: 'v1' }, expectedRevision: 0, ttlSeconds: 1 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false });
    await client.resolve('ref://prod/cfg/pinned2', { revision: 1 });
    await h.admin.revoke('ref://prod/cfg/pinned2', 1);
    await sleep(1100);
    await expect(client.resolve('ref://prod/cfg/pinned2', { revision: 1 })).rejects.toMatchObject({ reason: 'resolver.revoked' });
  });
});

/** Two resolver processes over one FeltDB state and one vault: the topology the README says is unsupported. */
async function twoInstances(): Promise<{ a: ResolverRuntime; b: ResolverRuntime; urlA: string; urlB: string; key: string }> {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-two-'));
  cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
  const db = createFeltDB({ namespace: 'resolver', memory: true });
  cleanup.push(async () => db.close());
  const shared = { state: { db }, vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
  const a = track(await createResolverRuntime(shared));
  const b = track(await createResolverRuntime(shared));
  const urlA = (await a.serve({ port: 0 })).url.replace(/\/$/, '');
  const urlB = (await b.serve({ port: 0 })).url.replace(/\/$/, '');
  const operator = a.operator(TENANT);
  const created = await a.resolver.createKey(operator, { name: 'app' });
  await a.resolver.grant(operator, { subject: created.principal, actions: ['read'], pattern: '*' });
  return { a, b, urlA, urlB, key: created.secret };
}

describe('client: a live connection never extends a result past its TTL', () => {
  it('a change made through another resolver instance is seen within the TTL', async () => {
    const { a, urlB, key } = await twoInstances();
    const operator = a.operator(TENANT);
    await a.resolver.put(operator, { ref: 'ref://prod/cfg/x', kind: 'value', binding: { value: 'old' }, expectedRevision: 0, ttlSeconds: 1 });
    const client = track(await ResolverClient.connect({ url: urlB, apiKey: key, live: true }));
    expect(await client.get('ref://prod/cfg/x')).toBe('old');
    await a.resolver.put(operator, { ref: 'ref://prod/cfg/x', binding: { value: 'new' }, expectedRevision: 1 });
    await sleep(1200);
    expect(await client.get('ref://prod/cfg/x')).toBe('new');
  });

  it('a revocation made through another instance stops resolution within the TTL', async () => {
    const { a, urlB, key } = await twoInstances();
    const operator = a.operator(TENANT);
    await a.resolver.put(operator, { ref: 'ref://prod/cfg/r', kind: 'value', binding: { value: 'v' }, expectedRevision: 0, ttlSeconds: 1 });
    const client = track(await ResolverClient.connect({ url: urlB, apiKey: key, live: true }));
    await client.get('ref://prod/cfg/r');
    await a.resolver.revoke(operator, { ref: 'ref://prod/cfg/r', expectedRevision: 1 });
    await sleep(1200);
    await expect(client.get('ref://prod/cfg/r')).rejects.toMatchObject({ reason: 'resolver.revoked' });
  });
});

describe('secrets: concurrent writes and destruction', () => {
  it('concurrent secret writes leave the committed revision revealable, even with a custody that keeps one version', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-custody-'));
    cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
    const vault = createVault({ directory: dir, key: randomBytes(32) });
    // A custody like most KMS-backed ones: it reveals the version it holds now, nothing older.
    const custody = { withSecret: vault.withSecret, store: vault.store, status: vault.status, remove: vault.remove };
    const runtime = track(await createResolverRuntime({ state: { memory: true }, custody }));
    const operator = runtime.operator(TENANT);
    const ref = 'ref://prod/llm/key';
    await runtime.resolver.put(operator, { ref, kind: 'secret', secret: 'first', expectedRevision: 0 });
    const writers = ['second', 'third'].map((secret) => runtime.resolver.put(operator, { ref, secret, expectedRevision: 1 }).then(() => secret, () => null));
    const results = await Promise.all(writers);
    const winner = results.find((r) => r !== null);
    expect(results.filter((r) => r !== null)).toHaveLength(1);
    expect((await runtime.resolver.resolve(operator, { ref, reveal: true })).secret).toBe(winner);
  });

  it('a revocation whose destruction failed can be retried until the material is gone', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-custody-'));
    cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
    const vault = createVault({ directory: dir, key: randomBytes(32) });
    let failures = 1;
    const custody = {
      ...vault,
      remove: async (input: Parameters<NonNullable<typeof vault.remove>>[0]) => {
        if (failures-- > 0) throw new Error('custody unavailable');
        return vault.remove!(input);
      },
    };
    const runtime = track(await createResolverRuntime({ state: { memory: true }, custody }));
    const operator = runtime.operator(TENANT);
    const ref = 'ref://prod/llm/leaked';
    await runtime.resolver.put(operator, { ref, kind: 'secret', secret: 'leaked-material', expectedRevision: 0 });
    await expect(runtime.resolver.revoke(operator, { ref, expectedRevision: 1 })).rejects.toBeTruthy();
    const reference = { secretId: (await import('@appport/resolver')).referenceId(TENANT, ref), tenantId: TENANT };
    const context = { tenantId: TENANT, principalId: 'audit', purpose: 'test' };
    // The name is revoked, but the material is still in custody.
    expect((await vault.status({ reference, context } as never)).state).toBe('set');
    // Retrying the revocation finishes the destruction, and still reports the name as already revoked.
    await expect(runtime.resolver.revoke(operator, { ref, expectedRevision: 2 })).rejects.toMatchObject({ reason: 'resolver.revoked' });
    expect((await vault.status({ reference, context } as never)).state).toBe('revoked');
  });
});

describe('management API: creating a key with grants is all or nothing', () => {
  let h: Harness;
  it('an invalid grant creates no key', async () => {
    h = track(await startResolver());
    const before = (await h.admin.listKeys()).keys.length;
    const response = await fetch(`${h.url}/_resolver/keys`, {
      method: 'POST',
      headers: { authorization: `Bearer ${h.adminKey}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'half-made', grants: [{ actions: ['read'], pattern: 'not-a-pattern' }] }),
    });
    expect(response.status).toBe(400);
    expect((await h.admin.listKeys()).keys.length).toBe(before);
  });
});

describe('recovery', () => {
  it('a live client recovers after a resolver restart and sees changes made while it was disconnected', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-restart-'));
    cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
    const options = { state: { local: dir }, vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
    let runtime = await createResolverRuntime(options);
    let server = await runtime.serve({ port: 0 });
    const port = server.port;
    const operator = runtime.operator(TENANT);
    const key = await runtime.resolver.createKey(operator, { name: 'app' });
    await runtime.resolver.grant(operator, { subject: key.principal, actions: ['read'], pattern: '*' });
    await runtime.resolver.put(operator, { ref: 'ref://prod/cfg/r', kind: 'value', binding: { value: 1 }, expectedRevision: 0, ttlSeconds: 3600 });
    const warnings: string[] = [];
    const client = track(await ResolverClient.connect({ url: server.url.replace(/\/$/, ''), apiKey: key.secret, onWarning: (w) => warnings.push(w.kind) }));
    expect(await client.get('ref://prod/cfg/r')).toBe(1);
    await runtime.close();
    // Changed while the client's resolver is down: no notification can reach it.
    runtime = await createResolverRuntime(options);
    await runtime.resolver.put(runtime.operator(TENANT), { ref: 'ref://prod/cfg/r', binding: { value: 2 }, expectedRevision: 1 });
    server = await runtime.serve({ port });
    cleanup.push(() => runtime.close());
    await waitFor(() => (warnings.includes('reconnected') ? true : undefined), 10_000);
    expect(await client.get('ref://prod/cfg/r')).toBe(2);
  });
});

describe('dependencies between references', () => {
  it('revoking a credential reports the models that still name it; the model then fails when used, with the reason', async () => {
    const h = track(await startResolver());
    await h.admin.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: 'sk-1', expectedRevision: 0 });
    await h.admin.put({ ref: 'ref://prod/chat/model', kind: 'model', binding: { value: { provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/key' } }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/*'], [['reveal'], 'ref://prod/llm/*']]);
    const used = await client.model('ref://prod/chat/model');
    // A receipt: which model revision and which credential revision were used.
    expect(used).toMatchObject({ ref: 'ref://prod/chat/model', revision: 1, credentialRevision: 1, apiKey: 'sk-1' });

    const revoked = await h.admin.revoke('ref://prod/llm/key', 1, 'leaked');
    expect(revoked.dependents).toEqual(['ref://prod/chat/model']);
    await waitFor(async () => (await client.model('ref://prod/chat/model').then(() => undefined, (e) => e)));
    await expect(client.model('ref://prod/chat/model')).rejects.toMatchObject({ reason: 'resolver.revoked' });
    // A model cannot be pointed at the revoked credential again, nor rolled back onto it.
    await expect(h.admin.put({ ref: 'ref://prod/chat/model', binding: { value: { provider: 'openai', model: 'gpt-4o-mini', credential: 'ref://prod/llm/key' } }, expectedRevision: 1 })).rejects.toMatchObject({ reason: 'resolver.credential-missing' });
  });

  it('dependents are limited to references the caller may read', async () => {
    const h = track(await startResolver());
    await h.admin.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: 'sk-1', expectedRevision: 0 });
    await h.admin.put({ ref: 'ref://team-a/model', kind: 'model', binding: { value: { provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/key' } }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read', 'write'], 'ref://prod/*']]);
    expect((await client.revoke('ref://prod/llm/key', 1)).dependents).toEqual([]);
  });
});

describe('cross-tenant attempts', () => {
  it('a principal of one tenant cannot resolve, change, revoke or watch another tenant\'s reference with the same name', async () => {
    const h = track(await startResolver());
    await h.admin.put({ ref: 'ref://prod/cfg/shared-name', kind: 'value', binding: { value: 'acme' }, expectedRevision: 0 });
    const globex = h.runtime.operator('globex');
    const key = await h.runtime.resolver.createKey(globex, { name: 'globex-admin' });
    await h.runtime.resolver.grant(globex, { subject: key.principal, actions: ['read', 'write', 'reveal', 'admin'], pattern: '*' });
    const other = track(await ResolverClient.connect({ url: h.url, apiKey: key.secret, live: false }));
    await expect(other.get('ref://prod/cfg/shared-name')).rejects.toMatchObject({ reason: 'resolver.not-found' });
    await expect(other.revoke('ref://prod/cfg/shared-name', 1)).rejects.toMatchObject({ reason: 'resolver.not-found' });
    await expect(other.put({ ref: 'ref://prod/cfg/shared-name', binding: { value: 'x' }, expectedRevision: 1 })).rejects.toMatchObject({ reason: 'resolver.stale-revision' });
    expect((await other.history('ref://prod/cfg/shared-name').catch((e) => e)).reason).toBe('resolver.not-found');
    expect((await other.grants()).grants.every((g) => g.subject === key.principal)).toBe(true);
    expect((await other.listKeys()).keys.map((k) => k.name)).toEqual(['globex-admin']);
    // acme's key ids are not revocable from globex.
    const acmeKeys = (await h.admin.listKeys()).keys;
    for (const k of acmeKeys) await other.revokeKey(k.id).catch(() => undefined);
    expect((await h.admin.listKeys()).keys.every((k) => k.status === 'active')).toBe(true);
    expect(await h.admin.get('ref://prod/cfg/shared-name')).toBe('acme');
  });
});

describe('isolation of in-memory runtimes', () => {
  it('two memory runtimes in one process do not share state', async () => {
    const a = track(await createResolverRuntime({ state: { memory: true }, custody: createVault({ directory: mkdtempSync(path.join(tmpdir(), 'v-')), key: randomBytes(32) }) }));
    const b = track(await createResolverRuntime({ state: { memory: true }, custody: createVault({ directory: mkdtempSync(path.join(tmpdir(), 'v-')), key: randomBytes(32) }) }));
    await a.resolver.put(a.operator(TENANT), { ref: 'ref://prod/cfg/only-in-a', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
    await expect(b.resolver.resolve(b.operator(TENANT), { ref: 'ref://prod/cfg/only-in-a' })).rejects.toMatchObject({ reason: 'resolver.not-found' });
  });
});
