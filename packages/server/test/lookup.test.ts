// Exact lookup by a reference's lookup entry (resolver.lookup): a general, indexed primitive.
// PersonalOS uses it to resolve an external identity (key "identity:<adapter>:<instance>", value the
// principal id) to the account-link references that name it, without listing references.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startResolver, type Harness } from './harness.js';

let h: Harness;
beforeAll(async () => {
  h = await startResolver({ local: true });
});
afterAll(async () => {
  await h?.close();
});

const link = (n: string, value: string, key = 'identity:multiplayer:prod') =>
  h.admin.put({ ref: `ref://identity/test/${n}`, kind: 'value', binding: { value: { canonical: `account:${n}` } }, expectedRevision: 0, ttlSeconds: 0, lookup: { key, value } } as never);

describe('resolver.lookup', () => {
  it('finds exactly the references with that key and value, and nothing else', async () => {
    await link('ada-1', 'ada');
    await link('grace-1', 'grace');
    await link('ada-other-install', 'ada', 'identity:multiplayer:staging');
    await h.admin.put({ ref: 'ref://identity/test/plain', kind: 'value', binding: { value: 1 }, expectedRevision: 0 } as never);
    expect((await h.admin.lookup('identity:multiplayer:prod', 'ada')).refs.map((r) => r.ref)).toEqual(['ref://identity/test/ada-1']);
    expect((await h.admin.lookup('identity:multiplayer:prod', 'Ada')).refs).toEqual([]);
    expect((await h.admin.lookup('identity:multiplayer:prod', 'nobody')).refs).toEqual([]);
    expect((await h.admin.lookup('identity:multiplayer:staging', 'ada')).refs.map((r) => r.ref)).toEqual(['ref://identity/test/ada-other-install']);
  });

  it('returns every match, so the caller can refuse an ambiguous one', async () => {
    await link('dup-1', 'dup');
    await link('dup-2', 'dup');
    expect((await h.admin.lookup('identity:multiplayer:prod', 'dup')).refs.map((r) => r.ref)).toEqual(['ref://identity/test/dup-1', 'ref://identity/test/dup-2']);
  });

  it('a revoked reference no longer answers (unless revoked ones are asked for)', async () => {
    await link('rev-1', 'revoked-user');
    await h.admin.revoke('ref://identity/test/rev-1', 1, 'unlinked');
    expect((await h.admin.lookup('identity:multiplayer:prod', 'revoked-user')).refs).toEqual([]);
    const all = await h.admin.lookup('identity:multiplayer:prod', 'revoked-user', { includeRevoked: true });
    expect(all.refs.map((r) => [r.ref, r.state])).toEqual([['ref://identity/test/rev-1', 'revoked']]);
  });

  it('a reference the caller may not read is invisible to its lookup', async () => {
    await h.admin.put({ ref: 'ref://elsewhere/secret-link', kind: 'value', binding: { value: { x: 1 } }, expectedRevision: 0, lookup: { key: 'identity:multiplayer:prod', value: 'ada' } } as never);
    const { client } = await h.clientWith([[['read'], 'ref://identity/*']]);
    expect((await client.lookup('identity:multiplayer:prod', 'ada')).refs.map((r) => r.ref)).toEqual(['ref://identity/test/ada-1']);
    const { client: none } = await h.clientWith([[['read'], 'ref://nothing/*']]);
    expect((await none.lookup('identity:multiplayer:prod', 'ada')).refs).toEqual([]);
  });

  it('the entry is fixed at creation: an update may repeat it, never change it', async () => {
    await link('fixed', 'fixed-user');
    await expect(h.admin.put({ ref: 'ref://identity/test/fixed', binding: { value: { canonical: 'account:x' } }, expectedRevision: 1, lookup: { key: 'identity:multiplayer:prod', value: 'someone-else' } } as never)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await h.admin.put({ ref: 'ref://identity/test/fixed', binding: { value: { canonical: 'account:x' } }, expectedRevision: 1 } as never);
    expect((await h.admin.lookup('identity:multiplayer:prod', 'fixed-user')).refs.map((r) => r.revision)).toEqual([2]);
  });

  it('refuses malformed keys and values', async () => {
    await expect(h.admin.lookup('Bad Key', 'x')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(h.admin.lookup('identity:x', '')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(link('bad', 'x', 'UPPER')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('is served from a compound index on (tenant, key, value), not a scan', async () => {
    expect(h.runtime.store.lookupIndexed()).toBe(true);
    const indexes = h.runtime.db.collection('resolver_references').listIndexes();
    expect(indexes.map((i) => [i.name, i.type, i.fields])).toContainEqual(['resolver_references_lookup', 'compound', ['tenantId', 'lookupKey', 'lookupValue']]);
  });
});
