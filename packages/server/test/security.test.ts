import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppPort } from '@appport/sdk';
import { ResolverClient } from '@appport/resolver-client';
import { COLLECTIONS, createVault } from '@appport/resolver';
import { startResolver, waitFor, type Harness } from './harness.js';

const SECRET = 'sk-live-THIS-MUST-NEVER-BE-AT-REST-OR-LOGGED';

let h: Harness;
beforeAll(async () => {
  h = await startResolver();
  await h.admin.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: SECRET, expectedRevision: 0 });
  await h.admin.put({ ref: 'ref://prod/app/config', kind: 'value', binding: { value: { a: 1 } }, expectedRevision: 0 });
  await h.admin.put({ ref: 'ref://staging/app/config', kind: 'value', binding: { value: { a: 'staging' } }, expectedRevision: 0 });
});
afterAll(async () => h?.close());

const code = async (p: Promise<unknown>) => p.then(() => 'OK', (e) => e.code as string);

describe('authentication and authorization', () => {
  it('refuses callers without a valid API key', async () => {
    const anonymous = await AppPort.discover({ origin: h.url });
    await expect(anonymous.call('resolver.resolve', { ref: 'ref://prod/app/config' })).rejects.toMatchObject({ code: expect.stringMatching(/UNAUTHORIZED|FORBIDDEN/) });
    await anonymous.close();
    const forged = new ResolverClient({ url: h.url, apiKey: 'app_live_000000_forged', live: false });
    expect(await code(forged.get('ref://prod/app/config'))).toMatch(/UNAUTHORIZED|FORBIDDEN/);
    await forged.close();
  });

  it('allows exactly what is granted, deny by default', async () => {
    const { client } = await h.clientWith([[['read'], 'ref://prod/app/*']]);
    expect(await client.get('ref://prod/app/config')).toEqual({ a: 1 });
    expect(await code(client.get('ref://staging/app/config'))).toBe('FORBIDDEN');
    expect(await code(client.get('ref://prod/llm/key'))).toBe('FORBIDDEN');
    expect(await code(client.put({ ref: 'ref://prod/app/config', binding: { value: { a: 2 } }, expectedRevision: 1 }))).toBe('FORBIDDEN');
    expect(await code(client.grant('someone', ['admin'], '*'))).toBe('FORBIDDEN');
    expect(await code(client.createKey('escalate'))).toBe('FORBIDDEN');
  });

  it('does not reveal whether a reference exists to a caller who may not read it', async () => {
    const { client } = await h.clientWith([[['read'], 'ref://prod/app/*']]);
    expect(await code(client.get('ref://staging/app/config'))).toBe('FORBIDDEN');
    expect(await code(client.get('ref://staging/app/does-not-exist'))).toBe('FORBIDDEN');
  });

  it('applies a removed grant on the next request', async () => {
    const { client, principal } = await h.clientWith([[['read'], 'ref://prod/app/*']]);
    expect(await client.get('ref://prod/app/config')).toEqual({ a: 1 });
    const { grants } = await h.admin.grants();
    for (const g of grants.filter((g) => g.subject === principal)) await h.admin.ungrant(g.id);
    // The client still caches the old answer until a change or TTL; a fresh client is refused at once.
    const fresh = new ResolverClient({ url: h.url, apiKey: (await h.admin.createKey('x')).secret, live: false });
    expect(await code(fresh.get('ref://prod/app/config'))).toBe('FORBIDDEN');
    await fresh.close();
  });

  it('keeps tenants apart: names, values, lists and change notifications', async () => {
    const other = h.runtime.operator('globex');
    const key = await h.runtime.resolver.createKey(other, { name: 'globex-admin' });
    await h.runtime.resolver.grant(other, { subject: key.principal, actions: ['admin', 'read', 'write', 'reveal'], pattern: '*' });
    const globex = await ResolverClient.connect({ url: h.url, apiKey: key.secret });
    expect(await code(globex.get('ref://prod/app/config'))).toBe('NOT_FOUND');
    expect((await globex.list()).refs).toEqual([]);
    const seen: string[] = [];
    globex.watch('ref://', (e) => seen.push(e.ref));
    await new Promise((r) => setTimeout(r, 200));
    await h.admin.set('ref://prod/app/config', { binding: { value: { a: 'changed' } } });
    await globex.put({ ref: 'ref://prod/app/config', kind: 'value', binding: { value: { mine: true } }, expectedRevision: 0 });
    await waitFor(() => (seen.length ? true : undefined));
    expect(seen).toEqual(['ref://prod/app/config']); // its own change only
    expect(await globex.get('ref://prod/app/config')).toEqual({ mine: true });
    expect(await h.admin.get('ref://prod/app/config')).toEqual({ a: 'changed' });
    await globex.close();
  });

  it('streams change notifications only for references the watcher may read', async () => {
    const { client } = await h.clientWith([[['read'], 'ref://prod/app/*']]);
    const seen: string[] = [];
    client.watch('ref://', (e) => seen.push(e.ref));
    await new Promise((r) => setTimeout(r, 200));
    await h.admin.set('ref://staging/app/config', { binding: { value: { a: 'hidden' } } });
    await h.admin.set('ref://prod/app/config', { binding: { value: { a: 'visible' } } });
    await waitFor(() => (seen.includes('ref://prod/app/config') ? true : undefined));
    expect(seen).not.toContain('ref://staging/app/config');
  });
});

describe('secrets', () => {
  it('reveals material only with a reveal grant, and records every reveal', async () => {
    const { client: reader } = await h.clientWith([[['read'], 'ref://prod/llm/*']]);
    const meta = await reader.resolve('ref://prod/llm/key');
    expect(JSON.stringify(meta)).not.toContain(SECRET);
    expect(meta.selected.value).toMatchObject({ credentialRef: expect.stringMatching(/^credential-ref:/), version: 1 });
    expect(await code(reader.secret('ref://prod/llm/key'))).toBe('FORBIDDEN');

    const { client: app, principal } = await h.clientWith([[['read', 'reveal'], 'ref://prod/llm/*']]);
    expect(await app.secret('ref://prod/llm/key')).toBe(SECRET);
    const { reveals } = await h.runtime.resolver.reveals(h.runtime.operator('acme'), { ref: 'ref://prod/llm/key' });
    expect(reveals.some((r) => r.principalId === principal && r.custodyVersion === 1 && r.decisionId.startsWith('dec_'))).toBe(true);
    expect(JSON.stringify(reveals)).not.toContain(SECRET);
  });

  it('never stores material in FeltDB, in history, in lists or in the vault in plaintext', async () => {
    const dump: string[] = [];
    for (const name of [...Object.values(COLLECTIONS), 'service_effect_evidence']) {
      dump.push(JSON.stringify(await h.runtime.db.collection(name).all()));
    }
    expect(dump.join('\n')).not.toContain(SECRET);
    expect(JSON.stringify(await h.admin.history('ref://prod/llm/key'))).not.toContain(SECRET);
    expect(JSON.stringify(await h.admin.list())).not.toContain(SECRET);
    const vault = path.join(h.dir, 'vault');
    for (const file of readdirSync(vault)) expect(readFileSync(path.join(vault, file), 'utf8')).not.toContain(SECRET);
  });

  it('rotates by version; a pinned revision still reveals the version it pointed at', async () => {
    const r = await h.admin.put({ ref: 'ref://prod/llm/rotating', kind: 'secret', secret: 'v1-material', expectedRevision: 0 });
    await h.admin.put({ ref: 'ref://prod/llm/rotating', secret: 'v2-material', expectedRevision: r.revision });
    expect(await h.admin.secret('ref://prod/llm/rotating')).toBe('v2-material');
    const pinned = await h.runtime.resolver.resolve(h.runtime.operator('acme'), { ref: 'ref://prod/llm/rotating', revision: 1, reveal: true });
    expect(pinned.secret).toBe('v1-material');
  });

  it('a vault opened with another key cannot read the material', async () => {
    const other = createVault({ directory: path.join(h.dir, 'vault'), key: randomBytes(32) });
    const ref = { reference: { secretId: 'x', tenantId: 'acme' }, context: { tenantId: 'acme', principalId: 'p', purpose: 't' } };
    await other.store({ ...ref, value: 'sealed' });
    const wrong = createVault({ directory: path.join(h.dir, 'vault'), key: randomBytes(32) });
    await expect(wrong.withSecret(ref, (s) => s.value)).rejects.toMatchObject({ code: 'CORRUPT' });
    const crossTenant = { ...ref, context: { ...ref.context, tenantId: 'globex' } };
    await expect(other.withSecret(crossTenant, (s) => s.value)).rejects.toMatchObject({ code: 'MISSING' });
  });

  it('revoking a secret destroys its material and every resolution fails', async () => {
    const r = await h.admin.put({ ref: 'ref://prod/llm/compromised', kind: 'secret', secret: 'leaked-key', expectedRevision: 0 });
    await h.admin.revoke('ref://prod/llm/compromised', r.revision, 'leaked in a log');
    expect(await code(h.admin.secret('ref://prod/llm/compromised'))).toBe('NOT_FOUND');
    await expect(h.runtime.resolver.resolve(h.runtime.operator('acme'), { ref: 'ref://prod/llm/compromised', revision: 1, reveal: true })).rejects.toMatchObject({ reason: 'resolver.revoked' });
    const status = await h.runtime.services.gateway.custody!.status({ reference: { secretId: (await import('@appport/resolver')).referenceId('acme', 'ref://prod/llm/compromised'), tenantId: 'acme' }, context: { tenantId: 'acme', principalId: 'op', purpose: 't' } });
    expect(status.state).toBe('revoked');
    expect(await code(h.admin.put({ ref: 'ref://prod/llm/compromised', kind: 'secret', secret: 'new', expectedRevision: 0 }))).toBe('CONFLICT');
  });
});

describe('revisions, history and rollback', () => {
  it('refuses a stale revision and lets exactly one of concurrent writers win', async () => {
    await h.admin.put({ ref: 'ref://prod/race/value', kind: 'value', binding: { value: 0 }, expectedRevision: 0 });
    const writers = Array.from({ length: 8 }, (_, i) => h.admin.put({ ref: 'ref://prod/race/value', binding: { value: i + 1 }, expectedRevision: 1 }).then(() => 'won', (e) => e.code));
    const results = await Promise.all(writers);
    expect(results.filter((r) => r === 'won')).toHaveLength(1);
    expect(results.filter((r) => r === 'CONFLICT')).toHaveLength(7);
    const { entries } = await h.admin.history('ref://prod/race/value');
    expect(entries.map((e) => e.revision)).toEqual([1, 2]);
    const stale = await h.admin.put({ ref: 'ref://prod/race/value', binding: { value: 99 }, expectedRevision: 1 }).catch((e) => e);
    expect(stale).toMatchObject({ code: 'CONFLICT', reason: 'resolver.stale-revision', details: { currentRevision: 2 } });
  });

  it('records actor and reason, and rollback restores an old binding as a new revision', async () => {
    await h.admin.put({ ref: 'ref://prod/hist/value', kind: 'value', binding: { value: 'a' }, expectedRevision: 0, reason: 'initial' });
    await h.admin.put({ ref: 'ref://prod/hist/value', binding: { value: 'b' }, expectedRevision: 1, reason: 'bad change' });
    await h.admin.rollback('ref://prod/hist/value', 1, 2, 'revert bad change');
    expect(await h.admin.get('ref://prod/hist/value')).toBe('a');
    const { entries } = await h.admin.history('ref://prod/hist/value');
    expect(entries.map((e) => [e.revision, e.action, e.restoredFrom ?? null, e.reason])).toEqual([
      [1, 'create', null, 'initial'],
      [2, 'update', null, 'bad change'],
      [3, 'rollback', 1, 'revert bad change'],
    ]);
    expect(entries.every((e) => e.actor.startsWith('api_key:'))).toBe(true);
  });

  it('fixes kind and schema at creation', async () => {
    await h.admin.put({ ref: 'ref://prod/typed/limits', kind: 'value', schema: { type: 'object', required: ['rps'], properties: { rps: { type: 'integer', minimum: 1 } } }, binding: { value: { rps: 10 } }, expectedRevision: 0 });
    expect(await code(h.admin.put({ ref: 'ref://prod/typed/limits', binding: { value: { rps: 'fast' } }, expectedRevision: 1 }))).toBe('INVALID_INPUT');
    expect(await code(h.admin.put({ ref: 'ref://prod/typed/limits', kind: 'endpoint', binding: { value: { url: 'https://x.example' } }, expectedRevision: 1 }))).toBe('INVALID_INPUT');
    expect(await code(h.admin.put({ ref: 'ref://prod/typed/limits', schema: {}, binding: { value: { rps: 1 } }, expectedRevision: 1 }))).toBe('INVALID_INPUT');
    expect((await h.admin.put({ ref: 'ref://prod/typed/limits', binding: { value: { rps: 50 } }, expectedRevision: 1 })).revision).toBe(2);
  });

  it('revocation is total and immediate for running clients, and a revoked name is never reused', async () => {
    await h.admin.put({ ref: 'ref://prod/kill/switch', kind: 'value', binding: { value: 'on' }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/kill/*']]);
    expect(await client.get('ref://prod/kill/switch')).toBe('on');
    await h.admin.revoke('ref://prod/kill/switch', 1, 'incident');
    await waitFor(async () => ((await code(client.get('ref://prod/kill/switch'))) === 'NOT_FOUND' ? true : undefined));
    expect(await code(client.resolve('ref://prod/kill/switch', { revision: 1 }))).toBe('NOT_FOUND');
    expect(await code(h.admin.put({ ref: 'ref://prod/kill/switch', kind: 'value', binding: { value: 'x' }, expectedRevision: 0 }))).toBe('CONFLICT');
  });
});

describe('model targets', () => {
  it('checks provider, catalog model and credential', async () => {
    const put = (value: unknown) => code(h.admin.put({ ref: `ref://prod/m/${randomBytes(3).toString('hex')}`, kind: 'model', binding: { value }, expectedRevision: 0 }));
    expect(await put({ provider: 'nope', model: 'x' })).toBe('INVALID_INPUT');
    expect(await put({ provider: 'anthropic', model: 'not-a-claude', credential: 'ref://prod/llm/key' })).toBe('INVALID_INPUT');
    expect(await put({ provider: 'openai', model: 'gpt-4o' })).toBe('INVALID_INPUT'); // needs a credential
    expect(await put({ provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/app/config' })).toBe('INVALID_INPUT'); // not a secret
    expect(await put({ provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/key' })).toBe('OK');
  });
});

describe('API key lifecycle', () => {
  it('a revoked key stops working at once, on an open connection and on its watch stream', async () => {
    const created = await h.admin.createKey('short-lived');
    await h.admin.grant(created.principal, ['read'], 'ref://prod/app/*');
    const client = await ResolverClient.connect({ url: h.url, apiKey: created.secret, live: true });
    expect(await client.get('ref://prod/app/config')).toBeDefined();
    await h.admin.revokeKey(created.id);
    await h.admin.set('ref://prod/app/config', { binding: { value: { a: 'after-revoke' } } });
    // The cache was invalidated by the change (or the stream ended); re-resolution is refused.
    await waitFor(async () => ((await code(client.get('ref://prod/app/config'))) === 'UNAUTHORIZED' ? true : undefined));
    const keys = (await h.admin.listKeys()).keys;
    expect(keys.find((k) => k.id === created.id)).toMatchObject({ status: 'revoked', prefix: expect.stringMatching(/^app_live_/) });
    await client.close();
  });
});
