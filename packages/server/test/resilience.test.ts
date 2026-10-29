// What a consumer sees when the resolver is down, and that state and secrets survive a restart.
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { createResolverRuntime } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';
import { startResolver } from './harness.js';

describe('resolver outage', () => {
  it('serves the last known good value within maxStaleSeconds, then fails', async () => {
    const h = await startResolver();
    await h.admin.put({ ref: 'ref://prod/cfg/x', kind: 'value', binding: { value: 'good' }, expectedRevision: 0, ttlSeconds: 0 });
    const warnings: string[] = [];
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false, maxStaleSeconds: 1, onWarning: (w) => warnings.push(w.kind) });
    expect(await client.get('ref://prod/cfg/x')).toBe('good');
    await h.runtime.close(); // the resolver goes away
    expect(await client.get('ref://prod/cfg/x')).toBe('good');
    expect(warnings).toContain('stale');
    await new Promise((r) => setTimeout(r, 1100));
    await expect(client.get('ref://prod/cfg/x')).rejects.toBeTruthy();
    await h.close().catch(() => undefined);
  });

  it('fails closed with maxStaleSeconds 0', async () => {
    const h = await startResolver();
    await h.admin.put({ ref: 'ref://prod/cfg/y', kind: 'value', binding: { value: 'v' }, expectedRevision: 0, ttlSeconds: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false, maxStaleSeconds: 0 });
    expect(await client.get('ref://prod/cfg/y')).toBe('v');
    await h.runtime.close();
    await expect(client.get('ref://prod/cfg/y')).rejects.toBeTruthy();
    await h.close().catch(() => undefined);
  });
});

describe('durability', () => {
  it('keeps references, history, grants, keys and secrets across a restart (local state)', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-durable-'));
    const vaultKey = randomBytes(32);
    const verifierKey = randomBytes(32).toString('hex');
    const open = () => createResolverRuntime({ state: { local: dir }, vaultKey, verifierKey });
    let runtime = await open();
    const operator = runtime.operator('acme');
    const key = await runtime.resolver.createKey(operator, { name: 'app' });
    await runtime.resolver.grant(operator, { subject: key.principal, actions: ['read', 'reveal'], pattern: 'ref://prod/*' });
    await runtime.resolver.put(operator, { ref: 'ref://prod/llm/key', kind: 'secret', secret: 'persisted-material', expectedRevision: 0 });
    await runtime.resolver.put(operator, { ref: 'ref://prod/cfg/z', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
    await runtime.resolver.put(operator, { ref: 'ref://prod/cfg/z', binding: { value: 2 }, expectedRevision: 1 });
    await runtime.close();

    runtime = await open();
    const server = await runtime.serve({ port: 0 });
    const client = await ResolverClient.connect({ url: server.url.replace(/\/$/, ''), apiKey: key.secret, live: false });
    expect(await client.get('ref://prod/cfg/z')).toBe(2);
    expect(await client.secret('ref://prod/llm/key')).toBe('persisted-material');
    expect((await runtime.resolver.history(runtime.operator('acme'), { ref: 'ref://prod/cfg/z' })).entries).toHaveLength(2);
    await client.close();
    await runtime.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
