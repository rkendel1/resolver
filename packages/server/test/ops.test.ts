// Operations: health and readiness endpoints, structured logs that never carry credentials or material,
// management sessions any instance can serve, and a client that never waits past its deadline.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createLogger, createResolverRuntime, type ResolverRuntime } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';

const cleanup: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await Promise.resolve(task()).catch(() => undefined);
});

async function instance(options: { db?: ReturnType<typeof createFeltDB>; vaultDirectory?: string; lines?: string[]; name?: string; keys?: { vaultKey: Buffer; verifierKey: string } } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-ops-'));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const keys = options.keys ?? { vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
  const runtime: ResolverRuntime = await createResolverRuntime({
    state: options.db ? { db: options.db } : { memory: true },
    vaultDirectory: options.vaultDirectory ?? path.join(dir, 'vault'),
    ...keys,
    environment: 'development',
    instanceId: options.name ?? 'ops-1',
    logger: createLogger({ instance: options.name ?? 'ops-1', level: 'debug', write: (line) => options.lines?.push(line) }),
  });
  cleanup.push(() => runtime.close());
  const url = (await runtime.serve({ port: 0 })).url.replace(/\/$/, '');
  return { runtime, url, keys };
}

describe('health and readiness', () => {
  it('health says the process is up; readiness reports each check and is 200 when all pass', async () => {
    const { url } = await instance();
    const health = await fetch(`${url}/_resolver/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: 'ok', instance: 'ops-1' });
    const ready = await fetch(`${url}/_resolver/ready`);
    expect(ready.status).toBe(200);
    expect(ready.headers.get('cache-control')).toBe('no-store');
    const body = await ready.json();
    expect(body).toMatchObject({ ready: true, instance: 'ops-1', checks: { config: { ok: true, environment: 'development' }, state: { ok: true }, sync: { ok: true }, custody: { ok: true, kind: 'vault' }, integrity: { ok: true } } });
  });

  it('readiness is 503 when the vault cannot be used', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-ops-'));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    const notADirectory = path.join(dir, 'vault');
    writeFileSync(notADirectory, 'not a directory');
    const { url } = await instance({ vaultDirectory: path.join(notADirectory, 'inside') });
    const ready = await fetch(`${url}/_resolver/ready`);
    expect(ready.status).toBe(503);
    expect((await ready.json()).checks.custody).toMatchObject({ ok: false, error: 'ENOTDIR' });
  });

  it('readiness is 503 when the state store does not answer', async () => {
    const { runtime, url } = await instance();
    runtime.store.sequence = async () => {
      throw Object.assign(new Error('down'), { code: 'UNAVAILABLE' });
    };
    expect((await fetch(`${url}/_resolver/ready`)).status).toBe(503);
    expect((await fetch(`${url}/_resolver/health`)).status).toBe(200);
  });
});

describe('structured logs', () => {
  it('one JSON line per call with request id, operation, outcome, instance and revision, and never a key, secret or binding', async () => {
    const lines: string[] = [];
    const { runtime, url } = await instance({ lines });
    const op = runtime.operator('acme');
    const key = await runtime.resolver.createKey(op, { name: 'logged' });
    await runtime.resolver.grant(op, { subject: key.principal, actions: ['read', 'write', 'reveal'], pattern: '*' });
    const client = await ResolverClient.connect({ url, apiKey: key.secret, live: false });
    cleanup.push(() => client.close());
    const secret = 'sk-NEVER-IN-LOGS';
    await client.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret, expectedRevision: 0, reason: 'a reason that is not logged' });
    await client.secret('ref://prod/llm/key');
    await client.put({ ref: 'ref://prod/cfg/x', kind: 'value', binding: { value: { password: 'not-logged-either' } }, expectedRevision: 0 });
    await client.put({ ref: 'ref://prod/cfg/x', binding: { value: 1 }, expectedRevision: 0 }).catch(() => undefined);

    const records = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    const calls = records.filter((r) => r['event'] === 'call');
    expect(calls.length).toBeGreaterThanOrEqual(4);
    for (const call of calls) {
      expect(call).toMatchObject({ instance: 'ops-1', level: expect.any(String), requestId: expect.stringMatching(/^req_/), operation: expect.stringMatching(/^resolver\./), code: expect.any(String), durationMs: expect.any(Number) });
    }
    expect(calls).toContainEqual(expect.objectContaining({ operation: 'resolver.put', code: 'OK', ref: 'ref://prod/llm/key', revision: 1, tenant: 'acme' }));
    expect(calls).toContainEqual(expect.objectContaining({ operation: 'resolver.put', code: 'CONFLICT', reason: 'resolver.stale-revision' }));
    const all = lines.join('\n');
    for (const forbidden of [secret, key.secret, 'not-logged-either', 'a reason that is not logged']) expect(all).not.toContain(forbidden);
  });
});

describe('management sessions across instances', () => {
  it('a browser signed in through one instance is served by another, and revoking its key ends the session everywhere', async () => {
    const db = createFeltDB({ namespace: `ops-${randomBytes(4).toString('hex')}`, memory: true });
    cleanup.push(() => db.close());
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-ops-'));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    const keys = { vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
    const a = await instance({ db, vaultDirectory: path.join(dir, 'vault'), keys, name: 'A' });
    const b = await instance({ db, vaultDirectory: path.join(dir, 'vault'), keys, name: 'B' });
    const op = a.runtime.operator('acme');
    const key = await a.runtime.resolver.createKey(op, { name: 'operator' });
    await a.runtime.resolver.grant(op, { subject: key.principal, actions: ['read', 'write', 'admin'], pattern: '*' });

    const signIn = await fetch(`${a.url}/_resolver/session`, { method: 'POST', headers: { 'content-type': 'application/json', origin: a.url }, body: JSON.stringify({ apiKey: key.secret }) });
    expect(signIn.status).toBe(204);
    const cookie = signIn.headers.get('set-cookie')!.split(';')[0]!;
    // Served by B, which never saw the sign-in.
    const onB = await fetch(`${b.url}/_resolver/session`, { headers: { cookie } });
    expect(onB.status).toBe(200);
    expect(await onB.json()).toMatchObject({ principal: key.principal, name: 'operator', via: 'session' });
    const write = await fetch(`${b.url}/_resolver/references`, { method: 'POST', headers: { cookie, 'content-type': 'application/json', origin: b.url }, body: JSON.stringify({ ref: 'ref://prod/cfg/ui', kind: 'value', binding: { value: 1 }, expectedRevision: 0 }) });
    expect(write.status).toBe(200);
    // The change is recorded as the key's, wherever it was made.
    expect((await a.runtime.resolver.history(op, { ref: 'ref://prod/cfg/ui' })).entries[0]!.actor).toBe(`api_key:${key.principal}`);

    await b.runtime.resolver.revokeKey(op, { id: key.id });
    expect((await fetch(`${a.url}/_resolver/session`, { headers: { cookie } })).status).toBe(401);
    expect((await fetch(`${b.url}/_resolver/session`, { headers: { cookie } })).status).toBe(401);
    // Only a hash of the token is stored.
    const stored = JSON.stringify(await db.collection('resolver_sessions').find({}));
    expect(stored).not.toContain(cookie.split('=')[1]);
  });

  it('signing out on one instance ends the session on the others', async () => {
    const db = createFeltDB({ namespace: `ops-${randomBytes(4).toString('hex')}`, memory: true });
    cleanup.push(() => db.close());
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-ops-'));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    const keys = { vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
    const a = await instance({ db, vaultDirectory: path.join(dir, 'vault'), keys, name: 'A' });
    const b = await instance({ db, vaultDirectory: path.join(dir, 'vault'), keys, name: 'B' });
    const key = await a.runtime.resolver.createKey(a.runtime.operator('acme'), { name: 'operator' });
    const signIn = await fetch(`${a.url}/_resolver/session`, { method: 'POST', headers: { 'content-type': 'application/json', origin: a.url }, body: JSON.stringify({ apiKey: key.secret }) });
    const cookie = signIn.headers.get('set-cookie')!.split(';')[0]!;
    expect((await fetch(`${b.url}/_resolver/session`, { method: 'DELETE', headers: { cookie, origin: b.url } })).status).toBe(204);
    expect((await fetch(`${a.url}/_resolver/session`, { headers: { cookie } })).status).toBe(401);
  });
});

describe('client deadline', () => {
  it('a resolver that accepts connections but never answers fails the call within timeoutMs', async () => {
    const sockets = new Set<import('node:net').Socket>();
    const silent: TcpServer = createTcpServer((socket) => sockets.add(socket)); // accepts, never responds
    await new Promise<void>((r) => silent.listen(0, '127.0.0.1', () => r()));
    cleanup.push(() => new Promise((r) => {
      for (const socket of sockets) socket.destroy();
      silent.close(r);
    }));
    const url = `http://127.0.0.1:${(silent.address() as { port: number }).port}`;
    const client = new ResolverClient({ url, apiKey: 'app_live_x', live: false, timeoutMs: 300 });
    const started = Date.now();
    const error = await client.get('ref://prod/cfg/x').catch((e) => e);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(error.authoritative).toBe(false);
    await client.close();
  });
});

describe('multi-instance configuration is checked at startup', () => {
  const base = () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-ops-'));
    cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
    return { dir, vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32), multiInstance: true, environment: 'development' as const };
  };
  it('refuses memory state, unshared local state, and custody that keeps one version', async () => {
    await expect(createResolverRuntime({ ...base(), state: { memory: true } })).rejects.toThrow(/memory state/);
    const b = base();
    await expect(createResolverRuntime({ ...b, state: { local: b.dir } })).rejects.toThrow(/shared: true/);
    const c = base();
    const single = { withSecret: async () => { throw new Error('x'); }, store: async () => ({ version: 1, storedAt: '' }), status: async () => ({ state: 'missing' }) };
    await expect(createResolverRuntime({ ...c, state: { local: c.dir, shared: true }, custody: single as never })).rejects.toThrow(/keep versions/);
  });

  it('refuses an invalid outbound configuration and an unknown environment', async () => {
    const d = base();
    await expect(createResolverRuntime({ ...d, multiInstance: false, state: { memory: true }, environment: 'production', outbound: { allowedOrigins: ['https://x.example.com/path'] } })).rejects.toThrow(/must be an origin/);
    await expect(createResolverRuntime({ ...d, multiInstance: false, state: { memory: true }, environment: 'staging' as never })).rejects.toThrow(/unknown environment/);
  });
});
