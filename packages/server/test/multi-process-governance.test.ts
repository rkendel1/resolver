// Governance and adoption across real processes: two `resolver serve` processes (the built CLI) over one shared
// state, an operator using the CLI on the same host, writers and consumers talking to either instance.
// Needs `npm run build` first. Uses local state opened shared (several processes on one host).
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { ResolverClient } from '@appport/resolver-client';
import { generateSigningKey, signChangeAuthorization } from '@appport/resolver-client/authorization';
import { freePort } from './feltdb-server.js';
import { waitFor } from './harness.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const cleanup: Array<() => Promise<unknown>> = [];
afterAll(async () => {
  for (const task of cleanup.splice(0).reverse()) await task().catch(() => undefined);
});

function cli(args: string[], env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { env: { ...process.env, ...env } }, (error, stdout, stderr) => resolve({ code: error ? ((error as { code?: number }).code ?? 1) : 0, stdout, stderr }));
  });
}

async function serve(env: Record<string, string>, name: string): Promise<{ url: string; stop(): Promise<void> }> {
  const port = await freePort();
  const child: ChildProcess = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], { env: { ...process.env, ...env, RESOLVER_INSTANCE_ID: name }, stdio: ['ignore', 'pipe', 'pipe'] });
  const logs: string[] = [];
  child.stdout!.on('data', (d: Buffer) => logs.push(d.toString('utf8')));
  child.stderr!.on('data', (d: Buffer) => logs.push(d.toString('utf8')));
  const url = `http://127.0.0.1:${port}`;
  await waitFor(async () => {
    if (child.exitCode !== null) throw new Error(`${name} exited: ${logs.join('')}`);
    return fetch(`${url}/_resolver/health`).then((r) => (r.ok ? true : undefined), () => undefined);
  }, 15_000);
  const stop = async () => {
    if (child.exitCode !== null) return;
    child.kill('SIGTERM');
    await new Promise((r) => child.once('exit', r));
  };
  cleanup.push(stop);
  return { url, stop };
}

describe.skipIf(!existsSync(CLI))('governance across two resolver processes (local state shared)', () => {
  it('one authorization commits once across instances; evidence, break-glass and consumption survive restarts; adoption reads across instances', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-mp-gov-'));
    cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
    const env: Record<string, string> = { RESOLVER_DIR: dir, RESOLVER_VAULT_DIR: path.join(dir, 'vault'), RESOLVER_STATE_SHARED: '1', RESOLVER_MULTI_INSTANCE: '1', RESOLVER_ENV: 'development', RESOLVER_SYNC_INTERVAL_MS: '100', RESOLVER_LOG_LEVEL: 'off' };
    const init = await cli(['init', '--tenant', 'acme'], env);
    expect(init.code, init.stderr).toBe(0);
    const adminKey = init.stdout.trim();
    const a = await serve(env, 'A');
    let b = await serve(env, 'B');
    const adminA = await ResolverClient.connect({ url: a.url, apiKey: adminKey, live: false });
    cleanup.push(() => adminA.close());
    await adminA.set('ref://prod/search', { kind: 'endpoint', binding: { value: { url: 'https://search-a.example.com' } } });

    // The operator sets the trust roots with the CLI on the state host while both instances serve.
    const { publicKey, privateKeyPem } = generateSigningKey();
    const local = (args: string[]) => cli([...args, '--tenant', 'acme'], env);
    expect((await local(['signing-key', 'add', 'rc-1', '--issuer', 'resolver-control', '--public-key', publicKey, '--reason', 'approvals'])).code).toBe(0);
    expect((await local(['policy', 'set', 'prod', '--pattern', 'ref://prod/*', '--operations', 'put,rollback,revoke', '--issuer', 'resolver-control', '--reason', 'governed'])).code).toBe(0);

    // A consumer registered through B, watching through B.
    const writerKey = (await adminA.createKey('writer'));
    await adminA.grant(writerKey.principal, ['read', 'write'], '*');
    const consumerKey = await adminA.createKey('storefront');
    await adminA.grant(consumerKey.principal, ['read'], 'ref://prod/*');
    const consumer = await ResolverClient.connect({ url: b.url, apiKey: consumerKey.secret, consumer: { application: 'storefront', environment: 'prod', dependencies: ['ref://prod/search'] } });
    cleanup.push(() => consumer.close());
    const seen: Array<{ revision: number; governance?: string }> = [];
    consumer.watch('ref://prod/search', (e) => seen.push(e));
    await consumer.resolve('ref://prod/search');

    // Without an authorization, through either instance: refused.
    const viaA = await ResolverClient.connect({ url: a.url, apiKey: writerKey.secret, live: false });
    const viaB = await ResolverClient.connect({ url: b.url, apiKey: writerKey.secret, live: false });
    cleanup.push(() => viaA.close(), () => viaB.close());
    const binding = { value: { url: 'https://search-b.example.com' } };
    await expect(viaB.put({ ref: 'ref://prod/search', binding, expectedRevision: 1 })).rejects.toMatchObject({ reason: 'resolver.authorization-required' });

    // The same authorization presented to both instances at once: exactly one commit.
    const jti = 'chg-mp-1';
    const token = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'rc-1', issuer: 'resolver-control', tenant: 'acme', ref: 'ref://prod/search', op: 'put', expectedRevision: 1, request: { kind: 'endpoint', binding }, jti, decision: 'CHG-1' });
    const results = await Promise.allSettled([viaA, viaB].map((c) => c.put({ ref: 'ref://prod/search', binding, expectedRevision: 1, authorization: token })));
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    // The watcher on B hears of it with its governance, whichever instance committed it.
    expect(await waitFor(() => seen.find((e) => e.revision === 2), 10_000)).toMatchObject({ governance: 'authorized' });
    await consumer.resolve('ref://prod/search');

    // Break-glass by the operator, from a CLI process: recorded, and announced to watchers on B.
    expect((await local(['break-glass', 'set', 'ref://prod/search', '--value', '{"url":"https://search-c.example.com"}', '--reason', 'incident 12'])).code).toBe(0);
    expect(await waitFor(() => seen.find((e) => e.revision === 3), 10_000)).toMatchObject({ governance: 'break-glass' });

    // Restart B: the consumed authorization is durable; re-signed with the same jti, it is refused through B.
    await b.stop();
    b = await serve(env, 'B2');
    const viaB2 = await ResolverClient.connect({ url: b.url, apiKey: writerKey.secret, live: false });
    cleanup.push(() => viaB2.close());
    const reused = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'rc-1', issuer: 'resolver-control', tenant: 'acme', ref: 'ref://prod/search', op: 'put', expectedRevision: 3, request: { kind: 'endpoint', binding }, jti });
    await expect(viaB2.put({ ref: 'ref://prod/search', binding, expectedRevision: 3, authorization: reused })).rejects.toMatchObject({ reason: 'resolver.authorization-consumed' });
    const history = (await viaB2.history('ref://prod/search')).entries;
    expect(history.map((e) => e.governance?.mode ?? null)).toEqual([null, 'authorized', 'break-glass']);

    // Adoption of revision 2, read through A: the consumer fetched it through B (observed); nobody reported use.
    const adoption = (await adminA.adoption('ref://prod/search', 2)) as { authorized: { mode: string; decision: string }; fetched: { count: number }; adopted: { count: number }; available: { current: boolean } };
    expect(adoption.authorized).toMatchObject({ mode: 'authorized', decision: 'CHG-1' });
    expect(adoption.fetched.count).toBe(1);
    expect(adoption.adopted.count).toBe(0);
    expect(adoption.available.current).toBe(false);

    const governance = (await adminA.governanceEvents()).events.map((e) => e.type);
    expect(governance).toEqual(expect.arrayContaining(['signing-key.added', 'policy.set', 'break-glass']));
    const integrity = await cli(['verify'], env);
    expect(integrity.code, integrity.stdout + integrity.stderr).toBe(0);
  }, 90_000);
});
