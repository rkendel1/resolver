// The multi-instance acceptance scenario with real processes: two `resolver serve` processes (the built
// CLI) over one shared state and one shared vault, as behind a load balancer. Nothing is shared between
// them but the state and the vault directory.
//
// Runs against local state opened `shared` (several processes on one host; always) and against a real
// FeltDB server (several hosts; when FELTDB_SERVER_BIN is set). Needs `npm run build` first.
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, describe, expect, it } from 'vitest';
import { ResolverClient } from '@appport/resolver-client';
import { FELTDB_SERVER_BIN, freePort, startFeltdbServer, type FeltdbServer } from './feltdb-server.js';
import { waitFor } from './harness.js';

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const run = promisify(execFile);
const cleanup: Array<() => Promise<unknown>> = [];
afterAll(async () => {
  for (const task of cleanup.splice(0).reverse()) await task().catch(() => undefined);
});

async function cli(args: string[], env: Record<string, string>, stdin?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [CLI, ...args], { env: { ...process.env, ...env } }, (error, stdout, stderr) =>
      resolve({ code: error ? ((error as { code?: number }).code ?? 1) : 0, stdout, stderr }),
    );
    if (stdin !== undefined) child.stdin!.end(stdin);
  });
}

interface Instance {
  url: string;
  logs: string[];
  stop(): Promise<void>;
}

async function serve(env: Record<string, string>, name: string): Promise<Instance> {
  const port = await freePort();
  const child: ChildProcess = spawn(process.execPath, [CLI, 'serve', '--port', String(port)], { env: { ...process.env, ...env, RESOLVER_INSTANCE_ID: name }, stdio: ['ignore', 'pipe', 'pipe'] });
  const logs: string[] = [];
  child.stdout!.on('data', (d: Buffer) => logs.push(...d.toString('utf8').split('\n').filter(Boolean)));
  child.stderr!.on('data', (d: Buffer) => logs.push(...d.toString('utf8').split('\n').filter(Boolean)));
  const url = `http://127.0.0.1:${port}`;
  await waitFor(async () => {
    if (child.exitCode !== null) throw new Error(`${name} exited: ${logs.join('\n')}`);
    return fetch(`${url}/_resolver/health`).then((r) => (r.ok ? true : undefined), () => undefined);
  }, 15_000);
  const instance = {
    url,
    logs,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      await new Promise((r) => child.once('exit', r));
    },
  };
  cleanup.push(() => instance.stop());
  return instance;
}

const step = (name: string) => void (process.env['RESOLVER_TEST_TRACE'] && process.stderr.write(`[step ${name} ${new Date().toISOString()}]\n`));
const ready = async (instance: Instance) => (await fetch(`${instance.url}/_resolver/ready`)).status;

const BACKENDS: Array<{ name: string; enabled: boolean; state: () => Promise<{ env: Record<string, string>; server?: FeltdbServer }> }> = [
  { name: 'local state shared by two processes', enabled: true, state: async () => ({ env: { RESOLVER_STATE_SHARED: '1' } }) },
  {
    name: 'FeltDB server',
    enabled: FELTDB_SERVER_BIN !== undefined,
    state: async () => {
      const server = await startFeltdbServer();
      cleanup.push(() => server.stop());
      return { env: { RESOLVER_FELTDB_URL: server.url }, server };
    },
  },
];

for (const backend of BACKENDS) {
  describe.skipIf(!backend.enabled || !existsSync(CLI))(`two resolver processes (${backend.name})`, () => {
    it('acceptance: converge, deny, revoke, restart, survive an interruption, restore with integrity, refuse internal destinations', async () => {
      const dir = mkdtempSync(path.join(tmpdir(), 'resolver-mp-'));
      cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
      const { env: stateEnv, server: feltdb } = await backend.state();
      const env: Record<string, string> = {
        ...stateEnv,
        RESOLVER_DIR: dir,
        RESOLVER_VAULT_DIR: path.join(dir, 'vault'),
        RESOLVER_MULTI_INSTANCE: '1',
        RESOLVER_ENV: 'production',
        RESOLVER_SYNC_INTERVAL_MS: '100',
        RESOLVER_LOG_LEVEL: 'info',
      };
      const init = await cli(['init', '--tenant', 'acme'], env);
      expect(init.code, init.stderr).toBe(0);
      const adminKey = init.stdout.trim();

      step('1');
      // 1. Start A and B.
      const a = await serve(env, 'A');
      let b = await serve(env, 'B');
      expect([await ready(a), await ready(b)]).toEqual([200, 200]);
      const adminA = await ResolverClient.connect({ url: a.url, apiKey: adminKey, live: false });
      const adminB = await ResolverClient.connect({ url: b.url, apiKey: adminKey, live: false });
      cleanup.push(() => adminA.close(), () => adminB.close());

      step('2-3');
      // 2-3. Create through A, resolve through B.
      await adminA.put({ ref: 'ref://prod/cfg/flag', kind: 'value', binding: { value: 'v1' }, expectedRevision: 0, ttlSeconds: 3600 });
      expect(await adminB.get('ref://prod/cfg/flag')).toBe('v1');

      step('4-5');
      // 4-5. Update through A; an application connected to B (live, TTL one hour) converges on its own.
      const appKey = await adminA.createKey('app');
      const grant = await adminA.grant(appKey.principal, ['read'], 'ref://prod/*');
      const app = await ResolverClient.connect({ url: b.url, apiKey: appKey.secret, maxStaleSeconds: 0 });
      cleanup.push(() => app.close());
      expect(await app.get('ref://prod/cfg/flag')).toBe('v1');
      await new Promise((r) => setTimeout(r, 300)); // subscribed
      await adminA.put({ ref: 'ref://prod/cfg/flag', binding: { value: 'v2' }, expectedRevision: 1 });
      await waitFor(async () => ((await app.get('ref://prod/cfg/flag')) === 'v2' ? true : undefined), 5000);

      step('6-7');
      // 6-7. Remove the grant through A; B denies the application's next request.
      await adminA.ungrant(grant.id);
      await expect(app.resolve('ref://prod/cfg/flag', { revision: 99 })).rejects.toMatchObject({ code: 'FORBIDDEN' });
      await waitFor(async () => (await app.get('ref://prod/cfg/flag').then(() => undefined, (e) => e)), 5000);
      await expect(app.get('ref://prod/cfg/flag')).rejects.toMatchObject({ code: 'FORBIDDEN' });
      await adminA.grant(appKey.principal, ['read', 'reveal'], 'ref://prod/*');

      step('8-9');
      // 8-9. Revoke through A; B no longer resolves it, for the admin or the application.
      await adminA.put({ ref: 'ref://prod/cfg/doomed', kind: 'value', binding: { value: 'x' }, expectedRevision: 0, ttlSeconds: 3600 });
      expect(await app.get('ref://prod/cfg/doomed')).toBe('x');
      await adminA.revoke('ref://prod/cfg/doomed', 1, 'test');
      await expect(adminB.get('ref://prod/cfg/doomed')).rejects.toMatchObject({ reason: 'resolver.revoked' });
      await waitFor(async () => (await app.get('ref://prod/cfg/doomed').then(() => undefined, (e) => e)), 5000);

      // Secrets: written through A and B at once; both instances reveal the one that won.
      await adminA.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: 'sk-first', expectedRevision: 0 });
      const writes = await Promise.all([
        adminA.put({ ref: 'ref://prod/llm/key', secret: 'sk-from-a', expectedRevision: 1 }).then(() => 'sk-from-a', () => null),
        adminB.put({ ref: 'ref://prod/llm/key', secret: 'sk-from-b', expectedRevision: 1 }).then(() => 'sk-from-b', () => null),
      ]);
      const winner = writes.find(Boolean)!;
      expect(writes.filter(Boolean)).toHaveLength(1);
      expect(await adminA.secret('ref://prod/llm/key')).toBe(winner);
      expect(await adminB.secret('ref://prod/llm/key')).toBe(winner);

      step('10-11');
      // 10-11. Restart B; changes made while it was down are served when it is back.
      await b.stop();
      await adminA.put({ ref: 'ref://prod/cfg/flag', binding: { value: 'v3' }, expectedRevision: 2 });
      b = await serve(env, 'B2');
      expect(await ready(b)).toBe(200);
      const adminB2 = await ResolverClient.connect({ url: b.url, apiKey: adminKey, live: false });
      cleanup.push(() => adminB2.close());
      expect(await adminB2.get('ref://prod/cfg/flag')).toBe('v3');

      step('12');
      // 12. Interrupt the state store: B reports not ready and answers nothing it cannot read, rather than
      //     a stale or advanced state; once the store is back, B catches up.
      if (feltdb) {
        feltdb.pause();
        step('12 paused');
        try {
          await waitFor(async () => ((await ready(b)) === 503 ? true : undefined), 15_000);
          step('12 not ready seen');
          const strict = new ResolverClient({ url: b.url, apiKey: adminKey, live: false, maxStaleSeconds: 0, timeoutMs: 1500 });
          await expect(strict.get('ref://prod/cfg/flag')).rejects.toBeTruthy();
          await strict.close();
          step('12 strict refused');
        } finally {
          feltdb.resume();
        }
        step('12 resumed');
        await adminA.put({ ref: 'ref://prod/cfg/flag', binding: { value: 'v4' }, expectedRevision: 3 });
        step('12 written after resume');
        await waitFor(async () => ((await ready(b)) === 200 ? true : undefined), 15_000);
        step('12 ready again');
        // A fresh client: what B serves now, not what an earlier client cached (TTL one hour, not live).
        const fresh = await ResolverClient.connect({ url: b.url, apiKey: adminKey, live: false });
        expect(await fresh.get('ref://prod/cfg/flag')).toBe('v4');
        await fresh.close();
      }

      // Prohibited internal destinations: an agent reference pointing at this host is refused before any
      // request, through either instance, on create and on rollback.
      let hits = 0;
      const internal: Server = createServer((_q, s) => {
        hits += 1;
        s.end('{}');
      });
      await new Promise<void>((r) => internal.listen(0, '127.0.0.1', () => r()));
      cleanup.push(() => new Promise((r) => internal.close(r)));
      const origin = `http://127.0.0.1:${(internal.address() as { port: number }).port}`;
      for (const client of [adminA, adminB2]) {
        await expect(client.put({ ref: 'ref://prod/agents/internal', kind: 'agent', binding: { value: { origin } }, expectedRevision: 0 })).rejects.toMatchObject({ reason: 'resolver.outbound-refused' });
      }
      expect(hits).toBe(0);

      step('13');
      // 13. Back up while both instances run, restore into an empty state and vault, verify, and serve it.
      const backupDir = path.join(dir, 'backup');
      const backup = await cli(['backup', backupDir], env);
      expect(backup.code, backup.stderr).toBe(0);
      // A tampered backup is refused.
      const tampered = path.join(dir, 'tampered');
      await run('cp', ['-r', backupDir, tampered]);
      const grantsFile = path.join(tampered, 'state', 'resolver_grants.jsonl');
      writeFileSync(grantsFile, readFileSync(grantsFile, 'utf8') + '{"id":"forged"}\n');
      const restoredDir = mkdtempSync(path.join(tmpdir(), 'resolver-restored-'));
      cleanup.push(async () => rmSync(restoredDir, { recursive: true, force: true }));
      const restoreEnv: Record<string, string> = {
        RESOLVER_DIR: restoredDir,
        RESOLVER_VAULT_DIR: path.join(restoredDir, 'vault'),
        RESOLVER_VAULT_KEY: readFileSync(path.join(dir, 'vault.key'), 'utf8').trim(),
        RESOLVER_VERIFIER_KEY: readFileSync(path.join(dir, 'verifier.key'), 'utf8').trim(),
        RESOLVER_ENV: 'production',
        RESOLVER_LOG_LEVEL: 'off',
        ...(feltdb ? { RESOLVER_FELTDB_URL: (await startRestoreServer()).url } : {}),
      };
      const refused = await cli(['restore', tampered], restoreEnv);
      expect(refused.code).not.toBe(0);
      expect(refused.stderr).toMatch(/does not match the manifest/);
      const restore = await cli(['restore', backupDir], restoreEnv);
      expect(restore.code, restore.stderr + restore.stdout).toBe(0);
      expect(JSON.parse(restore.stdout).integrity.ok).toBe(true);
      expect((await cli(['verify'], restoreEnv)).code).toBe(0);
      const restored = await serve({ ...restoreEnv, RESOLVER_VERIFY_ON_START: '1', RESOLVER_LOG_LEVEL: 'info' }, 'restored');
      expect(await ready(restored)).toBe(200);
      const fromRestore = await ResolverClient.connect({ url: restored.url, apiKey: adminKey, live: false });
      cleanup.push(() => fromRestore.close());
      expect(await fromRestore.get('ref://prod/cfg/flag')).toBe(feltdb ? 'v4' : 'v3');
      expect(await fromRestore.secret('ref://prod/llm/key')).toBe(winner);
      await expect(fromRestore.get('ref://prod/cfg/doomed')).rejects.toMatchObject({ reason: 'resolver.revoked' });

      // Logs: structured, from both instances, and never carrying a key or secret.
      const all = [...a.logs, ...b.logs, ...restored.logs].join('\n');
      expect(all).toContain('"event":"call"');
      for (const forbidden of [adminKey, appKey.secret, 'sk-first', 'sk-from-a', 'sk-from-b']) expect(all).not.toContain(forbidden);
    }, 180_000);
  });
}

async function startRestoreServer(): Promise<FeltdbServer> {
  const server = await startFeltdbServer();
  cleanup.push(() => server.stop());
  return server;
}
