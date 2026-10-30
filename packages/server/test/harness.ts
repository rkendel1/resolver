import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { createResolverRuntime, type ResolverRuntime, type ResolverRuntimeOptions } from '@appport/resolver';
import { ResolverClient, type ResolverClientOptions } from '@appport/resolver-client';

export const TENANT = 'acme';

export interface Harness {
  runtime: ResolverRuntime;
  url: string;
  dir: string;
  /** An admin key (grant: admin on *) and a client using it. */
  admin: ResolverClient;
  adminKey: string;
  /** Issues a key with the given grants and returns a client for it. */
  clientWith(grants: Array<[string[], string]>, options?: Partial<ResolverClientOptions>): Promise<{ client: ResolverClient; principal: string; key: string }>;
  close(): Promise<void>;
}

export async function startResolver(options: { local?: boolean; runtime?: Partial<ResolverRuntimeOptions> } = {}): Promise<Harness> {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-test-'));
  const runtime = await createResolverRuntime({
    state: options.local ? { local: dir } : { memory: true },
    // Agent fixtures run on loopback; the SSRF tests configure production explicitly.
    environment: 'development',
    vaultDirectory: path.join(dir, 'vault'),
    vaultKey: randomBytes(32),
    verifierKey: randomBytes(32).toString('hex'),
    targets: { verifyAgents: true, agentTimeoutMs: 2000 },
    ...options.runtime,
  });
  const server = await runtime.serve({ port: 0 });
  const url = server.url.replace(/\/$/, '');
  const operator = runtime.operator(TENANT);
  const created = await runtime.resolver.createKey(operator, { name: 'admin' });
  await runtime.resolver.grant(operator, { subject: created.principal, actions: ['admin', 'read', 'write', 'reveal'], pattern: '*' });
  const clients: ResolverClient[] = [];
  const admin = await ResolverClient.connect({ url, apiKey: created.secret, live: false });
  clients.push(admin);
  return {
    runtime,
    url,
    dir,
    admin,
    adminKey: created.secret,
    async clientWith(grants, clientOptions = {}) {
      const key = await admin.createKey(`k-${randomBytes(3).toString('hex')}`);
      for (const [actions, pattern] of grants) await admin.grant(key.principal, actions, pattern);
      const client = await ResolverClient.connect({ url, apiKey: key.secret, ...clientOptions });
      clients.push(client);
      return { client, principal: key.principal, key: key.secret };
    },
    async close() {
      for (const c of clients) await c.close().catch(() => undefined);
      await runtime.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

export async function waitFor<T>(probe: () => Promise<T | undefined> | T | undefined, timeoutMs = 5000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = await probe();
    if (value !== undefined) return value;
    if (Date.now() - start > timeoutMs) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 25));
  }
}
