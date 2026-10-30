// Two independent resolver instances over one shared state: they learn of each other's changes through
// the change sequence (sync.ts), never through a shared process. Each scenario runs against
// - two runtimes sharing one FeltDB handle (always), and
// - two runtimes with their own connections to a real FeltDB server (when FELTDB_SERVER_BIN is set).
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, type ResolverRuntime, type ResolverRuntimeOptions } from '@appport/resolver';
import type { ChangeEvent } from '@appport/resolver-core';
import { ResolverClient } from '@appport/resolver-client';
import { FELTDB_SERVER_BIN, startFeltdbServer } from './feltdb-server.js';
import { TENANT, waitFor } from './harness.js';

const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task().catch(() => undefined);
});

interface Pair {
  open(name: string): Promise<ResolverRuntime>;
  a: ResolverRuntime;
  b: ResolverRuntime;
}

const BACKENDS: Array<{ name: string; state: () => Promise<ResolverRuntimeOptions['state'] & object>; enabled: boolean }> = [
  {
    name: 'shared FeltDB handle',
    enabled: true,
    state: async () => {
      const db = createFeltDB({ namespace: `resolver-sync-${randomBytes(4).toString('hex')}`, memory: true });
      cleanup.push(async () => db.close());
      return { db };
    },
  },
  {
    name: 'FeltDB server',
    enabled: FELTDB_SERVER_BIN !== undefined,
    state: async () => {
      const server = await startFeltdbServer();
      cleanup.push(() => server.stop());
      return { remote: { url: server.url } };
    },
  },
];

async function pair(state: ResolverRuntimeOptions['state'], extra: Partial<ResolverRuntimeOptions> = {}): Promise<Pair> {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-sync-'));
  cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
  const shared = {
    vaultDirectory: path.join(dir, 'vault'),
    vaultKey: randomBytes(32),
    verifierKey: randomBytes(32).toString('hex'),
    environment: 'development' as const,
    sync: { intervalMs: 50, gapTimeoutMs: 400, staleAfterMs: 500 },
  };
  const open = async (name: string) => {
    // A shared handle must not be closed by either runtime; a remote one is each runtime's own connection.
    const runtime = await createResolverRuntime({ state, ...shared, instanceId: name, ...extra, ...(('remote' in state) ? { multiInstance: true } : {}) });
    cleanup.push(() => runtime.close());
    return runtime;
  };
  return { open, a: await open('A'), b: await open('B') };
}

/** Collects the change notifications a watcher on `runtime` receives. */
function watcher(runtime: ResolverRuntime) {
  const events: ChangeEvent[] = [];
  const abort = new AbortController();
  let ended = false;
  void (async () => {
    for await (const event of runtime.resolver.watch(runtime.operator(TENANT), { prefix: 'ref://' }, abort.signal)) events.push(event);
    ended = true;
  })();
  cleanup.push(async () => abort.abort());
  return { events, get ended() { return ended; }, stop: () => abort.abort() };
}

const op = (r: ResolverRuntime) => r.operator(TENANT);
const until = <T>(probe: () => T | undefined | false, ms = 5000) => waitFor(async () => probe() || undefined, ms);

for (const backend of BACKENDS) {
  describe.skipIf(!backend.enabled)(`two instances over one state (${backend.name})`, () => {
    it('1-2: a change through A reaches B\'s watchers and B\'s reads', async () => {
      const { a, b } = await pair(await backend.state());
      const seenOnB = watcher(b);
      await a.resolver.put(op(a), { ref: 'ref://prod/cfg/x', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      await a.resolver.put(op(a), { ref: 'ref://prod/cfg/x', binding: { value: 2 }, expectedRevision: 1 });
      expect((await b.resolver.resolve(op(b), { ref: 'ref://prod/cfg/x' })).selected.value).toBe(2);
      await until(() => seenOnB.events.length === 2);
      expect(seenOnB.events.map((e) => e.revision)).toEqual([1, 2]);
      const sequence = await a.store.sequence();
      await until(() => b.sync.status.applied === sequence);
    });

    it('3-4: a revocation through A stops resolution on B, and B\'s watchers hear of it', async () => {
      const { a, b } = await pair(await backend.state());
      await a.resolver.put(op(a), { ref: 'ref://prod/cfg/r', kind: 'value', binding: { value: 'v' }, expectedRevision: 0 });
      const seenOnB = watcher(b);
      await a.resolver.revoke(op(a), { ref: 'ref://prod/cfg/r', expectedRevision: 1 });
      await expect(b.resolver.resolve(op(b), { ref: 'ref://prod/cfg/r' })).rejects.toMatchObject({ reason: 'resolver.revoked' });
      await until(() => seenOnB.events.some((e) => e.state === 'revoked'));
    });

    it('3-4: a live client connected to B drops a reference revoked through A, well before its TTL', async () => {
      const { a, b } = await pair(await backend.state());
      const server = await b.serve({ port: 0 });
      const key = await b.resolver.createKey(op(b), { name: 'app' });
      await b.resolver.grant(op(b), { subject: key.principal, actions: ['read'], pattern: '*' });
      await a.resolver.put(op(a), { ref: 'ref://prod/cfg/long', kind: 'value', binding: { value: 'v' }, expectedRevision: 0, ttlSeconds: 3600 });
      const client = await ResolverClient.connect({ url: server.url.replace(/\/$/, ''), apiKey: key.secret });
      cleanup.push(() => client.close());
      expect(await client.get('ref://prod/cfg/long')).toBe('v');
      await new Promise((r) => setTimeout(r, 200)); // subscribed
      await a.resolver.revoke(op(a), { ref: 'ref://prod/cfg/long', expectedRevision: 1 });
      await waitFor(async () => (await client.get('ref://prod/cfg/long').then(() => undefined, (e) => e)), 5000);
      await expect(client.get('ref://prod/cfg/long')).rejects.toMatchObject({ reason: 'resolver.revoked' });
    });

    it('5: a grant removed through A is enforced by B on the next request', async () => {
      const { a, b } = await pair(await backend.state());
      await a.resolver.put(op(a), { ref: 'ref://prod/cfg/g', kind: 'value', binding: { value: 'v' }, expectedRevision: 0 });
      const key = await a.resolver.createKey(op(a), { name: 'app' });
      const grant = await a.resolver.grant(op(a), { subject: key.principal, actions: ['read'], pattern: 'ref://prod/*' });
      const viaB = await b.services.apiKeys.authenticateApiKey(key.secret);
      expect((await b.resolver.resolve(viaB!, { ref: 'ref://prod/cfg/g' })).selected.value).toBe('v');
      await a.resolver.ungrant(op(a), { id: grant.id });
      await expect(b.resolver.resolve(viaB!, { ref: 'ref://prod/cfg/g' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    });

    it('6: concurrent secret updates through A and B converge: one wins, both instances reveal it, no orphan', async () => {
      const { a, b } = await pair(await backend.state());
      const ref = 'ref://prod/llm/key';
      await a.resolver.put(op(a), { ref, kind: 'secret', secret: 'one', expectedRevision: 0 });
      const results = await Promise.all([
        a.resolver.put(op(a), { ref, secret: 'from-a', expectedRevision: 1 }).then(() => 'from-a', () => null),
        b.resolver.put(op(b), { ref, secret: 'from-b', expectedRevision: 1 }).then(() => 'from-b', () => null),
      ]);
      const winners = results.filter(Boolean);
      expect(winners).toHaveLength(1);
      const [onA, onB] = await Promise.all([a, b].map((r) => r.resolver.resolve(op(r), { ref, reveal: true })));
      expect(onA!.secret).toBe(winners[0]);
      expect(onB!.secret).toBe(winners[0]);
      expect(onA!.revision).toBe(onB!.revision);
      // The losing writer's material was discarded, not left in the shared vault.
      const report = await a.integrity();
      expect(report.ok).toBe(true);
      expect(report.warnings.filter((w) => w.warning === 'orphan-version')).toEqual([]);
    });

    it('7: an instance that restarts serves the current state and resumes following changes', async () => {
      const p = await pair(await backend.state());
      await p.a.resolver.put(op(p.a), { ref: 'ref://prod/cfg/r', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      await p.b.close();
      // Changed while B is down.
      await p.a.resolver.put(op(p.a), { ref: 'ref://prod/cfg/r', binding: { value: 2 }, expectedRevision: 1 });
      const b = await p.open('B-restarted');
      expect(b.sync.status.applied).toBe(await b.store.sequence());
      expect((await b.resolver.resolve(op(b), { ref: 'ref://prod/cfg/r' })).selected.value).toBe(2);
      expect((await b.readiness()).ready).toBe(true);
      const seen = watcher(b);
      await p.a.resolver.put(op(p.a), { ref: 'ref://prod/cfg/r', binding: { value: 3 }, expectedRevision: 2 });
      await until(() => seen.events.some((e) => e.revision === 3));
    });

    it('9: concurrent writes through both instances: every revision reaches both, in order, exactly once', async () => {
      const { a, b } = await pair(await backend.state());
      const seenOnA = watcher(a);
      const seenOnB = watcher(b);
      const refs = ['ref://prod/c/0', 'ref://prod/c/1', 'ref://prod/c/2'];
      const writer = async (r: ResolverRuntime) => {
        for (let i = 0; i < 8; i++) {
          for (const ref of refs) {
            for (;;) {
              const current = await r.store.reference(TENANT, ref);
              try {
                await r.resolver.put(op(r), { ref, ...(current ? {} : { kind: 'value' }), binding: { value: i }, expectedRevision: current?.revision ?? 0 });
                break;
              } catch (error) {
                if ((error as { reason?: string }).reason !== 'resolver.stale-revision') throw error;
              }
            }
          }
        }
      };
      await Promise.all([writer(a), writer(b)]);
      const total = 2 * 8 * refs.length;
      expect(await a.store.sequence()).toBe(total);
      for (const seen of [seenOnA, seenOnB]) {
        await until(() => seen.events.length >= total, 10_000);
        await new Promise((r) => setTimeout(r, 200)); // nothing extra arrives
        expect(seen.events).toHaveLength(total);
        for (const ref of refs) {
          const revisions = seen.events.filter((e) => e.ref === ref).map((e) => e.revision);
          expect(revisions).toEqual(Array.from({ length: 16 }, (_, i) => i + 1));
        }
      }
      await until(() => a.sync.status.applied === total && b.sync.status.applied === total);
    });
  });
}

describe('sync failures (fault injection)', () => {
  const shared = BACKENDS[0]!;

  it('8: a failed pass does not advance the applied position; the next pass delivers every change in order', async () => {
    const { a, b } = await pair(await shared.state());
    const seen = watcher(b);
    const real = b.store.changesAfter.bind(b.store);
    let failing = true;
    b.store.changesAfter = async (after: number, limit: number) => {
      if (failing) throw Object.assign(new Error('injected'), { code: 'UNAVAILABLE' });
      return real(after, limit);
    };
    const before = b.sync.status.applied;
    for (let i = 1; i <= 3; i++) await a.resolver.put(op(a), { ref: `ref://prod/f/${i}`, kind: 'value', binding: { value: i }, expectedRevision: 0 });
    await until(() => b.sync.status.consecutiveFailures >= 3);
    expect(b.sync.status.applied).toBe(before);
    expect(seen.events).toEqual([]);
    // Reads never depended on it.
    expect((await b.resolver.resolve(op(b), { ref: 'ref://prod/f/3' })).selected.value).toBe(3);
    // Failing long enough, the instance says it is not ready (a load balancer stops routing to it).
    await until(() => !b.sync.healthy, 3000);
    expect((await b.readiness()).ready).toBe(false);
    failing = false;
    await until(() => b.sync.status.applied === before + 3);
    expect(seen.events.map((e) => e.ref)).toEqual(['ref://prod/f/1', 'ref://prod/f/2', 'ref://prod/f/3']);
    await until(() => b.sync.healthy);
    expect((await b.readiness()).ready).toBe(true);
  });

  it('8: a pass that fails halfway keeps the changes it delivered and resumes after them', async () => {
    // Passes are driven by hand: the automatic interval is far away.
    const { a, b } = await pair(await shared.state(), { sync: { intervalMs: 3_600_000, staleAfterMs: 3_600_000 } });
    const seen = watcher(b);
    const real = b.store.changesAfter.bind(b.store);
    let calls = 0;
    // The first read returns one row, the second fails: the state went away in the middle of a pass.
    b.store.changesAfter = async (after: number, limit: number) => {
      calls += 1;
      if (calls === 1) return (await real(after, limit)).slice(0, 1);
      if (calls === 2) throw Object.assign(new Error('injected'), { code: 'UNAVAILABLE' });
      return real(after, limit);
    };
    const before = b.sync.status.applied;
    for (let i = 1; i <= 3; i++) await a.resolver.put(op(a), { ref: `ref://prod/h/${i}`, kind: 'value', binding: { value: i }, expectedRevision: 0 });
    await b.sync.pass();
    expect(b.sync.status.applied).toBe(before + 1);
    expect(b.sync.status.consecutiveFailures).toBe(1);
    await until(() => seen.events.length === 1);
    await b.sync.pass();
    expect(b.sync.status.applied).toBe(before + 3);
    await until(() => seen.events.length === 3);
    expect(seen.events.map((e) => e.ref)).toEqual(['ref://prod/h/1', 'ref://prod/h/2', 'ref://prod/h/3']);
  });

  it('applying the same revisions twice notifies once', async () => {
    const { a, b } = await pair(await shared.state());
    const seen = watcher(b);
    const real = b.store.changesAfter.bind(b.store);
    b.store.changesAfter = async (after: number, limit: number) => {
      const rows = await real(after, limit);
      return [...rows, ...rows, ...rows]; // duplicates, as several readers could see
    };
    await a.resolver.put(op(a), { ref: 'ref://prod/d/1', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
    await a.resolver.put(op(a), { ref: 'ref://prod/d/1', binding: { value: 2 }, expectedRevision: 1 });
    await until(() => b.sync.status.applied >= 2);
    await new Promise((r) => setTimeout(r, 200));
    expect(seen.events.map((e) => e.revision)).toEqual([1, 2]);
  });

  it('a missing sequence number is waited for, then watchers are resynchronized rather than silently skipped', async () => {
    const { a, b } = await pair(await shared.state());
    const seen = watcher(b);
    const real = b.store.changesAfter.bind(b.store);
    const start = await b.store.sequence();
    b.store.changesAfter = async (after: number, limit: number) => (await real(after, limit)).filter((r) => r.seq !== start + 1);
    await a.resolver.put(op(a), { ref: 'ref://prod/g/1', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
    await a.resolver.put(op(a), { ref: 'ref://prod/g/2', kind: 'value', binding: { value: 2 }, expectedRevision: 0 });
    // Not before the gap timeout: nothing is delivered past the missing number.
    await new Promise((r) => setTimeout(r, 150));
    expect(b.sync.status.applied).toBe(start);
    expect(seen.events).toEqual([]);
    // After it: the watch stream ends (clients revalidate everything), and the instance moves on.
    await until(() => seen.ended, 3000);
    await until(() => b.sync.status.applied === start + 2);
    expect(b.sync.status.resyncs).toBe(1);
  });

  it('readiness reports a state store that does not answer', async () => {
    const { b } = await pair(await shared.state());
    const real = b.store.sequence.bind(b.store);
    let down = true;
    b.store.sequence = async () => {
      if (down) throw Object.assign(new Error('down'), { code: 'UNAVAILABLE' });
      return real();
    };
    const report = await b.readiness();
    expect(report.ready).toBe(false);
    expect(report.checks.state).toMatchObject({ ok: false, error: 'UNAVAILABLE' });
    down = false;
    await until(() => b.sync.healthy);
    expect((await b.readiness()).ready).toBe(true);
  });
});
