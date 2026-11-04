// revealSecret(ref): a secret's material and the revision it belongs to, as one consistent pair, so a
// durable receipt can say exactly which credential a call used. Against the real resolver over HTTP.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createLogger } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';
import { startResolver, waitFor, type Harness } from './harness.js';

const KEY = 'ref://prod/integrations/payments-key';
const material = (n: number) => `pk-${n}-${randomBytes(12).toString('hex')}`;
const code = async (p: Promise<unknown>) => p.then(() => 'OK', (e) => e.code as string);

let harnesses: Harness[] = [];
afterEach(async () => {
  for (const h of harnesses) await h.close();
  harnesses = [];
});
async function start(options: Parameters<typeof startResolver>[0] = {}) {
  const h = await startResolver(options);
  harnesses.push(h);
  return h;
}

describe('revealSecret: material and revision as one result', () => {
  it('1: returns the exact revision of the material it returns', async () => {
    const h = await start();
    const first = material(1);
    const created = await h.admin.put({ ref: KEY, kind: 'secret', secret: first, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read', 'reveal'], KEY]]);
    const revealed = await client.revealSecret(KEY);
    expect(revealed).toEqual({ ref: KEY, revision: created.revision, value: first });
    // The existing API is unchanged: the same material, as a string.
    expect(await client.secret(KEY)).toBe(first);
  });

  it('2: after a rotation, the new revision and the new material arrive together', async () => {
    const h = await start();
    await h.admin.put({ ref: KEY, kind: 'secret', secret: material(1), expectedRevision: 0, ttlSeconds: 300 });
    const { client } = await h.clientWith([[['read', 'reveal'], KEY]]);
    const before = await client.revealSecret(KEY);
    const second = material(2);
    const rotated = await h.admin.set(KEY, { secret: second, ttlSeconds: 300 });
    const after = await waitFor(async () => {
      const r = await client.revealSecret(KEY);
      return r.revision === rotated.revision ? r : undefined;
    });
    expect(before.revision).toBe(1);
    expect(after).toEqual({ ref: KEY, revision: rotated.revision, value: second });
  });

  it('3: under concurrent rotations, every pair a reader sees is a revision with its own material', async () => {
    const h = await start();
    const written = new Map<number, string>();
    const first = material(0);
    written.set((await h.admin.put({ ref: KEY, kind: 'secret', secret: first, expectedRevision: 0, ttlSeconds: 1 })).revision, first);
    // A live reader (notifications) and one with no notifications (TTL only): both cache.
    const live = (await h.clientWith([[['read', 'reveal'], KEY]])).client;
    const polling = (await h.clientWith([[['read', 'reveal'], KEY]], { live: false })).client;
    const seen: Array<{ revision: number; value: string }> = [];
    let writing = true;
    const writer = (async () => {
      for (let n = 1; n <= 40; n++) {
        const next = material(n);
        const result = await h.admin.set(KEY, { secret: next, ttlSeconds: 1 });
        written.set(result.revision, next);
      }
      writing = false;
    })();
    const reader = (client: ResolverClient) =>
      (async () => {
        while (writing) {
          const r = await client.revealSecret(KEY);
          seen.push({ revision: r.revision, value: r.value });
          // A cached answer settles in microtasks; yield so the writer's requests make progress.
          await new Promise((resolve) => setImmediate(resolve));
        }
      })();
    await Promise.all([writer, reader(live), reader(polling), reader(live)]);
    expect(written.size).toBe(41);
    expect(seen.length).toBeGreaterThan(40);
    const mismatched = seen.filter((p) => written.get(p.revision) !== p.value);
    expect(mismatched).toEqual([]);
    expect(new Set(seen.map((p) => p.revision)).size).toBeGreaterThan(1); // readers did see rotations
  });

  it('4: removing reveal stops it (and secret()) for that key; a fresh client is refused at once', async () => {
    const h = await start();
    await h.admin.put({ ref: KEY, kind: 'secret', secret: material(1), expectedRevision: 0 });
    const { client, principal, key } = await h.clientWith([[['read'], KEY], [['reveal'], KEY]]);
    await client.revealSecret(KEY);
    const reveal = (await h.admin.grants()).grants.find((g) => g.subject === principal && g.actions.includes('reveal'))!;
    await h.admin.ungrant(reveal.id);
    const fresh = await ResolverClient.connect({ url: h.url, apiKey: key, live: false });
    try {
      expect(await code(fresh.revealSecret(KEY))).toBe('FORBIDDEN');
      expect(await code(fresh.secret(KEY))).toBe('FORBIDDEN');
      expect((await fresh.resolve(KEY)).revision).toBe(1); // read remains
    } finally {
      await fresh.close();
    }
  });

  it('5: a cached credential is dropped on the authority-change notification, well before its TTL', async () => {
    const h = await start();
    await h.admin.put({ ref: KEY, kind: 'secret', secret: material(1), expectedRevision: 0, ttlSeconds: 300 });
    const { client, principal } = await h.clientWith([[['read'], KEY], [['reveal'], KEY]]);
    await client.revealSecret(KEY); // cached for 300 s
    const reveal = (await h.admin.grants()).grants.find((g) => g.subject === principal && g.actions.includes('reveal'))!;
    const removedAt = Date.now();
    await h.admin.ungrant(reveal.id);
    await waitFor(async () => ((await code(client.revealSecret(KEY))) === 'FORBIDDEN' ? true : undefined), 5000);
    expect(Date.now() - removedAt).toBeLessThan(5000);
  });

  it('6: with no notification (a client that does not watch), the cache is bounded by the TTL', async () => {
    const h = await start();
    const ttlSeconds = 2;
    await h.admin.put({ ref: KEY, kind: 'secret', secret: material(1), expectedRevision: 0, ttlSeconds });
    const { client, principal } = await h.clientWith([[['read'], KEY], [['reveal'], KEY]], { live: false });
    const cachedAt = Date.now();
    await client.revealSecret(KEY);
    const reveal = (await h.admin.grants()).grants.find((g) => g.subject === principal && g.actions.includes('reveal'))!;
    await h.admin.ungrant(reveal.id);
    // The documented bound: a client that missed the change may answer from cache until the TTL ends…
    if (Date.now() - cachedAt < ttlSeconds * 1000 - 300) expect(await code(client.revealSecret(KEY))).toBe('OK');
    // …and never after it.
    await new Promise((r) => setTimeout(r, Math.max(0, cachedAt + ttlSeconds * 1000 + 200 - Date.now())));
    expect(await code(client.revealSecret(KEY))).toBe('FORBIDDEN');
  });

  it('7: the material is in no log line and no stored record; only the vault holds it, sealed', async () => {
    const lines: string[] = [];
    const h = await start({ local: true, runtime: { logger: createLogger({ instance: 'test', level: 'debug', write: (l) => lines.push(l) }) } });
    const values = [material(1), material(2)];
    await h.admin.put({ ref: KEY, kind: 'secret', secret: values[0]!, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read', 'reveal'], KEY]]);
    await client.revealSecret(KEY);
    await h.admin.set(KEY, { secret: values[1]! });
    await waitFor(async () => ((await client.revealSecret(KEY)).value === values[1] ? true : undefined));
    expect((await h.admin.history(KEY)).entries.length).toBe(2);
    expect(lines.length).toBeGreaterThan(0);
    const files: string[] = [];
    const walk = (dir: string) => readdirSync(dir).forEach((n) => (statSync(path.join(dir, n)).isDirectory() ? walk(path.join(dir, n)) : files.push(path.join(dir, n))));
    walk(h.dir);
    expect(files.some((f) => f.includes(`${path.sep}vault${path.sep}`))).toBe(true);
    for (const value of values) {
      expect(lines.filter((l) => l.includes(value))).toEqual([]);
      expect(files.filter((f) => readFileSync(f).includes(value))).toEqual([]);
    }
  });
});
