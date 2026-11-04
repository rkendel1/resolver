// RESOLVER_VERIFIER_KEY (`verifierKey`) must reach AppPort Services' API-key verifiers. It is the
// server-held key mixed into every new key's verifier (`hmac-scrypt$…`). It was once passed under a
// name Services does not read, so keys were stored as plain `scrypt$…` and the configured key had no
// effect. Keys stored that way must keep working once the key is applied.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, type ResolverRuntime } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';

const TENANT = 'acme';
const REF = 'ref://prod/cfg/verifier';
const cleanup: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

function place() {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-verifier-'));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const db = createFeltDB({ namespace: `resolver-${randomBytes(4).toString('hex')}`, memory: true });
  cleanup.push(() => db.close());
  return { db, vault: { vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32) } };
}

async function start(p: ReturnType<typeof place>, verifierKey?: string): Promise<{ runtime: ResolverRuntime; url: string }> {
  const runtime = await createResolverRuntime({ state: { db: p.db }, ...p.vault, environment: 'development', ...(verifierKey ? { verifierKey } : {}) });
  const url = (await runtime.serve({ port: 0 })).url.replace(/\/$/, '');
  return { runtime, url };
}

/** Issues a key that may read REF, and makes sure REF exists. */
async function issue(runtime: ResolverRuntime, name: string): Promise<string> {
  const operator = runtime.operator(TENANT);
  const created = await runtime.resolver.createKey(operator, { name });
  await runtime.resolver.grant(operator, { subject: created.principal, actions: ['read'], pattern: REF });
  const existing = await runtime.resolver.list(operator, { prefix: REF });
  if (existing.refs.length === 0) await runtime.resolver.put(operator, { ref: REF, kind: 'value', binding: { value: 'v' }, expectedRevision: 0 });
  return created.secret;
}

async function works(url: string, apiKey: string): Promise<boolean> {
  const client = new ResolverClient({ url, apiKey, live: false });
  try {
    return (await client.resolve(REF)).ref === REF;
  } catch {
    return false;
  } finally {
    await client.close();
  }
}

async function hashes(db: ReturnType<typeof place>['db']): Promise<string[]> {
  const keys = await db.collection<{ secretHash: string }>('api_keys').find({});
  return keys.map((k) => k.secretHash.split('$')[0]!);
}

describe('the verifier key reaches API-key verification', () => {
  it('a new key is stored as hmac-scrypt under the configured key, and only that key verifies it', async () => {
    const p = place();
    const key = randomBytes(32).toString('hex');
    const first = await start(p, key);
    const secret = await issue(first.runtime, 'app');
    expect(await hashes(p.db)).toEqual(['hmac-scrypt']);
    expect(await works(first.url, secret)).toBe(true);
    await first.runtime.close();

    // Same verifier key after a restart: still valid.
    const again = await start(p, key);
    expect(await works(again.url, secret)).toBe(true);
    await again.runtime.close();

    // Another verifier key: the stored verifier no longer matches.
    const other = await start(p, randomBytes(32).toString('hex'));
    expect(await works(other.url, secret)).toBe(false);
    await other.runtime.close();
  });

  it('a key stored without a verifier key (scrypt) keeps working once one is configured', async () => {
    const p = place();
    const before = await start(p);
    const legacy = await issue(before.runtime, 'legacy');
    expect(await hashes(p.db)).toEqual(['scrypt']);
    await before.runtime.close();

    const after = await start(p, randomBytes(32).toString('hex'));
    expect(await works(after.url, legacy)).toBe(true);
    const fresh = await issue(after.runtime, 'fresh');
    expect((await hashes(p.db)).sort()).toEqual(['hmac-scrypt', 'scrypt']);
    expect(await works(after.url, fresh)).toBe(true);
    await after.runtime.close();
  });
});
