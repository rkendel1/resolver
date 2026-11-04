// Resolver requires versioned custody (VersionedCustody): every revision reveals exactly the material it
// was written with. A latest-only custody is refused before anything starts; there is no fallback that
// could pair a revision with another revision's material.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, GrantAuthorizer, Resolver, ResolverStore, createVault, requireVersionedCustody, type ResolverRuntime } from '@appport/resolver';

const cleanup: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
  for (const step of cleanup.splice(0).reverse()) await step();
});

/** A custody that keeps only the latest value, as AppPort Services' SecretCustody allows. */
const latestOnly = () => {
  let current: { value: string; version: number } | undefined;
  return {
    async withSecret(_input: unknown, use: (s: { value: string; secretId: string; version: number }) => unknown) {
      if (!current) throw new Error('missing');
      return use({ value: current.value, secretId: 'x', version: current.version });
    },
    async store(input: { value: string }) {
      current = { value: input.value, version: (current?.version ?? 0) + 1 };
      return { version: current.version, storedAt: new Date().toISOString() };
    },
    async status() {
      return current ? { state: 'set' as const, version: current.version, writable: true } : { state: 'missing' as const, writable: true };
    },
  };
};

function dir() {
  const d = mkdtempSync(path.join(tmpdir(), 'resolver-custody-'));
  cleanup.push(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

describe('versioned custody is required', () => {
  it('a runtime given a latest-only custody refuses to start, naming withSecretVersion', async () => {
    await expect(createResolverRuntime({ state: { memory: true }, environment: 'development', custody: latestOnly() as never })).rejects.toThrow(/withSecretVersion/);
  });

  it('a Resolver built directly refuses a latest-only custody too', () => {
    const db = createFeltDB({ namespace: `custody-${randomBytes(4).toString('hex')}`, memory: true });
    cleanup.push(() => db.close());
    const store = new ResolverStore(db);
    expect(() => new Resolver({ store, authorizer: new GrantAuthorizer(store), custody: latestOnly() as never, services: {} as never, targets: {} as never })).toThrow(/withSecretVersion/);
  });

  it('the vault passes the check', () => {
    expect(() => requireVersionedCustody(createVault({ directory: dir(), key: randomBytes(32) }))).not.toThrow();
  });
});

describe('a pinned revision reveals exactly its own material', () => {
  it('after two later stores, revisions 1, 2 and 3 each reveal the value written with them', async () => {
    const d = dir();
    const runtime: ResolverRuntime = await createResolverRuntime({ state: { memory: true }, environment: 'development', vaultDirectory: path.join(d, 'vault'), vaultKey: randomBytes(32) });
    cleanup.push(() => runtime.close());
    const operator = runtime.operator('acme');
    const ref = 'ref://prod/integrations/pinned-key';
    const values = [1, 2, 3].map((n) => `sk-${n}-${randomBytes(8).toString('hex')}`);
    for (const [i, secret] of values.entries()) {
      await runtime.resolver.put(operator, { ref, ...(i === 0 ? { kind: 'secret' as const } : {}), secret, expectedRevision: i });
    }
    for (const [i, value] of values.entries()) {
      const pinned = await runtime.resolver.resolve(operator, { ref, revision: i + 1, reveal: true });
      expect(pinned.revision).toBe(i + 1);
      expect(pinned.secret).toBe(value);
    }
    const current = await runtime.resolver.resolve(operator, { ref, reveal: true });
    expect([current.revision, current.secret]).toEqual([3, values[2]]);
  });
});
