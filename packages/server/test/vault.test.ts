// The vault shared by several resolver processes: two independent vault objects on one directory stand
// in for two processes (no shared in-process queue between them).
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createVault } from '@appport/resolver';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function shared() {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-vault-'));
  dirs.push(dir);
  const key = randomBytes(32);
  return [createVault({ directory: dir, key }), createVault({ directory: dir, key })] as const;
}

const reference = { secretId: 'secret-1', tenantId: 'acme' };
const context = { tenantId: 'acme', principalId: 'p', purpose: 't' };

describe('vault shared by several processes', () => {
  it('concurrent stores get distinct versions, and every version opens with what was stored', async () => {
    const [a, b] = shared();
    const writes = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? a : b).store({ reference, value: `value-${i}`, context } as never).then((r) => [i, r.version] as const)));
    const versions = writes.map(([, v]) => v);
    expect(new Set(versions).size).toBe(40);
    for (const [i, version] of writes) {
      expect(await a.withSecretVersion({ reference, context, version } as never, (s) => s.value)).toBe(`value-${i}`);
    }
  });

  it('after removal nothing opens and nothing new is written, from either process', async () => {
    const [a, b] = shared();
    await a.store({ reference, value: 'v1', context } as never);
    await b.remove!({ reference, context } as never);
    await expect(a.withSecret({ reference, context } as never, (s) => s.value)).rejects.toMatchObject({ code: 'REVOKED' });
    await expect(a.store({ reference, value: 'resurrected', context } as never)).rejects.toMatchObject({ code: 'REVOKED' });
    expect((await a.list()).find((e) => e.secretId === 'secret-1')).toMatchObject({ removed: true, versions: [] });
  });

  it('a removal racing stores leaves no readable material behind', async () => {
    const [a, b] = shared();
    await a.store({ reference, value: 'v1', context } as never);
    await Promise.all([
      ...Array.from({ length: 10 }, (_, i) => a.store({ reference, value: `late-${i}`, context } as never).catch(() => undefined)),
      b.remove!({ reference, context } as never),
    ]);
    await b.remove!({ reference, context } as never); // what revocation's retry does
    expect((await a.list()).find((e) => e.secretId === 'secret-1')!.versions).toEqual([]);
    await expect(b.withSecretVersion({ reference, context, version: 1 } as never, (s) => s.value)).rejects.toMatchObject({ code: 'REVOKED' });
  });

  it('a version whose commit lost is discarded; verification checks presence, key and seal without returning material', async () => {
    const [a] = shared();
    const kept = (await a.store({ reference, value: 'kept', context } as never)) as unknown as { version: number; seal: string };
    const lost = (await a.store({ reference, value: 'lost', context } as never)) as unknown as { version: number; seal: string };
    await a.discardVersion({ reference, version: lost.version });
    expect(await a.verifyVersion({ reference, version: lost.version })).toBe('missing');
    expect(await a.verifyVersion({ reference, version: kept.version, seal: kept.seal })).toBe('ok');
    expect(await a.verifyVersion({ reference, version: kept.version, seal: 'another-seal' })).toBe('mismatch');
    const other = createVault({ directory: a.directory, key: randomBytes(32) });
    expect(await other.verifyVersion({ reference, version: kept.version })).toBe('undecryptable');
  });
});
