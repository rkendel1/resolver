// Vault key rotation: re-sealing every stored version under a new key while the resolver keeps serving,
// resumable after an interruption, migrating format-1 files, and leaving revision pins unchanged.
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { createResolverRuntime, createVault, keyId, referenceId, type ResolverRuntime } from '@appport/resolver';

const cleanup: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
});

function setup() {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-rotation-'));
  const db = createFeltDB({ namespace: `rotation-${randomBytes(4).toString('hex')}`, memory: true });
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }), () => db.close());
  const vaultDirectory = path.join(dir, 'vault');
  const open = async (key: Buffer, previousVaultKeys: Buffer[] = []): Promise<ResolverRuntime> => {
    const runtime = await createResolverRuntime({ state: { db }, vaultDirectory, vaultKey: key, previousVaultKeys, environment: 'development' });
    cleanup.push(() => runtime.close());
    return runtime;
  };
  return { dir, vaultDirectory, open };
}

const kidsOnDisk = (vaultDirectory: string) =>
  readdirSync(vaultDirectory, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && /^v\d+\.json$/.test(e.name))
    .map((e) => JSON.parse(readFileSync(path.join(e.parentPath, e.name), 'utf8')).kid as string);

describe('vault key rotation', () => {
  it('re-seals every version under the new key; pinned revisions reveal what they did before; the old key can then go', async () => {
    const { vaultDirectory, open } = setup();
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    let runtime = await open(oldKey);
    const op = runtime.operator('acme');
    await runtime.resolver.put(op, { ref: 'ref://prod/llm/a', kind: 'secret', secret: 'a-1', expectedRevision: 0 });
    await runtime.resolver.put(op, { ref: 'ref://prod/llm/a', secret: 'a-2', expectedRevision: 1 });
    await runtime.resolver.put(op, { ref: 'ref://prod/llm/b', kind: 'secret', secret: 'b-1', expectedRevision: 0 });
    await runtime.close();

    // Step 1: every instance gets the new key as current and the old one as previous.
    runtime = await open(newKey, [oldKey]);
    expect((await runtime.integrity()).warnings.filter((w) => w.warning === 'old-vault-key')).toHaveLength(3);
    // Step 2: re-seal.
    const report = await runtime.vault!.rotate();
    expect(report).toMatchObject({ resealed: 3, alreadyCurrent: 0 });
    expect(new Set(kidsOnDisk(vaultDirectory))).toEqual(new Set([keyId(newKey)]));
    // Rotation is idempotent.
    expect(await runtime.vault!.rotate()).toMatchObject({ resealed: 0, alreadyCurrent: 3 });
    const integrity = await runtime.integrity();
    expect(integrity.ok).toBe(true);
    expect(integrity.warnings.filter((w) => w.warning === 'old-vault-key')).toEqual([]);
    await runtime.close();

    // Step 3: drop the old key. Pins are unchanged: the same revision reveals the same material.
    runtime = await open(newKey);
    const op2 = runtime.operator('acme');
    expect((await runtime.resolver.resolve(op2, { ref: 'ref://prod/llm/a', revision: 1, reveal: true })).secret).toBe('a-1');
    expect((await runtime.resolver.resolve(op2, { ref: 'ref://prod/llm/a', reveal: true })).secret).toBe('a-2');
    expect((await runtime.resolver.resolve(op2, { ref: 'ref://prod/llm/b', reveal: true })).secret).toBe('b-1');
    await runtime.close();

    // With only the old key, nothing opens, and the failure says why.
    const stale = createVault({ directory: vaultDirectory, key: oldKey });
    const reference = { secretId: referenceId('acme', 'ref://prod/llm/b'), tenantId: 'acme' };
    await expect(stale.withSecret({ reference, context: { tenantId: 'acme', principalId: 'p', purpose: 't' } } as never, (s) => s.value)).rejects.toMatchObject({ code: 'KEY_MISSING' });
  });

  it('an interrupted rotation leaves every version readable with both keys, and running it again finishes it', async () => {
    const { vaultDirectory, open } = setup();
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    const runtime = await open(oldKey);
    const op = runtime.operator('acme');
    for (let i = 0; i < 6; i++) await runtime.resolver.put(op, { ref: `ref://prod/s/${i}`, kind: 'secret', secret: `value-${i}`, expectedRevision: 0 });
    await runtime.close();

    // Interrupted after half of the secrets: rotate only what is visible, then put the rest back.
    const entries = readdirSync(vaultDirectory).sort();
    const aside = `${vaultDirectory}-aside`;
    mkdirSync(aside);
    for (const entry of entries.slice(3)) renameSync(path.join(vaultDirectory, entry), path.join(aside, entry));
    expect((await createVault({ directory: vaultDirectory, key: newKey, previousKeys: [oldKey] }).rotate()).resealed).toBe(3);
    for (const entry of entries.slice(3)) renameSync(path.join(aside, entry), path.join(vaultDirectory, entry));
    expect(new Set(kidsOnDisk(vaultDirectory))).toEqual(new Set([keyId(newKey), keyId(oldKey)]));

    // Mixed state: an instance with both keys serves every secret.
    const mid = await open(newKey, [oldKey]);
    for (let i = 0; i < 6; i++) expect((await mid.resolver.resolve(mid.operator('acme'), { ref: `ref://prod/s/${i}`, reveal: true })).secret).toBe(`value-${i}`);
    // Running it again re-seals only what is left.
    expect(await mid.vault!.rotate()).toMatchObject({ resealed: 3, alreadyCurrent: 3 });
    expect(new Set(kidsOnDisk(vaultDirectory))).toEqual(new Set([keyId(newKey)]));
    expect((await mid.integrity()).ok).toBe(true);
  });

  it('serves reveals and writes during the rotation without errors or wrong values', async () => {
    const { vaultDirectory, open } = setup();
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    const seed = await open(oldKey);
    for (let i = 0; i < 20; i++) await seed.resolver.put(seed.operator('acme'), { ref: `ref://prod/c/${i}`, kind: 'secret', secret: `c-${i}`, expectedRevision: 0 });
    await seed.close();
    const runtime = await open(newKey, [oldKey]);
    const op = runtime.operator('acme');
    let stop = false;
    const failures: unknown[] = [];
    const readers = Array.from({ length: 4 }, async () => {
      while (!stop) {
        const i = Math.floor(Math.random() * 20);
        const got = await runtime.resolver.resolve(op, { ref: `ref://prod/c/${i}`, reveal: true }).catch((e) => e);
        if (got.secret !== `c-${i}` && !(typeof got.secret === 'string' && got.secret.startsWith(`c-${i}-`))) failures.push(got);
      }
    });
    const writer = (async () => {
      for (let n = 0; n < 5; n++) {
        const ref = `ref://prod/c/${n}`;
        const current = (await runtime.store.reference('acme', ref))!;
        await runtime.resolver.put(op, { ref, secret: `c-${n}-${n}`, expectedRevision: current.revision });
      }
    })();
    const report = await runtime.vault!.rotate();
    await writer;
    stop = true;
    await Promise.all(readers);
    expect(failures).toEqual([]);
    expect(report.resealed).toBe(20);
    // Versions written during the rotation were sealed with the new key already.
    expect(new Set(kidsOnDisk(vaultDirectory))).toEqual(new Set([keyId(newKey)]));
    expect((await runtime.integrity()).ok).toBe(true);
  });

  it('migrates format-1 vault files: same versions, same pins, sealed under the current key', async () => {
    const { vaultDirectory, open } = setup();
    const key = randomBytes(32);
    const runtime = await open(key);
    const op = runtime.operator('acme');
    const ref = 'ref://prod/llm/legacy';
    await runtime.resolver.put(op, { ref, kind: 'secret', secret: 'new-1', expectedRevision: 0 });
    // Replace what the vault wrote with the format-1 file the previous release wrote: two versions, one file.
    const secretId = referenceId('acme', ref);
    const name = createHash('sha256').update(`acme\u0000${secretId}`).digest('hex');
    rmSync(path.join(vaultDirectory, name), { recursive: true, force: true });
    const seal = (version: number, value: string) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(`acme\u0000${secretId}\u0000${version}`));
      const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
      return { version, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64'), storedAt: new Date().toISOString() };
    };
    writeFileSync(path.join(vaultDirectory, `${name}.json`), JSON.stringify({ format: 'resolver.vault/1', tenantId: 'acme', secretId, versions: [seal(1, 'new-1')] }));
    expect((await runtime.resolver.resolve(op, { ref, reveal: true })).secret).toBe('new-1'); // format 1 still reads
    await runtime.resolver.put(op, { ref, secret: 'new-2', expectedRevision: 1 }); // a new version alongside it
    expect(await runtime.vault!.rotate()).toMatchObject({ migrated: 1, alreadyCurrent: 1 });
    expect(readdirSync(vaultDirectory)).not.toContain(`${name}.json`);
    expect((await runtime.resolver.resolve(op, { ref, revision: 1, reveal: true })).secret).toBe('new-1');
    expect((await runtime.resolver.resolve(op, { ref, reveal: true })).secret).toBe('new-2');
  });

  it('revocation still destroys material after rotation, and a rotation never brings it back', async () => {
    const { vaultDirectory, open } = setup();
    const oldKey = randomBytes(32);
    const newKey = randomBytes(32);
    const runtime = await open(newKey, [oldKey]);
    const op = runtime.operator('acme');
    await runtime.resolver.put(op, { ref: 'ref://prod/llm/gone', kind: 'secret', secret: 'gone', expectedRevision: 0 });
    await runtime.resolver.revoke(op, { ref: 'ref://prod/llm/gone', expectedRevision: 1 });
    expect(await runtime.vault!.rotate()).toMatchObject({ skippedRemoved: 1 });
    expect(kidsOnDisk(vaultDirectory)).toEqual([]);
    expect((await runtime.integrity()).ok).toBe(true);
  });
});
