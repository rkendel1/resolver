// Backup and restore of state and vault together, with disposable state and vaults: round trip, lost
// vault, lost database, incomplete and tampered backups, a vault from another backup, and missing keys.
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { checkBackup, createBackup, createResolverRuntime, createVault, restoreBackup, type ResolverRuntime } from '@appport/resolver';

const cleanup: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
});

const SECRETS = { current: 'sk-current-MUST-NOT-APPEAR', old: 'sk-old-MUST-NOT-APPEAR' };

function place() {
  const dir = mkdtempSync(path.join(tmpdir(), 'resolver-backup-'));
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }));
  const db = createFeltDB({ namespace: `backup-${randomBytes(4).toString('hex')}`, memory: true });
  cleanup.push(() => db.close());
  return { dir, db, vaultDirectory: path.join(dir, 'vault') };
}

async function source(keys = { vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') }) {
  const { dir, db, vaultDirectory } = place();
  const runtime = await createResolverRuntime({ state: { db }, vaultDirectory, ...keys, environment: 'development' });
  cleanup.push(() => runtime.close());
  const op = runtime.operator('acme');
  await runtime.resolver.put(op, { ref: 'ref://prod/llm/key', kind: 'secret', secret: SECRETS.old, expectedRevision: 0 });
  await runtime.resolver.put(op, { ref: 'ref://prod/llm/key', secret: SECRETS.current, expectedRevision: 1 });
  await runtime.resolver.put(op, { ref: 'ref://prod/llm/revoked', kind: 'secret', secret: 'gone', expectedRevision: 0 });
  await runtime.resolver.revoke(op, { ref: 'ref://prod/llm/revoked', expectedRevision: 1 });
  await runtime.resolver.put(op, { ref: 'ref://prod/chat/model', kind: 'model', binding: { value: { provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/key' } }, expectedRevision: 0 });
  const app = await runtime.resolver.createKey(op, { name: 'app' });
  await runtime.resolver.grant(op, { subject: app.principal, actions: ['read', 'reveal'], pattern: 'ref://prod/*' });
  return { dir, db, vaultDirectory, runtime, keys, appKey: app.secret };
}

async function target(keys: { vaultKey: Buffer; verifierKey: string; previousVaultKeys?: Buffer[] }) {
  const { db, vaultDirectory } = place();
  const vault = createVault({ directory: vaultDirectory, key: keys.vaultKey, previousKeys: keys.previousVaultKeys ?? [] });
  return { db, vaultDirectory, vault, keys };
}

async function backupOf(s: Awaited<ReturnType<typeof source>>) {
  const out = path.join(s.dir, 'backup');
  await createBackup({ db: s.db, vault: s.runtime.vault!, out });
  return out;
}

describe('backup and restore', () => {
  it('round trip: references, history, pins, grants, API keys and secrets come back, and verify', async () => {
    const s = await source();
    const out = await backupOf(s);
    // Nothing in a backup is plaintext material.
    for (const file of readdirSync(out, { recursive: true, withFileTypes: true }).filter((e) => e.isFile())) {
      const body = readFileSync(path.join(file.parentPath, file.name), 'utf8');
      for (const secret of [...Object.values(SECRETS), 'gone', s.appKey]) expect(body).not.toContain(secret);
    }
    const t = await target(s.keys);
    const { manifest, integrity } = await restoreBackup({ from: out, db: t.db, vault: t.vault });
    expect(integrity.ok).toBe(true);
    expect(manifest.sequence).toBe(await s.runtime.store.sequence());

    const restored = await createResolverRuntime({ state: { db: t.db }, vaultDirectory: t.vaultDirectory, ...s.keys, environment: 'development', verifyIntegrityOnStart: true });
    cleanup.push(() => restored.close());
    expect((await restored.readiness()).ready).toBe(true);
    const viaKey = await restored.services.apiKeys.authenticateApiKey(s.appKey);
    expect(viaKey).not.toBeNull(); // the same API key works against the restored state
    expect((await restored.resolver.resolve(viaKey!, { ref: 'ref://prod/llm/key', reveal: true })).secret).toBe(SECRETS.current);
    expect((await restored.resolver.resolve(viaKey!, { ref: 'ref://prod/llm/key', revision: 1, reveal: true })).secret).toBe(SECRETS.old);
    await expect(restored.resolver.resolve(viaKey!, { ref: 'ref://prod/llm/revoked' })).rejects.toMatchObject({ reason: 'resolver.revoked' });
    expect((await restored.resolver.history(restored.operator('acme'), { ref: 'ref://prod/llm/key' })).entries).toHaveLength(2);
    // The change sequence continues where it was: new writes are numbered after the restored ones.
    const next = await restored.resolver.put(restored.operator('acme'), { ref: 'ref://prod/cfg/after', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
    expect(next.revision).toBe(1);
    expect(await restored.store.sequence()).toBe(manifest.sequence + 1);
  });

  it('refuses an incomplete or tampered backup, and changes nothing', async () => {
    const s = await source();
    const out = await backupOf(s);
    const variants: Array<[string, (dir: string) => void, RegExp]> = [
      ['manifest missing', (d) => unlinkSync(path.join(d, 'manifest.json')), /no readable manifest/],
      ['state file missing', (d) => unlinkSync(path.join(d, 'state', 'resolver_revisions.jsonl')), /is missing/],
      ['state file edited', (d) => writeFileSync(path.join(d, 'state', 'resolver_grants.jsonl'), '{"id":"forged"}\n'), /does not match/],
      ['vault file missing', (d) => {
        const manifest = JSON.parse(readFileSync(path.join(d, 'manifest.json'), 'utf8'));
        unlinkSync(path.join(d, 'vault', Object.keys(manifest.vault.files)[0]!));
      }, /is missing/],
      ['vault file edited', (d) => {
        const manifest = JSON.parse(readFileSync(path.join(d, 'manifest.json'), 'utf8'));
        const file = path.join(d, 'vault', Object.keys(manifest.vault.files)[0]!);
        writeFileSync(file, `${readFileSync(file, 'utf8')} `);
      }, /does not match/],
    ];
    for (const [name, damage, message] of variants) {
      const copy = path.join(s.dir, `damaged-${name.replaceAll(' ', '-')}`);
      cpSync(out, copy, { recursive: true });
      damage(copy);
      const t = await target(s.keys);
      await expect(restoreBackup({ from: copy, db: t.db, vault: t.vault }), name).rejects.toThrow(message);
      expect(await t.db.collection('resolver_references').find({}), name).toEqual([]);
    }
  });

  it('refuses to restore without the vault key the backup needs', async () => {
    const s = await source();
    const out = await backupOf(s);
    const t = await target({ ...s.keys, vaultKey: randomBytes(32) });
    await expect(restoreBackup({ from: out, db: t.db, vault: t.vault })).rejects.toMatchObject({ reason: 'restore.key-missing' });
    // With the old key as a previous key, it restores (and a rotation can follow).
    const u = await target({ ...s.keys, vaultKey: randomBytes(32), previousVaultKeys: [s.keys.vaultKey] });
    expect((await restoreBackup({ from: out, db: u.db, vault: u.vault })).integrity.ok).toBe(true);
  });

  it('refuses a target that is not empty', async () => {
    const s = await source();
    const out = await backupOf(s);
    const t = await target(s.keys);
    expect((await restoreBackup({ from: out, db: t.db, vault: t.vault })).integrity.ok).toBe(true);
    await expect(restoreBackup({ from: out, db: t.db, vault: t.vault })).rejects.toMatchObject({ reason: 'restore.target-not-empty' });
  });

  it('a state restored with a vault from another backup is reported, never served silently', async () => {
    // Two resolvers with the same names and the same keys: their vaults hold "the same" version 1.
    const keys = { vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex') };
    const first = await source(keys);
    const second = await source(keys);
    const out1 = await backupOf(first);
    const out2 = await backupOf(second);
    const mixed = path.join(first.dir, 'mixed');
    cpSync(out1, mixed, { recursive: true });
    rmSync(path.join(mixed, 'vault'), { recursive: true });
    cpSync(path.join(out2, 'vault'), path.join(mixed, 'vault'), { recursive: true });
    // Re-sign the manifest's vault section so only the seals can tell (an operator mixing directories by hand).
    const m1 = JSON.parse(readFileSync(path.join(out1, 'manifest.json'), 'utf8'));
    const m2 = JSON.parse(readFileSync(path.join(out2, 'manifest.json'), 'utf8'));
    writeFileSync(path.join(mixed, 'manifest.json'), JSON.stringify({ ...m1, vault: m2.vault }));
    const t = await target(keys);
    const { integrity } = await restoreBackup({ from: mixed, db: t.db, vault: t.vault });
    expect(integrity.ok).toBe(false);
    expect(integrity.problems.map((p) => [p.ref, p.revision, p.problem])).toEqual(
      expect.arrayContaining([['ref://prod/llm/key', 1, 'mismatch'], ['ref://prod/llm/key', 2, 'mismatch']]),
    );
    // And an instance asked to verify at startup stays out of rotation.
    const restored = await createResolverRuntime({ state: { db: t.db }, vaultDirectory: t.vaultDirectory, ...keys, environment: 'development', verifyIntegrityOnStart: true });
    cleanup.push(() => restored.close());
    expect((await restored.readiness()).checks.integrity).toMatchObject({ ok: false, checked: true });
  });

  it('lost vault: references and keys survive, every secret revision is reported missing, and reveals fail explicitly', async () => {
    const s = await source();
    await s.runtime.close();
    rmSync(s.vaultDirectory, { recursive: true, force: true });
    const runtime: ResolverRuntime = await createResolverRuntime({ state: { db: s.db }, vaultDirectory: s.vaultDirectory, ...s.keys, environment: 'development', verifyIntegrityOnStart: true });
    cleanup.push(() => runtime.close());
    const report = await runtime.integrity();
    expect(report.problems.filter((p) => p.problem === 'missing').map((p) => p.revision).sort()).toEqual([1, 2]);
    expect((await runtime.readiness()).ready).toBe(false);
    await expect(runtime.resolver.resolve(runtime.operator('acme'), { ref: 'ref://prod/llm/key', reveal: true })).rejects.toMatchObject({ reason: 'resolver.custody-unavailable' });
    // Non-secret references are unaffected.
    expect((await runtime.resolver.resolve(runtime.operator('acme'), { ref: 'ref://prod/chat/model' })).kind).toBe('model');
    // Recovery: set each secret again (a new revision, a new version) and the reference resolves.
    await runtime.resolver.put(runtime.operator('acme'), { ref: 'ref://prod/llm/key', secret: 'sk-reissued', expectedRevision: 2 });
    expect((await runtime.resolver.resolve(runtime.operator('acme'), { ref: 'ref://prod/llm/key', reveal: true })).secret).toBe('sk-reissued');
  });

  it('lost database: the vault alone restores nothing; the backup restores both', async () => {
    const s = await source();
    const out = await backupOf(s);
    // A fresh state over the surviving vault: no reference points at its versions.
    const fresh = place();
    const runtime = await createResolverRuntime({ state: { db: fresh.db }, vaultDirectory: s.vaultDirectory, ...s.keys, environment: 'development' });
    cleanup.push(() => runtime.close());
    const orphaned = await runtime.integrity();
    expect(orphaned.checked.references).toBe(0);
    expect(orphaned.warnings.filter((w) => w.warning === 'orphan-version').length).toBeGreaterThan(0);
    // The backup brings back state and vault together.
    const t = await target(s.keys);
    expect((await restoreBackup({ from: out, db: t.db, vault: t.vault })).integrity.ok).toBe(true);
  });

  it('a backup is checkable on its own, before any restore', async () => {
    const s = await source();
    const out = await backupOf(s);
    const manifest = await checkBackup(out);
    expect(manifest.requiredVaultKeys).toHaveLength(1);
    expect(manifest.collections['resolver_references']!.rows).toBe(3);
    expect(manifest.collections['resolver_sessions']).toBeUndefined();
  });
});
