/**
 * Backup and restore of a resolver: its FeltDB state and its vault, together.
 *
 * What a backup holds:
 * - every row of the resolver's collections and of the AppPort Services collections it uses (API keys,
 *   their prefixes and audit events, decision evidence), exported through FeltDB, one JSON line per row;
 * - every file of the vault (sealed versions and tombstones; ciphertext only);
 * - a manifest: the change sequence the state was exported at, a SHA-256 of every file, and the ids of the
 *   vault keys the backup needs. Key material is never in a backup: the vault keys and the verifier key
 *   are kept in the secret manager, separately.
 *
 * Consistency boundary: the state is exported first and is consistent when the change sequence did not
 * move during the export (otherwise the export is retried). The vault is copied after it. Vault versions
 * are written before the revisions that point at them and never edited, so every version the exported
 * state points at is in the later vault copy, unless it was destroyed by a revocation in between; the
 * restore's integrity check reports exactly that case. Management sessions are not backed up.
 *
 * Restore: refuses a backup whose files do not match the manifest, a target that is not empty, and keys
 * that cannot open the backup's vault. It restores the vault, then the state, then verifies every secret
 * revision against the vault and returns the report; the resolver should be started only on `ok`.
 */

import { createHash } from 'node:crypto';
import { copyFile, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { StateFirstDB } from '@feltdb/core';
import { verifyIntegrity, type IntegrityReport } from './integrity.js';
import { COLLECTIONS, ResolverStore } from './store.js';
import type { Vault } from './vault.js';

/** What a backup exports. Sessions are left out on purpose: a restore must not bring old sign-ins back. */
export const BACKUP_COLLECTIONS = [
  COLLECTIONS.references,
  COLLECTIONS.revisions,
  COLLECTIONS.grants,
  COLLECTIONS.reveals,
  COLLECTIONS.meta,
  COLLECTIONS.authority,
  'api_keys',
  'api_key_prefixes',
  'api_key_audit_events',
  'service_effect_evidence',
] as const;

export interface BackupManifest {
  format: 'resolver.backup/1';
  createdAt: string;
  sequence: number;
  collections: Record<string, { rows: number; sha256: string }>;
  vault: { files: Record<string, string> };
  /** Vault key ids the backup's versions are sealed with (and `legacy` when format-1 entries exist). */
  requiredVaultKeys: string[];
}

export class BackupError extends Error {
  constructor(
    readonly reason: 'backup.incomplete' | 'backup.corrupt' | 'backup.busy' | 'restore.target-not-empty' | 'restore.key-missing' | 'backup.target-not-empty',
    message: string,
  ) {
    super(message);
    this.name = 'BackupError';
  }
}

const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

async function files(root: string, dir = root): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  const out: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await files(root, full)));
    else if (entry.isFile() && !entry.name.endsWith('.tmp')) out.push(path.relative(root, full));
  }
  return out.sort();
}

async function emptyOrMissing(dir: string): Promise<boolean> {
  try {
    return (await readdir(dir)).length === 0;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

const strip = (row: Record<string, unknown>) => {
  const { __version: _v, recordId: _r, ...rest } = row;
  return rest;
};

/** Exports the state, then the vault, into `out` (which must be empty or missing). */
export async function createBackup(input: { db: StateFirstDB; vault: Vault; out: string; attempts?: number }): Promise<BackupManifest> {
  if (!(await emptyOrMissing(input.out))) throw new BackupError('backup.target-not-empty', `${input.out} is not empty`);
  const store = new ResolverStore(input.db);
  await mkdir(path.join(input.out, 'state'), { recursive: true, mode: 0o700 });
  let sequence = -1;
  let collections: BackupManifest['collections'] = {};
  for (let attempt = 0; attempt < (input.attempts ?? 5); attempt++) {
    const before = await store.sequence();
    collections = {};
    for (const name of BACKUP_COLLECTIONS) {
      const rows = (await input.db.collection<Record<string, unknown>>(name).find({})).map(strip).sort((a, b) => String(a['id']).localeCompare(String(b['id'])));
      const body = rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : '');
      await writeFile(path.join(input.out, 'state', `${name}.jsonl`), body, { mode: 0o600 });
      collections[name] = { rows: rows.length, sha256: sha256(body) };
    }
    if ((await store.sequence()) === before) {
      sequence = before;
      break;
    }
  }
  if (sequence < 0) throw new BackupError('backup.busy', 'the state kept changing during the export; retry when writes are quieter');

  // After the state: every version the exported revisions point at is already in the vault.
  const vaultFiles: Record<string, string> = {};
  const kids = new Set<string>();
  for (const relative of await files(input.vault.directory)) {
    const source = path.join(input.vault.directory, relative);
    const target = path.join(input.out, 'vault', relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    try {
      await copyFile(source, target);
    } catch (error) {
      // Removed since it was listed: a revocation destroyed it, which the restore's check reports.
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    const body = await readFile(target);
    vaultFiles[relative] = sha256(body);
    try {
      const parsed = JSON.parse(body.toString('utf8')) as { format?: string; kid?: string; versions?: unknown[] };
      if (parsed.format === 'resolver.vault/2' && parsed.kid) kids.add(parsed.kid);
      if (parsed.format === 'resolver.vault/1' && parsed.versions?.length) kids.add('legacy');
    } catch {
      throw new BackupError('backup.corrupt', `vault file ${relative} is not valid JSON`);
    }
  }
  const manifest: BackupManifest = {
    format: 'resolver.backup/1',
    createdAt: new Date().toISOString(),
    sequence,
    collections,
    vault: { files: vaultFiles },
    requiredVaultKeys: [...kids].sort(),
  };
  await writeFile(path.join(input.out, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return manifest;
}

/** Checks every file of a backup against its manifest without changing anything. */
export async function checkBackup(from: string): Promise<BackupManifest> {
  let manifest: BackupManifest;
  try {
    manifest = JSON.parse(await readFile(path.join(from, 'manifest.json'), 'utf8')) as BackupManifest;
  } catch {
    throw new BackupError('backup.incomplete', 'the backup has no readable manifest.json');
  }
  if (manifest.format !== 'resolver.backup/1') throw new BackupError('backup.corrupt', `unknown backup format ${String(manifest.format)}`);
  for (const name of BACKUP_COLLECTIONS) {
    const expected = manifest.collections[name];
    if (!expected) throw new BackupError('backup.incomplete', `the manifest has no entry for ${name}`);
    let body: string;
    try {
      body = await readFile(path.join(from, 'state', `${name}.jsonl`), 'utf8');
    } catch {
      throw new BackupError('backup.incomplete', `state/${name}.jsonl is missing`);
    }
    if (sha256(body) !== expected.sha256) throw new BackupError('backup.corrupt', `state/${name}.jsonl does not match the manifest`);
  }
  const present = new Set(await files(path.join(from, 'vault')));
  for (const [relative, digest] of Object.entries(manifest.vault.files)) {
    if (!present.has(relative)) throw new BackupError('backup.incomplete', `vault/${relative} is missing`);
    if (sha256(await readFile(path.join(from, 'vault', relative))) !== digest) throw new BackupError('backup.corrupt', `vault/${relative} does not match the manifest`);
    present.delete(relative);
  }
  if (present.size > 0) throw new BackupError('backup.corrupt', `the backup's vault holds files the manifest does not list`);
  return manifest;
}

/**
 * Restores `from` into an empty state (`db`) and an empty vault (`vault.directory`), then verifies them
 * together. `vault` must be configured with every key the backup needs.
 */
export async function restoreBackup(input: { from: string; db: StateFirstDB; vault: Vault }): Promise<{ manifest: BackupManifest; integrity: IntegrityReport }> {
  const manifest = await checkBackup(input.from);
  for (const kid of manifest.requiredVaultKeys) {
    if (kid !== 'legacy' && !input.vault.keys.accepted.includes(kid)) {
      throw new BackupError('restore.key-missing', `the backup's vault is sealed with key ${kid}, which is not configured (RESOLVER_VAULT_KEY or RESOLVER_VAULT_PREVIOUS_KEYS)`);
    }
  }
  if (!(await emptyOrMissing(input.vault.directory))) throw new BackupError('restore.target-not-empty', `the vault directory ${input.vault.directory} is not empty`);
  for (const name of BACKUP_COLLECTIONS) {
    if ((await input.db.collection(name).find({})).length > 0) throw new BackupError('restore.target-not-empty', `the state already holds ${name} rows`);
  }

  // Vault first: once a revision is visible, the version it points at is already in place.
  for (const relative of Object.keys(manifest.vault.files)) {
    const target = path.join(input.vault.directory, relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(path.join(input.from, 'vault', relative), target);
  }
  // The sequence row last: an instance that starts early sees no change sequence beyond the rows it can read.
  const order = [...BACKUP_COLLECTIONS.filter((n) => n !== COLLECTIONS.meta), COLLECTIONS.meta];
  for (const name of order) {
    const body = await readFile(path.join(input.from, 'state', `${name}.jsonl`), 'utf8');
    const collection = input.db.collection<Record<string, unknown>>(name);
    for (const line of body.split('\n')) {
      if (!line) continue;
      const row = JSON.parse(line) as Record<string, unknown>;
      await collection.insert(row, String(row['id']), { requireAbsent: true });
    }
  }
  const integrity = await verifyIntegrity(new ResolverStore(input.db), input.vault, input.vault);
  return { manifest, integrity };
}

/** Size of a backup on disk, for reporting. */
export async function backupSize(from: string): Promise<number> {
  let total = 0;
  for (const relative of await files(from)) total += (await stat(path.join(from, relative))).size;
  return total;
}
