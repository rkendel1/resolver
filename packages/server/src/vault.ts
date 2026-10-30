/**
 * Secret custody for the resolver: an encrypted vault in a directory, outside the state store.
 *
 * Implements `SecretCustody` from @appport/services, so the material lives where AppPort Services
 * expects a host to keep it ("secret values are never FeltDB fields"). Each version is sealed with
 * AES-256-GCM, with the tenant, secret id and version as additional authenticated data: a ciphertext
 * moved to another secret or version does not open.
 *
 * Layout (format `resolver.vault/2`), safe for several resolver processes sharing one directory:
 *
 *   <dir>/<hash(tenant, secret)>/v<N>.json   one sealed version, published once and never edited in place
 *   <dir>/<hash(tenant, secret)>/removed.json  the tombstone: present once the secret is revoked
 *
 * - A new version is written to a temporary file and published with `link`, which fails if the name is
 *   taken: two processes storing at once get different versions, never one overwriting the other.
 * - Removal writes the tombstone first, then deletes every version. Nothing is read once the tombstone
 *   exists, and a version published concurrently with removal is deleted by the next removal pass.
 * - Every version records the id of the key that sealed it (`kid`), so the vault key can be rotated
 *   (`rotate`): versions are re-sealed one file at a time, and old and new keys both open while that runs.
 * - Every version carries a random `seal` id. The resolver records it in the revision that points at the
 *   version, so a restored state can be checked against a restored vault (`verify`) without reading or
 *   storing anything derived from the material.
 *
 * Format `resolver.vault/1` (one file per secret holding every version, no key id) is still read, and
 * `rotate` migrates it.
 *
 * Versions are kept, so a reference pinned to an earlier revision can still reveal what it pointed at.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { link, mkdir, readdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type {
  ResolvedSecret,
  ScopedResolveSecretInput,
  SecretCustody,
  SecretCustodyStatus,
  SecretCustodyWriteResult,
} from '@appport/services';

interface SealedVersion {
  version: number;
  iv: string;
  tag: string;
  data: string;
  storedAt: string;
}

/** Format 1: every version of a secret in one file. Read-only now; `rotate` migrates it. */
interface LegacyFile {
  format: 'resolver.vault/1';
  tenantId: string;
  secretId: string;
  versions: SealedVersion[];
  removedAt?: string;
}

interface VersionFile extends SealedVersion {
  format: 'resolver.vault/2';
  tenantId: string;
  secretId: string;
  kid: string;
  seal: string;
}

export class VaultError extends Error {
  constructor(
    readonly code: 'MISSING' | 'REVOKED' | 'CORRUPT' | 'VERSION_MISSING' | 'KEY_MISSING',
    message: string,
  ) {
    super(message);
  }
}

/** What `verify` found for one version. Never the material. */
export type VersionCheck = 'ok' | 'missing' | 'removed' | 'mismatch' | 'undecryptable';

export interface VaultSecretEntry {
  tenantId: string;
  secretId: string;
  removed: boolean;
  versions: Array<{ version: number; kid: string | null; seal: string | null }>;
}

export interface RotationReport {
  resealed: number;
  migrated: number;
  alreadyCurrent: number;
  skippedRemoved: number;
}

/** Custody that can also open a specific stored version (for pinned revisions), and manage versions. */
export interface VersionedCustody extends SecretCustody<string> {
  withSecretVersion<T>(input: ScopedResolveSecretInput & { version: number }, use: (secret: ResolvedSecret<string>) => T | Promise<T>): Promise<T>;
  /** Deletes one version that no revision points at (a write whose commit failed). */
  discardVersion?(input: { reference: { secretId: string; tenantId: string }; version: number }): Promise<void>;
  /** Checks that `version` is present, opens with a configured key and carries `seal`. Never returns material. */
  verifyVersion?(input: { reference: { secretId: string; tenantId: string }; version: number; seal?: string }): Promise<VersionCheck>;
}

export function isVersionedCustody(custody: SecretCustody<string>): custody is VersionedCustody {
  return typeof (custody as Partial<VersionedCustody>).withSecretVersion === 'function';
}

/** Reads a 32-byte key given as 64 hex characters or base64. */
export function parseVaultKey(text: string): Buffer {
  const trimmed = text.trim();
  const key = /^[0-9a-f]{64}$/i.test(trimmed) ? Buffer.from(trimmed, 'hex') : Buffer.from(trimmed, 'base64');
  if (key.length !== 32) throw new Error('the vault key must be 32 bytes (64 hex characters or base64)');
  return key;
}

/** A key's id: derived from the key, so nothing has to be configured or kept in sync. Reveals nothing about it. */
export function keyId(key: Buffer): string {
  return createHash('sha256').update('resolver.vault.kid\u0000').update(key).digest('hex').slice(0, 16);
}

export interface VaultOptions {
  directory: string;
  /** The key new versions are sealed with. */
  key: Buffer;
  /** Earlier keys, still accepted for opening while a rotation is in progress or not yet run. */
  previousKeys?: Buffer[];
  now?: () => Date;
}

export interface Vault extends VersionedCustody {
  discardVersion(input: { reference: { secretId: string; tenantId: string }; version: number }): Promise<void>;
  verifyVersion(input: { reference: { secretId: string; tenantId: string }; version: number; seal?: string }): Promise<VersionCheck>;
  /** Every secret in the vault, with its versions' key ids and seals (no material). */
  list(): Promise<VaultSecretEntry[]>;
  /** Re-seals every version under the current key and migrates format 1. Idempotent and resumable. */
  rotate(): Promise<RotationReport>;
  /** The current key's id and the ids of every key this vault can open with. */
  readonly keys: { current: string; accepted: string[] };
  readonly directory: string;
}

const VERSION_FILE = /^v([1-9][0-9]{0,8})\.json$/;
const TOMBSTONE = 'removed.json';

export function createVault(options: VaultOptions): Vault {
  const { directory } = options;
  const all = [options.key, ...(options.previousKeys ?? [])];
  for (const key of all) if (key.length !== 32) throw new Error('the vault key must be 32 bytes');
  const keyring = new Map(all.map((key) => [keyId(key), key]));
  const currentKid = keyId(options.key);
  const now = options.now ?? (() => new Date());
  const queues = new Map<string, Promise<unknown>>();

  const name = (tenantId: string, secretId: string) => createHash('sha256').update(`${tenantId}\u0000${secretId}`).digest('hex');
  const dirFor = (tenantId: string, secretId: string) => path.join(directory, name(tenantId, secretId));
  const legacyFileFor = (tenantId: string, secretId: string) => path.join(directory, `${name(tenantId, secretId)}.json`);
  const versionFile = (tenantId: string, secretId: string, version: number) => path.join(dirFor(tenantId, secretId), `v${version}.json`);
  const aad = (tenantId: string, secretId: string, version: number) => Buffer.from(`${tenantId}\u0000${secretId}\u0000${version}`);
  const temporary = (target: string) => `${target}.${randomBytes(6).toString('hex')}.tmp`;

  const ignoreMissing = (error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  };

  async function readJson<T>(file: string): Promise<T | undefined> {
    try {
      return JSON.parse(await readFile(file, 'utf8')) as T;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      if (error instanceof SyntaxError) throw new VaultError('CORRUPT', 'a vault entry is not valid JSON');
      throw error;
    }
  }

  async function removed(tenantId: string, secretId: string): Promise<boolean> {
    if ((await readJson(path.join(dirFor(tenantId, secretId), TOMBSTONE))) !== undefined) return true;
    const legacy = await readLegacy(tenantId, secretId);
    return Boolean(legacy?.removedAt);
  }

  async function readLegacy(tenantId: string, secretId: string): Promise<LegacyFile | undefined> {
    const file = await readJson<LegacyFile>(legacyFileFor(tenantId, secretId));
    if (file && (file.format !== 'resolver.vault/1' || file.tenantId !== tenantId || file.secretId !== secretId)) {
      throw new VaultError('CORRUPT', 'the vault entry does not belong to this secret');
    }
    return file;
  }

  async function readVersion(tenantId: string, secretId: string, version: number): Promise<VersionFile | undefined> {
    const file = await readJson<VersionFile>(versionFile(tenantId, secretId, version));
    if (file && (file.format !== 'resolver.vault/2' || file.tenantId !== tenantId || file.secretId !== secretId || file.version !== version)) {
      throw new VaultError('CORRUPT', 'the vault entry does not belong to this secret version');
    }
    return file;
  }

  async function versionNumbers(tenantId: string, secretId: string): Promise<number[]> {
    let names: string[] = [];
    try {
      names = await readdir(dirFor(tenantId, secretId));
    } catch (error) {
      ignoreMissing(error);
    }
    const numbers = names.map((n) => VERSION_FILE.exec(n)?.[1]).filter((n): n is string => n !== undefined).map(Number);
    for (const sealed of (await readLegacy(tenantId, secretId))?.versions ?? []) numbers.push(sealed.version);
    return [...new Set(numbers)].sort((a, b) => a - b);
  }

  /** The sealed version, from format 2 or format 1, with the key id it was sealed under (null: unknown). */
  async function sealed(tenantId: string, secretId: string, version: number): Promise<(SealedVersion & { kid: string | null; seal: string | null }) | undefined> {
    const current = await readVersion(tenantId, secretId, version);
    if (current) return { ...current, kid: current.kid, seal: current.seal };
    const legacy = (await readLegacy(tenantId, secretId))?.versions.find((v) => v.version === version);
    return legacy ? { ...legacy, kid: null, seal: null } : undefined;
  }

  function decrypt(tenantId: string, secretId: string, entry: SealedVersion & { kid: string | null }): string {
    const candidates = entry.kid === null ? [...keyring.values()] : keyring.has(entry.kid) ? [keyring.get(entry.kid)!] : [];
    if (candidates.length === 0) throw new VaultError('KEY_MISSING', `version ${entry.version} was sealed with key ${entry.kid}, which is not configured`);
    for (const key of candidates) {
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'base64'));
        decipher.setAAD(aad(tenantId, secretId, entry.version));
        decipher.setAuthTag(Buffer.from(entry.tag, 'base64'));
        return Buffer.concat([decipher.update(Buffer.from(entry.data, 'base64')), decipher.final()]).toString('utf8');
      } catch {
        // try the next key (format 1 records no key id)
      }
    }
    throw new VaultError('CORRUPT', 'the vault entry could not be opened with the configured keys');
  }

  function seal(tenantId: string, secretId: string, version: number, value: string): Omit<VersionFile, 'seal' | 'storedAt'> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', options.key, iv);
    cipher.setAAD(aad(tenantId, secretId, version));
    const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return {
      format: 'resolver.vault/2',
      tenantId,
      secretId,
      version,
      kid: currentKid,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
  }

  /** Publishes `file` under `target` only if nothing is there: false if the name is taken. */
  async function publish(target: string, file: VersionFile): Promise<boolean> {
    const staging = temporary(target);
    await writeFile(staging, JSON.stringify(file), { mode: 0o600 });
    try {
      await link(staging, target);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw error;
    } finally {
      await unlink(staging).catch(ignoreMissing);
    }
  }

  /** In-process ordering per secret; cross-process safety comes from `link` and the tombstone. */
  function serial<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = queues.get(id) ?? Promise.resolve();
    const next = previous.then(task, task);
    const settled = next.catch(() => undefined);
    queues.set(id, settled);
    void settled.then(() => {
      if (queues.get(id) === settled) queues.delete(id);
    });
    return next;
  }

  async function resolveVersion(input: ScopedResolveSecretInput, version: number | 'current'): Promise<ResolvedSecret<string>> {
    const { secretId, tenantId } = input.reference;
    if (input.context.tenantId !== tenantId) throw new VaultError('MISSING', 'no such secret for this tenant');
    if (await removed(tenantId, secretId)) throw new VaultError('REVOKED', 'the secret was removed');
    const numbers = await versionNumbers(tenantId, secretId);
    if (numbers.length === 0) throw new VaultError('MISSING', 'no such secret');
    const chosen = version === 'current' ? numbers.at(-1)! : version;
    const entry = await sealed(tenantId, secretId, chosen);
    if (!entry) throw new VaultError('VERSION_MISSING', `version ${chosen} is not in the vault`);
    const value = decrypt(tenantId, secretId, entry);
    // A removal that raced this read wins: nothing is returned once the tombstone exists.
    if (await removed(tenantId, secretId)) throw new VaultError('REVOKED', 'the secret was removed');
    return {
      value,
      secretId,
      version: chosen,
      ...(input.reference.provider ? { provider: input.reference.provider } : {}),
      ...(input.reference.kind ? { kind: input.reference.kind } : {}),
    } as ResolvedSecret<string>;
  }

  async function removeAll(tenantId: string, secretId: string): Promise<void> {
    const dir = dirFor(tenantId, secretId);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tombstone = path.join(dir, TOMBSTONE);
    if ((await readJson(tombstone)) === undefined) {
      const staging = temporary(tombstone);
      await writeFile(staging, JSON.stringify({ format: 'resolver.vault/2', tenantId, secretId, removedAt: now().toISOString() }), { mode: 0o600 });
      await rename(staging, tombstone);
    }
    // Removal destroys the material: a revoked secret must not be recoverable from the vault.
    for (const entry of await readdir(dir)) {
      if (entry !== TOMBSTONE) await unlink(path.join(dir, entry)).catch(ignoreMissing);
    }
    await unlink(legacyFileFor(tenantId, secretId)).catch(ignoreMissing);
  }

  async function secretDirs(): Promise<Array<{ tenantId: string; secretId: string }>> {
    let entries: string[] = [];
    try {
      entries = await readdir(directory);
    } catch (error) {
      ignoreMissing(error);
    }
    const found = new Map<string, { tenantId: string; secretId: string }>();
    for (const entry of entries) {
      if (/^[0-9a-f]{64}\.json$/.test(entry)) {
        const legacy = await readJson<LegacyFile>(path.join(directory, entry));
        if (legacy?.format === 'resolver.vault/1') found.set(entry.slice(0, 64), { tenantId: legacy.tenantId, secretId: legacy.secretId });
      } else if (/^[0-9a-f]{64}$/.test(entry)) {
        const inside = await readdir(path.join(directory, entry)).catch(() => [] as string[]);
        for (const file of inside) {
          const body = await readJson<{ tenantId?: string; secretId?: string }>(path.join(directory, entry, file)).catch(() => undefined);
          if (body?.tenantId && body.secretId) {
            found.set(entry, { tenantId: body.tenantId, secretId: body.secretId });
            break;
          }
        }
      }
    }
    return [...found.values()];
  }

  return {
    directory,
    keys: { current: currentKid, accepted: [...keyring.keys()] },

    async withSecret(input, use) {
      return use(await resolveVersion(input, 'current'));
    },

    async withSecretVersion(input, use) {
      return use(await resolveVersion(input, input.version));
    },

    store(input): Promise<SecretCustodyWriteResult> {
      const { secretId, tenantId } = input.reference;
      return serial(`${tenantId}/${secretId}`, async () => {
        if (await removed(tenantId, secretId)) throw new VaultError('REVOKED', 'the secret was removed; it is never written again');
        await mkdir(dirFor(tenantId, secretId), { recursive: true, mode: 0o700 });
        const storedAt = now().toISOString();
        const sealId = randomBytes(16).toString('base64url');
        let version = ((await versionNumbers(tenantId, secretId)).at(-1) ?? 0) + 1;
        for (let attempt = 0; attempt < 64; attempt++, version++) {
          const file: VersionFile = { ...seal(tenantId, secretId, version, input.value), seal: sealId, storedAt };
          if (await publish(versionFile(tenantId, secretId, version), file)) {
            // Published after a concurrent removal: the removal wins.
            if (await removed(tenantId, secretId)) {
              await unlink(versionFile(tenantId, secretId, version)).catch(ignoreMissing);
              throw new VaultError('REVOKED', 'the secret was removed; it is never written again');
            }
            return { version, storedAt, seal: sealId } as SecretCustodyWriteResult;
          }
        }
        throw new VaultError('CORRUPT', 'could not allocate a vault version');
      });
    },

    async status(input): Promise<SecretCustodyStatus> {
      const { tenantId, secretId } = input.reference;
      if (await removed(tenantId, secretId)) return { state: 'revoked', location: 'resolver encrypted vault', writable: false };
      const latest = (await versionNumbers(tenantId, secretId)).at(-1);
      if (latest === undefined) return { state: 'missing', location: 'resolver encrypted vault', writable: true };
      const entry = await sealed(tenantId, secretId, latest);
      return {
        state: 'set',
        version: latest,
        ...(entry ? { updatedAt: entry.storedAt } : {}),
        location: 'resolver encrypted vault',
        writable: true,
      };
    },

    remove(input): Promise<void> {
      const { secretId, tenantId } = input.reference;
      return serial(`${tenantId}/${secretId}`, () => removeAll(tenantId, secretId));
    },

    discardVersion(input) {
      const { secretId, tenantId } = input.reference;
      return serial(`${tenantId}/${secretId}`, () => unlink(versionFile(tenantId, secretId, input.version)).catch(ignoreMissing));
    },

    async verifyVersion(input) {
      const { tenantId, secretId } = input.reference;
      if (await removed(tenantId, secretId)) return 'removed';
      const entry = await sealed(tenantId, secretId, input.version);
      if (!entry) return 'missing';
      try {
        decrypt(tenantId, secretId, entry);
      } catch {
        return 'undecryptable';
      }
      if (input.seal !== undefined && entry.seal !== input.seal) return 'mismatch';
      return 'ok';
    },

    async list() {
      const out: VaultSecretEntry[] = [];
      for (const { tenantId, secretId } of await secretDirs()) {
        const versions = [];
        for (const version of await versionNumbers(tenantId, secretId)) {
          const entry = await sealed(tenantId, secretId, version);
          if (entry) versions.push({ version, kid: entry.kid, seal: entry.seal });
        }
        out.push({ tenantId, secretId, removed: await removed(tenantId, secretId), versions });
      }
      return out;
    },

    async rotate() {
      const report: RotationReport = { resealed: 0, migrated: 0, alreadyCurrent: 0, skippedRemoved: 0 };
      for (const { tenantId, secretId } of await secretDirs()) {
        await serial(`${tenantId}/${secretId}`, async () => {
          if (await removed(tenantId, secretId)) {
            // Finish an interrupted removal instead of carrying material forward.
            await removeAll(tenantId, secretId);
            report.skippedRemoved += 1;
            return;
          }
          await mkdir(dirFor(tenantId, secretId), { recursive: true, mode: 0o700 });
          for (const version of await versionNumbers(tenantId, secretId)) {
            const target = versionFile(tenantId, secretId, version);
            const existing = await readVersion(tenantId, secretId, version);
            if (existing && existing.kid === currentKid) {
              report.alreadyCurrent += 1;
              continue;
            }
            const entry = existing ? { ...existing } : (await sealed(tenantId, secretId, version))!;
            const plaintext = decrypt(tenantId, secretId, { ...entry, kid: existing ? existing.kid : null });
            const file: VersionFile = {
              ...seal(tenantId, secretId, version, plaintext),
              seal: existing?.seal ?? randomBytes(16).toString('base64url'),
              storedAt: entry.storedAt,
            };
            if (existing) {
              // Replace in place: readers see the old or the new file, and both open while both keys are configured.
              const staging = temporary(target);
              await writeFile(staging, JSON.stringify(file), { mode: 0o600 });
              if (await removed(tenantId, secretId)) {
                await unlink(staging).catch(ignoreMissing);
                return;
              }
              await rename(staging, target);
              report.resealed += 1;
            } else if (await publish(target, file)) {
              report.migrated += 1;
            }
            // A removal that started meanwhile must not be undone by this write.
            if (await removed(tenantId, secretId)) {
              await removeAll(tenantId, secretId);
              return;
            }
          }
          // Every format-1 version now has a format-2 file: the old file holds nothing that is not elsewhere.
          await unlink(legacyFileFor(tenantId, secretId)).catch(ignoreMissing);
        });
      }
      return report;
    },
  };
}
