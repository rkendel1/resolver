/**
 * Secret custody for the resolver: an encrypted vault on local disk, outside the state store.
 *
 * Implements `SecretCustody` from @appport/services, so the material lives where AppPort Services
 * expects a host to keep it ("secret values are never FeltDB fields"). Each version is sealed with
 * AES-256-GCM under a 32-byte key the operator supplies, with the tenant, secret id and version as
 * additional authenticated data: a ciphertext moved to another secret or version does not open.
 *
 * Versions are kept, so a reference pinned to an earlier revision can still reveal what it pointed at.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
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

interface SecretFile {
  format: 'resolver.vault/1';
  tenantId: string;
  secretId: string;
  versions: SealedVersion[];
  removedAt?: string;
}

export class VaultError extends Error {
  constructor(
    readonly code: 'MISSING' | 'REVOKED' | 'CORRUPT' | 'VERSION_MISSING',
    message: string,
  ) {
    super(message);
  }
}

/** Custody that can also open a specific stored version (for pinned revisions). */
export interface VersionedCustody extends SecretCustody<string> {
  withSecretVersion<T>(input: ScopedResolveSecretInput & { version: number }, use: (secret: ResolvedSecret<string>) => T | Promise<T>): Promise<T>;
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

export function createVault(options: { directory: string; key: Buffer; now?: () => Date }): VersionedCustody {
  const { directory, key } = options;
  if (key.length !== 32) throw new Error('the vault key must be 32 bytes');
  const now = options.now ?? (() => new Date());
  const queues = new Map<string, Promise<unknown>>();

  const fileFor = (tenantId: string, secretId: string) => {
    const name = createHash('sha256').update(`${tenantId}\u0000${secretId}`).digest('hex');
    return path.join(directory, `${name}.json`);
  };
  const aad = (tenantId: string, secretId: string, version: number) => Buffer.from(`${tenantId}\u0000${secretId}\u0000${version}`);

  async function read(tenantId: string, secretId: string): Promise<SecretFile | undefined> {
    try {
      const file = JSON.parse(await readFile(fileFor(tenantId, secretId), 'utf8')) as SecretFile;
      if (file.format !== 'resolver.vault/1' || file.tenantId !== tenantId || file.secretId !== secretId) {
        throw new VaultError('CORRUPT', 'the vault entry does not belong to this secret');
      }
      return file;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
  }

  async function write(file: SecretFile): Promise<void> {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const target = fileFor(file.tenantId, file.secretId);
    const temporary = `${target}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(temporary, JSON.stringify(file), { mode: 0o600 });
    await rename(temporary, target);
  }

  /** One writer per secret at a time, so versions never collide. */
  function serial<T>(id: string, task: () => Promise<T>): Promise<T> {
    const previous = queues.get(id) ?? Promise.resolve();
    const next = previous.then(task, task);
    queues.set(id, next.catch(() => undefined));
    return next;
  }

  function open(file: SecretFile, version: number): string {
    const sealed = file.versions.find((v) => v.version === version);
    if (!sealed) throw new VaultError('VERSION_MISSING', `version ${version} is not in the vault`);
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
      decipher.setAAD(aad(file.tenantId, file.secretId, version));
      decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
      return Buffer.concat([decipher.update(Buffer.from(sealed.data, 'base64')), decipher.final()]).toString('utf8');
    } catch {
      throw new VaultError('CORRUPT', 'the vault entry could not be opened with this key');
    }
  }

  async function resolveVersion(
    input: ScopedResolveSecretInput,
    version: number | 'current',
  ): Promise<ResolvedSecret<string>> {
    const { secretId, tenantId } = input.reference;
    if (input.context.tenantId !== tenantId) throw new VaultError('MISSING', 'no such secret for this tenant');
    const file = await read(tenantId, secretId);
    if (!file) throw new VaultError('MISSING', 'no such secret');
    if (file.removedAt) throw new VaultError('REVOKED', 'the secret was removed');
    const chosen = version === 'current' ? file.versions.at(-1)?.version : version;
    if (chosen === undefined) throw new VaultError('MISSING', 'no version is stored');
    return {
      value: open(file, chosen),
      secretId,
      version: chosen,
      ...(input.reference.provider ? { provider: input.reference.provider } : {}),
      ...(input.reference.kind ? { kind: input.reference.kind } : {}),
    } as ResolvedSecret<string>;
  }

  return {
    async withSecret(input, use) {
      return use(await resolveVersion(input, 'current'));
    },

    async withSecretVersion(input, use) {
      return use(await resolveVersion(input, input.version));
    },

    store(input): Promise<SecretCustodyWriteResult> {
      const { secretId, tenantId } = input.reference;
      return serial(`${tenantId}/${secretId}`, async () => {
        const file = (await read(tenantId, secretId)) ?? { format: 'resolver.vault/1' as const, tenantId, secretId, versions: [] };
        const version = (file.versions.at(-1)?.version ?? 0) + 1;
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        cipher.setAAD(aad(tenantId, secretId, version));
        const data = Buffer.concat([cipher.update(input.value, 'utf8'), cipher.final()]);
        const storedAt = now().toISOString();
        file.versions.push({ version, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64'), storedAt });
        delete file.removedAt;
        await write(file);
        return { version, storedAt };
      });
    },

    async status(input): Promise<SecretCustodyStatus> {
      const file = await read(input.reference.tenantId, input.reference.secretId);
      if (file?.removedAt) return { state: 'revoked', updatedAt: file.removedAt, location: 'resolver encrypted vault', writable: true };
      const latest = file?.versions.at(-1);
      if (!file || !latest) return { state: 'missing', location: 'resolver encrypted vault', writable: true };
      return {
        state: 'set',
        version: latest.version,
        updatedAt: latest.storedAt,
        location: 'resolver encrypted vault',
        writable: true,
      };
    },

    remove(input): Promise<void> {
      const { secretId, tenantId } = input.reference;
      return serial(`${tenantId}/${secretId}`, async () => {
        const file = await read(tenantId, secretId);
        if (!file) return;
        // Removal destroys the material: a revoked secret must not be recoverable from the vault.
        await write({ ...file, versions: [], removedAt: now().toISOString() });
      });
    },
  };
}
