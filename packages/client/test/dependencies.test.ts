/**
 * Regression: `@appport/resolver-client` follows the AppPort 1.7 release line, and resolves one copy of the AppPort
 * packages with everything beside it. 0.2.2 pinned `@appport/sdk` 1.6.0 while FeltKit (and this workspace's own
 * server) were on 1.7.0, so an application installing both received two AppPort dependency graphs: two protocol
 * modules, two sets of SDK types, receipts digested by one copy that the other could not verify. The range here is
 * what keeps that from coming back; the resolution checks are what the range is for.
 */
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const clientDir = join(here, '..');
const clientPkg = JSON.parse(readFileSync(join(clientDir, 'package.json'), 'utf8')) as { version: string; dependencies: Record<string, string> };
const requireFromClient = createRequire(join(clientDir, 'package.json'));
/** A package's root as Node resolves it from `fromDir` (its export map may hide package.json from require.resolve). */
const packageDir = (fromDir: string, name: string): string => {
  const candidates = createRequire(join(fromDir, 'package.json')).resolve.paths(name) ?? [];
  const found = candidates.map((c) => join(c, ...name.split('/'))).find((d) => existsSync(join(d, 'package.json')));
  if (!found) throw new Error(`${name} is not resolvable from ${fromDir}`);
  return found;
};
const manifest = (dir: string) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name: string; version: string; dependencies?: Record<string, string>; exports?: Record<string, { import?: string }> };
const semver = (v: string) => v.split('.').map(Number) as [number, number, number];
const atLeast = (v: string, floor: string) => {
  const [a, b] = [semver(v), semver(floor)];
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
};

describe('@appport/resolver-client depends on the AppPort 1.7 release line', () => {
  it('declares a caret range from 1.7.0, never the 1.6.0 pin', () => {
    const range = clientPkg.dependencies['@appport/sdk'];
    expect(range).toMatch(/^\^1\.([7-9]|\d{2,})\.\d+$/);
    // A caret range from 1.7.0 admits 1.7.x and later minors below 2.0.0, and nothing from the 1.6 line.
    const floor = range.slice(1);
    expect(atLeast(floor, '1.7.0')).toBe(true);
    expect(atLeast('1.6.0', floor)).toBe(false);
  });

  it('resolves @appport/sdk 1.7.0 or later, and every package it brings at the version the SDK pins', () => {
    const sdkDir = packageDir(clientDir, '@appport/sdk');
    const sdk = manifest(sdkDir);
    expect(atLeast(sdk.version, '1.7.0')).toBe(true);
    expect(sdk.version).not.toMatch(/^1\.6\./);
    for (const [name, pinned] of Object.entries(sdk.dependencies ?? {})) {
      // Resolved from the SDK's own location: what the SDK itself loads.
      expect(manifest(packageDir(sdkDir, name)).version, name).toBe(pinned);
    }
  });

  it('resolves one @appport/protocol: the same module from the client, from the SDK and from the resolver server', async () => {
    const sdkDir = packageDir(clientDir, '@appport/sdk');
    const serverDir = join(here, '..', '..', 'server');
    const fromClient = packageDir(clientDir, '@appport/protocol');
    expect(packageDir(sdkDir, '@appport/protocol')).toBe(fromClient);
    expect(packageDir(serverDir, '@appport/protocol')).toBe(fromClient);
    expect(packageDir(packageDir(sdkDir, '@appport/core'), '@appport/protocol')).toBe(fromClient);
    expect(manifest(fromClient).version).toBe('1.5.0');
    // Protocol identity across the boundary: the module the client resolves and the one the SDK resolves are one instance,
    // so a feedback receipt digested by one validates under the other (appport.feedback/1, protocol 1.5.0).
    const protocol = (await import(/* @vite-ignore */ pathToFileURL(join(fromClient, manifest(fromClient).exports?.['.']?.import ?? 'dist/index.js')).href)) as { FEEDBACK_PROTOCOL: string; validateFeedbackReport: (r: unknown) => { ok: boolean } };
    const viaSdk = (await import(/* @vite-ignore */ pathToFileURL(join(packageDir(sdkDir, '@appport/protocol'), manifest(fromClient).exports?.['.']?.import ?? 'dist/index.js')).href)) as typeof protocol;
    expect(protocol.FEEDBACK_PROTOCOL).toBe('appport.feedback/1');
    expect(viaSdk.validateFeedbackReport).toBe(protocol.validateFeedbackReport);
  });

  it('uses only what the 1.7 SDK exports: AppPort.discover and the AppPortClient type', async () => {
    const sdk = (await import('@appport/sdk')) as { AppPort: { discover: unknown; connect: unknown } };
    expect(typeof sdk.AppPort.discover).toBe('function');
    expect(typeof sdk.AppPort.connect).toBe('function');
    const source = readFileSync(join(clientDir, 'src', 'client.ts'), 'utf8');
    const imports = [...source.matchAll(/import \{([^}]*)\} from '@appport\/sdk'/g)].flatMap((m) => m[1]!.split(',').map((s) => s.trim().replace(/^type /, '')));
    expect(imports.sort()).toEqual(['AppPort', 'AppPortClient']);
  });
});
