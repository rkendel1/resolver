#!/usr/bin/env node
/**
 * `resolver` command line.
 *
 *   resolver init  [--dir .resolver] [--tenant default]      create keys and the first admin API key
 *   resolver serve [--dir .resolver] [--port 4300] [--host 127.0.0.1]
 *   resolver backup <out-dir>                                state, then vault, with a manifest
 *   resolver restore <backup-dir>                            into empty state and vault, then verify
 *   resolver verify                                          state against vault (exit 1 on problems)
 *   resolver vault rotate                                    re-seal every version under RESOLVER_VAULT_KEY
 *
 * These run against the state and vault directly (configuration below). Configuration, all optional
 * except as noted:
 *   RESOLVER_ENV=production|development      default production (outbound fails closed)
 *   RESOLVER_FELTDB_URL, RESOLVER_FELTDB_TOKEN a FeltDB server (required for several hosts)
 *   RESOLVER_STATE_SHARED=1                    local state opened by several processes on one host
 *   RESOLVER_MULTI_INSTANCE=1                  several instances share the state (checked at startup)
 *   RESOLVER_VAULT_DIR                         default <dir>/vault (shared by every instance)
 *   RESOLVER_VAULT_KEY, RESOLVER_VAULT_PREVIOUS_KEYS (comma-separated)  default <dir>/vault.key
 *   RESOLVER_VERIFIER_KEY                      default <dir>/verifier.key
 *   RESOLVER_OUTBOUND_ORIGINS                  comma-separated origins agent discovery may contact
 *   RESOLVER_OUTBOUND_PRIVATE_NETWORKS         comma-separated CIDRs allowed although not public
 *   RESOLVER_OUTBOUND_ALLOW_HTTP=1
 *   RESOLVER_SYNC_INTERVAL_MS                  default 1000
 *   RESOLVER_INSTANCE_ID, RESOLVER_LOG_LEVEL=debug|info|warn|error|off   (JSON lines on stdout)
 *   RESOLVER_VERIFY_ON_START=1                 integrity check at startup; not ready on problems
 *
 * Everything else talks to a running resolver (RESOLVER_URL, RESOLVER_API_KEY), so every change is
 * authorized, recorded and pushed to running consumers exactly like any other client's:
 *
 *   resolver get <ref> [--key K] [--revision N] [--reveal]
 *   resolver set <ref> --kind <kind> (--value JSON | --binding JSON | --secret-stdin) [--reason R] [--ttl S] [--schema JSON]
 *   resolver history <ref> | rollback <ref> <revision> | revoke <ref> | list [prefix] | watch [prefix]
 *   resolver keys create <name> [--grant actions:pattern]... | keys list | keys revoke <id>
 *   resolver grant <subject> <actions> <pattern> | grants | ungrant <id>
 */

import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ResolverClient } from '@appport/resolver-client';
import { createBackup, restoreBackup } from './backup.js';
import { createLogger, silentLogger, type LogLevel } from './log.js';
import { createResolverRuntime, type ResolverRuntimeOptions } from './runtime.js';
import { createVault, parseVaultKey } from './vault.js';

export interface CliIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
  stdin: () => Promise<string>;
  env: Record<string, string | undefined>;
  /** Resolves when the process should stop serving (SIGINT/SIGTERM in the real CLI). */
  untilStopped?: () => Promise<void>;
}

const USAGE = `usage: resolver <init|serve|backup|restore|verify|vault|get|set|history|rollback|revoke|list|watch|keys|grant|grants|ungrant> ...
See the README for every option.`;

function parse(argv: string[]): { positional: string[]; flags: Map<string, string[]> } {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const [name, inline] = arg.slice(2).split('=', 2) as [string, string | undefined];
    const boolean = ['reveal', 'secret-stdin', 'json'].includes(name);
    const value = inline ?? (boolean ? 'true' : argv[++i]);
    if (value === undefined) throw new Error(`--${name} needs a value`);
    flags.set(name, [...(flags.get(name) ?? []), value]);
  }
  return { positional, flags };
}

function readKeyFile(file: string, generate: () => string): string {
  if (!existsSync(file)) {
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, generate() + '\n', { mode: 0o600, flag: 'wx' });
  }
  return readFileSync(file, 'utf8').trim();
}

const list = (value: string | undefined) => (value ?? '').split(',').map((v) => v.trim()).filter(Boolean);

/** Everything `serve`, `init`, `backup`, `restore`, `verify` and `vault` need, from flags and the environment. */
function runtimeOptions(flags: Map<string, string[]>, env: CliIo['env'], log = false): ResolverRuntimeOptions {
  const dir = path.resolve(flags.get('dir')?.[0] ?? env['RESOLVER_DIR'] ?? '.resolver');
  const vaultKey = parseVaultKey(env['RESOLVER_VAULT_KEY'] ?? readKeyFile(path.join(dir, 'vault.key'), () => randomBytes(32).toString('hex')));
  const previousVaultKeys = list(env['RESOLVER_VAULT_PREVIOUS_KEYS']).map(parseVaultKey);
  const verifierKey = env['RESOLVER_VERIFIER_KEY'] ?? readKeyFile(path.join(dir, 'verifier.key'), () => randomBytes(32).toString('hex'));
  const feltdbUrl = flags.get('feltdb-url')?.[0] ?? env['RESOLVER_FELTDB_URL'];
  const state: ResolverRuntimeOptions['state'] = feltdbUrl
    ? { remote: { url: feltdbUrl, ...(env['RESOLVER_FELTDB_TOKEN'] ? { token: env['RESOLVER_FELTDB_TOKEN'] } : {}) } }
    : { local: dir, ...(env['RESOLVER_STATE_SHARED'] === '1' ? { shared: true } : {}) };
  const environment = (env['RESOLVER_ENV'] ?? 'production') as ResolverRuntimeOptions['environment'];
  const level = env['RESOLVER_LOG_LEVEL'] ?? 'info';
  const instanceId = env['RESOLVER_INSTANCE_ID'];
  return {
    state,
    environment,
    multiInstance: env['RESOLVER_MULTI_INSTANCE'] === '1',
    vaultKey,
    previousVaultKeys,
    vaultDirectory: path.resolve(env['RESOLVER_VAULT_DIR'] ?? path.join(dir, 'vault')),
    verifierKey,
    outbound: {
      allowedOrigins: list(env['RESOLVER_OUTBOUND_ORIGINS']),
      allowPrivateNetworks: list(env['RESOLVER_OUTBOUND_PRIVATE_NETWORKS']),
      ...(env['RESOLVER_OUTBOUND_ALLOW_HTTP'] === '1' ? { allowHttp: true } : {}),
    },
    ...(env['RESOLVER_SYNC_INTERVAL_MS'] ? { sync: { intervalMs: Number(env['RESOLVER_SYNC_INTERVAL_MS']) } } : {}),
    ...(env['RESOLVER_VERIFY_ON_START'] === '1' ? { verifyIntegrityOnStart: true } : {}),
    ...(instanceId ? { instanceId } : {}),
    logger: log && level !== 'off' ? createLogger({ instance: instanceId ?? `resolver-${process.pid}`, level: level as LogLevel }) : silentLogger(),
  };
}

function localRuntime(flags: Map<string, string[]>, env: CliIo['env'], log = false) {
  return createResolverRuntime(runtimeOptions(flags, env, log));
}

function json(value: unknown, io: CliIo) {
  io.stdout(JSON.stringify(value, null, 2));
}

export async function main(argv: string[], io: CliIo): Promise<number> {
  let parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    io.stderr(`error: ${(error as Error).message}`);
    return 2;
  }
  const { positional, flags } = parsed;
  const [command, ...rest] = positional;
  const flag = (name: string) => flags.get(name)?.[0];

  try {
    if (command === 'init') {
      const tenant = flag('tenant') ?? 'default';
      const runtime = await localRuntime(flags, io.env);
      try {
        const operator = runtime.operator(tenant);
        const key = await runtime.resolver.createKey(operator, { name: flag('name') ?? 'admin' });
        await runtime.resolver.grant(operator, { subject: key.principal, actions: ['admin', 'read', 'write', 'reveal'], pattern: '*' });
        io.stderr(`Created an admin API key for tenant "${tenant}". It is shown once; store it in your secret manager.`);
        io.stdout(key.secret);
        return 0;
      } finally {
        await runtime.close();
      }
    }

    if (command === 'serve') {
      const runtime = await localRuntime(flags, io.env, true);
      const server = await runtime.serve({ port: Number(flag('port') ?? io.env['PORT'] ?? 4300), host: flag('host') ?? '127.0.0.1' });
      io.stderr(`resolver listening on ${server.url}`);
      await (io.untilStopped?.() ?? new Promise<void>(() => undefined));
      await runtime.close();
      return 0;
    }

    if (command === 'backup' || command === 'restore' || command === 'verify' || command === 'vault') {
      const options = runtimeOptions(flags, io.env);
      const vault = createVault({ directory: options.vaultDirectory!, key: options.vaultKey!, previousKeys: options.previousVaultKeys ?? [] });
      if (command === 'vault') {
        if (rest[0] !== 'rotate') {
          io.stderr('usage: resolver vault rotate');
          return 2;
        }
        const report = await vault.rotate();
        json({ currentKey: vault.keys.current, ...report }, io);
        return 0;
      }
      const runtime = await createResolverRuntime({ ...options, custody: vault, management: false });
      try {
        if (command === 'backup') {
          if (!rest[0]) throw new Error('usage: resolver backup <out-dir>');
          const manifest = await createBackup({ db: runtime.db, vault, out: path.resolve(rest[0]) });
          json({ out: path.resolve(rest[0]), sequence: manifest.sequence, rows: Object.fromEntries(Object.entries(manifest.collections).map(([k, v]) => [k, v.rows])), vaultFiles: Object.keys(manifest.vault.files).length, requiredVaultKeys: manifest.requiredVaultKeys }, io);
          return 0;
        }
        if (command === 'restore') {
          if (!rest[0]) throw new Error('usage: resolver restore <backup-dir>');
          const { manifest, integrity } = await restoreBackup({ from: path.resolve(rest[0]), db: runtime.db, vault });
          json({ restoredSequence: manifest.sequence, integrity }, io);
          if (!integrity.ok) io.stderr('error: the restored state and vault do not agree; do not start the resolver until the problems are resolved');
          return integrity.ok ? 0 : 1;
        }
        const integrity = await runtime.integrity();
        json(integrity, io);
        return integrity.ok ? 0 : 1;
      } finally {
        await runtime.close();
      }
    }

    const url = flag('url') ?? io.env['RESOLVER_URL'];
    const apiKey = io.env['RESOLVER_API_KEY'];
    if (!command) {
      io.stderr(USAGE);
      return 2;
    }
    if (!url || !apiKey) {
      io.stderr('error: set RESOLVER_URL and RESOLVER_API_KEY (from `resolver init` or `resolver keys create`)');
      return 2;
    }
    const client = new ResolverClient({ url, apiKey, live: command === 'watch' });
    try {
      switch (command) {
        case 'get': {
          const ref = rest[0]!;
          if (flag('reveal')) {
            io.stdout(await client.secret(ref));
            return 0;
          }
          const key = flag('key');
          const revision = flag('revision');
          json(await client.resolve(ref, { ...(key ? { key } : {}), ...(revision ? { revision: Number(revision) } : {}) }), io);
          return 0;
        }
        case 'set': {
          const ref = rest[0]!;
          const kind = flag('kind');
          const input: Record<string, unknown> = {};
          if (kind) input['kind'] = kind;
          if (flag('value') !== undefined) input['binding'] = { value: JSON.parse(flag('value')!) };
          if (flag('binding') !== undefined) input['binding'] = JSON.parse(flag('binding')!);
          if (flag('schema') !== undefined) input['schema'] = JSON.parse(flag('schema')!);
          if (flag('secret-stdin')) input['secret'] = (await io.stdin()).replace(/\r?\n$/, '');
          if (flag('reason')) input['reason'] = flag('reason');
          if (flag('ttl')) input['ttlSeconds'] = Number(flag('ttl'));
          json(await client.set(ref, input as never), io);
          return 0;
        }
        case 'history':
          json(await client.history(rest[0]!), io);
          return 0;
        case 'rollback': {
          const current = await client.resolve(rest[0]!);
          json(await client.rollback(rest[0]!, Number(rest[1]), current.currentRevision, flag('reason')), io);
          return 0;
        }
        case 'revoke': {
          const current = await client.resolve(rest[0]!);
          json(await client.revoke(rest[0]!, current.currentRevision, flag('reason')), io);
          return 0;
        }
        case 'list':
          json(await client.list(rest[0]), io);
          return 0;
        case 'watch': {
          const prefix = rest[0] ?? 'ref://';
          client.watch(prefix.endsWith('/') || prefix === 'ref://' ? prefix : prefix, (event) => io.stdout(JSON.stringify(event)));
          await (io.untilStopped?.() ?? new Promise<void>(() => undefined));
          return 0;
        }
        case 'keys': {
          const [sub, arg] = rest;
          if (sub === 'create') {
            const key = await client.createKey(arg!);
            for (const spec of flags.get('grant') ?? []) {
              const at = spec.indexOf(':');
              await client.grant(key.principal, spec.slice(0, at).split(','), spec.slice(at + 1));
            }
            io.stderr(`principal ${key.principal}. The key is shown once:`);
            io.stdout(key.secret);
            return 0;
          }
          if (sub === 'list') return json(await client.listKeys(), io), 0;
          if (sub === 'revoke') return json(await client.revokeKey(arg!), io), 0;
          break;
        }
        case 'grant':
          json(await client.grant(rest[0]!, rest[1]!.split(','), rest[2]!), io);
          return 0;
        case 'grants':
          json(await client.grants(), io);
          return 0;
        case 'ungrant':
          json(await client.ungrant(rest[0]!), io);
          return 0;
      }
      io.stderr(USAGE);
      return 2;
    } finally {
      await client.close();
    }
  } catch (error) {
    const e = error as { code?: string; reason?: string; message?: string };
    io.stderr(`error: ${e.code ? `${e.code}${e.reason ? ` (${e.reason})` : ''}: ` : ''}${e.message ?? String(error)}`);
    return 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const stop = new Promise<void>((resolve) => {
    process.once('SIGINT', () => resolve());
    process.once('SIGTERM', () => resolve());
  });
  const code = await main(process.argv.slice(2), {
    stdout: (line) => process.stdout.write(line + '\n'),
    stderr: (line) => process.stderr.write(line + '\n'),
    stdin: async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
      return Buffer.concat(chunks).toString('utf8');
    },
    env: process.env,
    untilStopped: () => stop,
  });
  process.exit(code);
}
