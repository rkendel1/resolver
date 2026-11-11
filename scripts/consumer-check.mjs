#!/usr/bin/env node
/**
 * Dependency integrity from a consumer's side: install the packed `@appport/resolver-client` (this checkout, built and
 * `npm pack`ed, never a workspace alias) beside `@feltdb/feltkit` from the npm registry in an otherwise empty project,
 * and prove that npm resolves one copy of every `@appport/*` package, none from the 1.6 line, and that the AppPort
 * protocol the client resolves is the very module FeltKit and the SDK resolve (so feedback receipts digested by one
 * validate under the other).
 *
 *   node scripts/consumer-check.mjs [--keep] [--feltkit <npm spec or path to a packed @feltdb/feltkit tarball>]
 *
 * The published FeltKit still pins `@appport/resolver-client` 0.2.2, so the consumer points that one dependency at the
 * packed tarball with an npm override: that is what a FeltKit release depending on this client will install, and it is
 * the consumer project's test scaffolding, not an override in any published package.
 *
 * Two groups of assertions. What this package controls holds whatever FeltKit is beside it: the client brings the 1.7
 * SDK line, nests no SDK of its own, and resolves the same protocol module as the SDK. The whole graph (one copy of every
 * @appport/* package, one protocol module for FeltKit too) holds once FeltKit's own pins are on protocol 1.5.0: the
 * published 0.3.18 still pins 1.4.1 (its alignment is on FeltKit's main, unreleased), so against the registry that part
 * is reported, not failed; against an aligned FeltKit (`--feltkit <tarball>`) it is required.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const env = { ...process.env, NO_COLOR: '1', npm_config_audit: 'false', npm_config_fund: 'false', npm_config_update_notifier: 'false' };
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 900_000, maxBuffer: 64 * 1024 * 1024 });
const say = (t) => process.stdout.write(`${t}\n`);
const problems = [];
const check = (ok, message) => (ok ? say(`✓ ${message}`) : problems.push(message));
const keep = process.argv.includes('--keep');
const feltkitArg = process.argv.indexOf('--feltkit');
const feltkitSpec = feltkitArg >= 0 ? process.argv[feltkitArg + 1] : '0.3.22';
const feltkitDependency = /\.tgz$/.test(feltkitSpec) ? `file:${feltkitSpec.startsWith('/') ? feltkitSpec : join(process.cwd(), feltkitSpec)}` : feltkitSpec;

const work = mkdtempSync(join(tmpdir(), 'resolver-consumer-'));
try {
  // The release artifacts of this checkout: core (the client depends on it exactly) and the client.
  run('npm', ['run', 'build'], root);
  const pack = (pkg) => {
    const out = run('npm', ['pack', '--pack-destination', work, '--json'], join(root, 'packages', pkg));
    return JSON.parse(out.slice(out.search(/^\[/m)))[0].filename;
  };
  const coreTgz = pack('core');
  const clientTgz = pack('client');
  const clientPkg = JSON.parse(readFileSync(join(root, 'packages/client/package.json'), 'utf8'));
  say(`Packed ${coreTgz} and ${clientTgz}`);

  // An otherwise empty consumer: FeltKit from the registry, this client from its tarball.
  const consumer = join(work, 'consumer');
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, 'package.json'),
    `${JSON.stringify(
      {
        name: 'resolver-client-consumer',
        private: true,
        version: '0.0.0',
        type: 'module',
        dependencies: { '@feltdb/feltkit': feltkitDependency, '@appport/resolver-client': `file:${join(work, clientTgz)}` },
        overrides: { '@appport/resolver-client': `file:${join(work, clientTgz)}`, '@appport/resolver-core': `file:${join(work, coreTgz)}` },
      },
      null,
      2,
    )}\n`,
  );
  say(`Installing @feltdb/feltkit (${feltkitDependency}) and @appport/resolver-client from its tarball…`);
  run('npm', ['install', '--ignore-scripts', '--no-package-lock'], consumer);

  // One copy of every @appport/* package, none from the 1.6 line.
  const tree = JSON.parse(run('npm', ['ls', '--all', '--json'], consumer));
  const versions = new Map();
  const walk = (deps) => {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (/^@appport\//.test(name)) (versions.get(name) ?? versions.set(name, new Set()).get(name)).add(d.version);
      walk(d.dependencies);
    }
  };
  walk(tree.dependencies);
  const feltkitPkg = JSON.parse(readFileSync(join(consumer, 'node_modules/@feltdb/feltkit/package.json'), 'utf8'));
  const feltkitProtocol = feltkitPkg.dependencies?.['@appport/protocol'] ?? '(none)';
  const feltkitAligned = /^1\.[5-9]\./.test(feltkitProtocol) || /^[2-9]\./.test(feltkitProtocol);
  say(`@feltdb/feltkit ${feltkitPkg.version} pins @appport/protocol ${feltkitProtocol}${feltkitAligned ? '' : ' (not yet on the 1.7 release line: whole-graph assertions are reported, not required)'}`);
  const whole = (ok, message) => (feltkitAligned ? check(ok, message) : say(`${ok ? '✓' : '!'} ${message}${ok ? '' : ' (FeltKit side; required once FeltKit publishes its aligned pins)'}`));
  const duplicates = [...versions].filter(([, v]) => v.size > 1);
  whole(duplicates.length === 0, `one copy of every @appport/* package (${versions.size} packages)${duplicates.length ? `; duplicated: ${duplicates.map(([n, v]) => `${n} ${[...v].join(', ')}`).join('; ')}` : ''}`);
  // The client's contract is its declared range (^1.7.0): any 1.x from 1.7 on, never the 1.6 line or a 2.x.
  const inRange = (v) => { const [maj, min] = v.split('.').map(Number); return maj === 1 && min >= 7; };
  whole([...versions.get('@appport/sdk') ?? []].every(inRange), `@appport/sdk resolves within ^1.7.0 only (${[...(versions.get('@appport/sdk') ?? [])].join(', ')})`);
  const clientSdk = JSON.parse(run(process.execPath, ['-e', 'const {createRequire}=require("node:module");const {join}=require("node:path");const {existsSync,readFileSync}=require("node:fs");const from=join(process.cwd(),"node_modules/@appport/resolver-client/package.json");const d=(createRequire(from).resolve.paths("@appport/sdk")||[]).map(p=>join(p,"@appport/sdk")).find(d=>existsSync(join(d,"package.json")));console.log(JSON.stringify({version:JSON.parse(readFileSync(join(d,"package.json"),"utf8")).version,dir:d}))'], consumer));
  check(inRange(clientSdk.version), `the SDK resolver-client resolves is ${clientSdk.version}, within its ^1.7.0 (${clientSdk.dir})`);
  whole([...versions.get('@appport/protocol') ?? []].every((v) => v === '1.5.0'), `@appport/protocol resolves to 1.5.0 only (${[...(versions.get('@appport/protocol') ?? [])].join(', ')})`);
  check([...versions.get('@appport/resolver-client') ?? []].join() === clientPkg.version, `@appport/resolver-client is ${clientPkg.version} (the packed one)`);
  const nestedSdk = join(consumer, 'node_modules/@appport/resolver-client/node_modules/@appport/sdk');
  check(!existsSync(nestedSdk), 'no SDK nested under resolver-client');
  const clientDir = join(consumer, 'node_modules/@appport/resolver-client');
  check(existsSync(clientDir) && !lstatSync(clientDir).isSymbolicLink(), 'resolver-client is an installed copy, not a link');

  // Protocol identity across the package boundary: FeltKit, the SDK and resolver-client load one protocol module, and a
  // feedback report digested through FeltKit's import validates through resolver-client's.
  const probe = `
    import { createRequire } from "node:module";
    import { join } from "node:path";
    import { existsSync } from "node:fs";
    import { pathToFileURL } from "node:url";
    const dirOf = (from, name) => { const paths = createRequire(join(from, "package.json")).resolve.paths(name) ?? []; const d = paths.map((p) => join(p, ...name.split("/"))).find((d) => existsSync(join(d, "package.json"))); if (!d) throw new Error(name + " not resolvable from " + from); return d; };
    const root = process.cwd();
    const { ResolverClient } = await import("@appport/resolver-client");
    if (typeof ResolverClient !== "function") throw new Error("@appport/resolver-client does not export ResolverClient");
    const feltkit = dirOf(root, "@feltdb/feltkit");
    const client = dirOf(root, "@appport/resolver-client");
    const sdk = dirOf(client, "@appport/sdk");
    const a = dirOf(feltkit, "@appport/protocol"), b = dirOf(client, "@appport/protocol"), c = dirOf(sdk, "@appport/protocol");
    const viaSdk = await import(pathToFileURL(join(c, "dist/index.js")).href);
    const viaClient = await import(pathToFileURL(join(b, "dist/index.js")).href);
    const viaFeltKit = await import(pathToFileURL(join(a, "dist/index.js")).href);
    const report = { protocol: viaClient.FEEDBACK_PROTOCOL, category: "unexpected_behavior", severity: "high", summary: "a summary", expected: "x", observed: "y", reproduction: { steps: ["call it"] }, evidence: [], context: { correlationId: "task_1" } };
    console.log(JSON.stringify({ protocol: viaClient.FEEDBACK_PROTOCOL, clientSdkSame: b === c && viaSdk.validateFeedbackReport === viaClient.validateFeedbackReport, feltkitSame: a === b && viaFeltKit.validateFeedbackReport === viaClient.validateFeedbackReport, valid: viaClient.validateFeedbackReport(report).ok, sameDigest: viaClient.digestOf(report) === viaSdk.digestOf(report) && (a !== b || viaFeltKit.digestOf(report) === viaClient.digestOf(report)), dirs: [a, b, c] }));
  `;
  writeFileSync(join(consumer, 'probe.mjs'), probe);
  const out = JSON.parse(run(process.execPath, ['probe.mjs'], consumer).trim());
  check(out.protocol === 'appport.feedback/1' && out.clientSdkSame && out.sameDigest, `resolver-client and the SDK load one @appport/protocol module (${out.dirs[1]}); an appport.feedback/1 report digests the same through either`);
  whole(out.feltkitSame, `FeltKit loads that same protocol module${out.feltkitSame ? '' : ` (it loads ${out.dirs[0]})`}`);
} finally {
  if (keep) say(`kept ${work}`);
  else rmSync(work, { recursive: true, force: true });
}

if (problems.length) {
  for (const p of problems) process.stderr.write(`✗ ${p}\n`);
  process.exit(1);
}
say(`Consumer check passed: ${process.exitCode ? '' : ''}resolver-client brings one coherent AppPort 1.7 graph beside @feltdb/feltkit${process.env.CONSUMER_CHECK_ALIGNED === '1' ? '' : ' (whole-graph assertions were required only if FeltKit\'s own pins are on protocol 1.5.0: see the lines above)'}.`);
