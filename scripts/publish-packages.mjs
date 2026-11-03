// Publishes the workspace packages to npm in dependency order.
// Reads NPM_TOKEN from the environment (loaded from .env.local by the npm script).
// Usage: npm run publish:packages [-- --dry-run] [-- --skip-tests]
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PACKAGES = ['core', 'client', 'server'];
const dryRun = process.argv.includes('--dry-run');
const skipTests = process.argv.includes('--skip-tests');

if (!process.env.NPM_TOKEN) {
  console.error('NPM_TOKEN is not set. Add it to .env.local or the environment.');
  process.exit(1);
}

// The token stays in the environment; npm expands ${NPM_TOKEN} in the config file.
const dir = mkdtempSync(join(tmpdir(), 'resolver-npm-'));
const userconfig = join(dir, 'npmrc');
writeFileSync(userconfig, '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n');
const env = { ...process.env, npm_config_userconfig: userconfig };

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', env, ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed`);
}

function published(name, version) {
  const r = spawnSync('npm', ['view', `${name}@${version}`, 'version'], { encoding: 'utf8', env });
  return r.status === 0 && r.stdout.trim() === version;
}

try {
  run('npm', ['run', 'build']);
  if (!skipTests) run('npm', ['test']);

  for (const pkg of PACKAGES) {
    const { name, version } = JSON.parse(
      (await import('node:fs')).readFileSync(`packages/${pkg}/package.json`, 'utf8'),
    );
    if (published(name, version)) {
      console.log(`- ${name}@${version} already published, skipping`);
      continue;
    }
    console.log(`- publishing ${name}@${version}${dryRun ? ' (dry run)' : ''}`);
    run('npm', ['publish', '-w', `packages/${pkg}`, '--access', 'public', ...(dryRun ? ['--dry-run'] : [])]);
  }
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
} finally {
  rmSync(dir, { recursive: true, force: true });
}
