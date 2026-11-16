import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const built = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

describe('resolver bin', () => {
  // npm installs `resolver` as a symlink to dist/cli.js; the CLI used to compare the unresolved path
  // with its own URL, do nothing, and exit 0.
  it.skipIf(!existsSync(built))('runs when invoked through a symlink, as a global install does', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-bin-'));
    try {
      const link = path.join(dir, 'resolver');
      symlinkSync(built, link);
      let output = '';
      try {
        output = execFileSync(process.execPath, [link, 'no-such-command'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (error) {
        const e = error as { status: number; stdout: string; stderr: string };
        expect(e.status).not.toBe(0);
        output = `${e.stdout}${e.stderr}`;
      }
      expect(output.trim().length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
