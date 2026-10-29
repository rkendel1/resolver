import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { main, type CliIo } from '../src/cli.js';

const dir = mkdtempSync(path.join(tmpdir(), 'resolver-cli-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function io(env: Record<string, string> = {}, stdin = ''): CliIo & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, stdout: (l) => out.push(l), stderr: (l) => err.push(l), stdin: async () => stdin, env: { ...env } };
}

describe('resolver CLI', () => {
  it('initializes, serves, and manages references end to end', async () => {
    const init = io();
    expect(await main(['init', '--dir', dir, '--tenant', 'acme'], init)).toBe(0);
    const adminKey = init.out[0]!;
    expect(adminKey).toMatch(/^app_live_/);
    expect(statSync(path.join(dir, 'vault.key')).mode & 0o077).toBe(0);

    let stop!: () => void;
    const serving = io();
    serving.untilStopped = () => new Promise<void>((r) => (stop = r));
    const port = 43000 + Math.floor(Math.random() * 1000);
    const served = main(['serve', '--dir', dir, '--port', String(port)], serving);
    await new Promise((r) => setTimeout(r, 400));
    const env = { RESOLVER_URL: `http://127.0.0.1:${port}`, RESOLVER_API_KEY: adminKey };

    expect(await main(['set', 'ref://prod/llm/key', '--kind', 'secret', '--secret-stdin'], io(env, 'sk-from-stdin\n'))).toBe(0);
    expect(await main(['set', 'ref://prod/chat/model', '--kind', 'model', '--value', '{"provider":"openai","model":"gpt-4o","credential":"ref://prod/llm/key"}', '--reason', 'launch'], io(env))).toBe(0);
    expect(await main(['set', 'ref://prod/chat/model', '--value', '{"provider":"openai","model":"gpt-4o-mini","credential":"ref://prod/llm/key"}', '--reason', 'cheaper'], io(env))).toBe(0);

    const got = io(env);
    expect(await main(['get', 'ref://prod/chat/model'], got)).toBe(0);
    expect(JSON.parse(got.out.join('\n')).selected.value.model).toBe('gpt-4o-mini');

    const secret = io(env);
    expect(await main(['get', 'ref://prod/llm/key', '--reveal'], secret)).toBe(0);
    expect(secret.out).toEqual(['sk-from-stdin']);

    expect(await main(['rollback', 'ref://prod/chat/model', '1', '--reason', 'quality'], io(env))).toBe(0);
    const history = io(env);
    await main(['history', 'ref://prod/chat/model'], history);
    expect(JSON.parse(history.out.join('\n')).entries.map((e: { action: string }) => e.action)).toEqual(['create', 'update', 'rollback']);

    const key = io(env);
    expect(await main(['keys', 'create', 'checkout', '--grant', 'read:ref://prod/chat/*'], key)).toBe(0);
    const narrow = io({ ...env, RESOLVER_API_KEY: key.out[0]! });
    expect(await main(['get', 'ref://prod/llm/key', '--reveal'], narrow)).toBe(1);
    expect(narrow.err.join('\n')).toContain('FORBIDDEN');

    const missing = io({});
    expect(await main(['get', 'ref://prod/x'], missing)).toBe(2);
    stop();
    expect(await served).toBe(0);
  });
});
