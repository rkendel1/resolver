// The governance commands, as an operator and a writer use them: the resolver's own CLI against a served state.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { generateSigningKey, signChangeAuthorization } from '@appport/resolver-client/authorization';
import { main, type CliIo } from '../src/cli.js';

const dir = mkdtempSync(path.join(tmpdir(), 'resolver-gov-cli-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function io(env: Record<string, string> = {}, stdin = ''): CliIo & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, stdout: (l) => out.push(l), stderr: (l) => err.push(l), stdin: async () => stdin, env: { RESOLVER_STATE_SHARED: '1', ...env } };
}

describe('governance through the CLI', () => {
  it('operator sets the trust roots on the host; writers need an authorization; break-glass is explicit and recorded', async () => {
    const init = io();
    expect(await main(['init', '--dir', dir, '--tenant', 'acme'], init)).toBe(0);
    const env = { RESOLVER_API_KEY: init.out[0]! };
    let stop!: () => void;
    const serving = io();
    serving.untilStopped = () => new Promise<void>((r) => (stop = r));
    const port = 44000 + Math.floor(Math.random() * 1000);
    const served = main(['serve', '--dir', dir, '--port', String(port)], serving);
    await new Promise((r) => setTimeout(r, 500));
    const net = { ...env, RESOLVER_URL: `http://127.0.0.1:${port}` };
    try {
      expect(await main(['set', 'ref://prod/limits', '--kind', 'value', '--value', '{"rps":10}'], io(net))).toBe(0);

      const { publicKey, privateKeyPem } = generateSigningKey();
      const local = (args: string[]) => main([...args, '--dir', dir, '--tenant', 'acme'], io());
      expect(await local(['signing-key', 'add', 'rc-1', '--issuer', 'resolver-control', '--public-key', publicKey, '--reason', 'approvals'])).toBe(0);
      // no reason: refused
      expect(await local(['policy', 'set', 'prod', '--pattern', 'ref://prod/*', '--operations', 'put,rollback,revoke', '--issuer', 'resolver-control'])).toBe(1);
      expect(await local(['policy', 'set', 'prod', '--pattern', 'ref://prod/*', '--operations', 'put,rollback,revoke', '--issuer', 'resolver-control', '--reason', 'prod is governed'])).toBe(0);

      const refused = io(net);
      expect(await main(['set', 'ref://prod/limits', '--value', '{"rps":20}'], refused)).toBe(1);
      expect(refused.err.join('\n')).toContain('resolver.authorization-required');

      const token = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'rc-1', issuer: 'resolver-control', tenant: 'acme', ref: 'ref://prod/limits', op: 'put', expectedRevision: 1, request: { kind: 'value', binding: { value: { rps: 20 } } }, decision: 'CHG-7' });
      expect(await main(['set', 'ref://prod/limits', '--kind', 'value', '--value', '{"rps":20}', '--authorization', token], io(net))).toBe(0);

      expect(await local(['break-glass', 'set', 'ref://prod/limits', '--value', '{"rps":1}'])).toBe(1); // no reason
      expect(await local(['break-glass', 'set', 'ref://prod/limits', '--value', '{"rps":1}', '--reason', 'incident 77: shed load'])).toBe(0);

      const history = io(net);
      expect(await main(['history', 'ref://prod/limits'], history)).toBe(0);
      const entries = JSON.parse(history.out.join('\n')).entries;
      expect(entries.map((e: { governance?: { mode: string } }) => e.governance?.mode ?? null)).toEqual([null, 'authorized', 'break-glass']);

      const governance = io(net);
      expect(await main(['governance'], governance)).toBe(0);
      const types = JSON.parse(governance.out.join('\n')).events.map((e: { type: string }) => e.type);
      expect(types).toEqual(expect.arrayContaining(['signing-key.added', 'policy.set', 'break-glass']));
    } finally {
      stop();
      await served;
    }
  });
});
