// SSRF protection for the resolver's own outbound requests (agent discovery). The checks run on the
// address a connection actually uses, not on host name strings; the fixtures below listen on loopback and
// use an injected resolver for host names, so every case runs without the network.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createFeltDB } from '@feltdb/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { classifyAddress, createOutboundPolicy, createResolverRuntime, OutboundRefusedError } from '@appport/resolver';
import { startResolver, type Harness } from './harness.js';

let hits: string[] = [];
let server: Server;
let port: number;
/** A redirect chain on loopback: /hop/N redirects to /hop/N-1, /hop/0 answers. */
beforeAll(async () => {
  server = createServer((request, response) => {
    hits.push(`${request.headers.host} ${request.url}`);
    const hop = /^\/hop\/(\d+)$/.exec(request.url ?? '');
    if (hop && Number(hop[1]) > 0) return response.writeHead(302, { location: `/hop/${Number(hop[1]) - 1}` }).end();
    const to = /^\/to\?(.+)$/.exec(request.url ?? '');
    if (to) return response.writeHead(307, { location: decodeURIComponent(to[1]!) }).end();
    response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as { port: number }).port;
});
afterAll(() => new Promise((r) => server.close(r)));

const refused = async (work: Promise<unknown>, reason: string) => {
  const error = await work.then(() => null, (e) => e);
  expect(error, `expected refusal ${reason}`).toBeInstanceOf(OutboundRefusedError);
  expect((error as OutboundRefusedError).reason).toBe(reason);
};

describe('address classification', () => {
  it.each([
    ['93.184.215.14', 'public'],
    ['8.8.8.8', 'public'],
    ['2606:4700:4700::1111', 'public'],
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['0.0.0.0', 'unspecified'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['100.64.0.1', 'shared-address-space'],
    ['169.254.169.254', 'link-local'], // cloud metadata
    ['224.0.0.1', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
    ['192.0.2.1', 'documentation'],
    ['198.18.0.1', 'benchmarking'],
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['::ffff:127.0.0.1', 'loopback'], // IPv4-mapped, dotted
    ['::ffff:7f00:1', 'loopback'], // IPv4-mapped, hex
    ['::ffff:169.254.169.254', 'link-local'],
    ['::ffff:a00:1', 'private'],
    ['::127.0.0.1', 'ipv4-compatible'],
    ['fc00::1', 'private'],
    ['fd12:3456::1', 'private'],
    ['fe80::1', 'link-local'],
    ['fec0::1', 'site-local'],
    ['ff02::1', 'multicast'],
    ['64:ff9b::7f00:1', 'nat64'],
    ['2001:db8::1', 'documentation'],
    ['2002:7f00:1::1', '6to4'],
    ['2001::1', 'reserved'], // Teredo
    ['4000::1', 'reserved'], // outside global unicast
    ['not-an-ip', 'invalid'],
  ])('%s is %s', (address, kind) => {
    expect(classifyAddress(address)).toBe(kind);
  });
});

describe('outbound policy', () => {
  const lookupTo = (address: string) => async () => [{ address, family: address.includes(':') ? 6 : 4 }];

  it('production without an allowlist contacts nothing (fails closed)', async () => {
    const policy = createOutboundPolicy('production');
    expect(policy.mode).toBe('disabled');
    await refused(policy.fetch('https://agents.example.com/.well-known/appport'), 'outbound.not-configured');
  });

  it('refuses an invalid allowlist at startup', () => {
    expect(() => createOutboundPolicy('production', { allowedOrigins: ['https://a.example.com/path'] })).toThrow(/must be an origin/);
    expect(() => createOutboundPolicy('production', { allowedOrigins: ['http://a.example.com'] })).toThrow(/only https/);
    expect(() => createOutboundPolicy('production', { allowedOrigins: ['https://user:pw@a.example.com'] })).toThrow(/origin/);
    expect(() => createOutboundPolicy('production', { allowedOrigins: ['not a url'] })).toThrow(/not a URL/);
    expect(() => createOutboundPolicy('production', { allowedOrigins: ['https://a.example.com'], allowPrivateNetworks: ['10.0.0.0/33'] })).toThrow(/CIDR/);
    expect(() => createOutboundPolicy('staging' as never)).toThrow(/environment/);
  });

  it('allows an allowlisted origin whose name resolves to an address the configuration permits', async () => {
    const policy = createOutboundPolicy('production', {
      allowedOrigins: [`http://agent.example.test:${port}`],
      allowHttp: true,
      allowPrivateNetworks: ['127.0.0.1/32'],
      lookup: lookupTo('127.0.0.1'),
    });
    const response = await policy.fetch(`http://agent.example.test:${port}/ok`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
  });

  it('refuses origins not on the allowlist, before any request', async () => {
    hits = [];
    const policy = createOutboundPolicy('production', { allowedOrigins: ['https://agents.example.com'], lookup: lookupTo('93.184.215.14') });
    await refused(policy.fetch('https://evil.example.com/'), 'outbound.origin-not-allowed');
    await refused(policy.fetch('https://agents.example.com:8443/'), 'outbound.origin-not-allowed'); // another port is another origin
    await refused(policy.fetch('http://agents.example.com/'), 'outbound.scheme-not-allowed');
    expect(hits).toEqual([]);
  });

  it('refuses loopback, private, link-local and other non-public destinations, however written', async () => {
    hits = [];
    const literals = [
      `http://127.0.0.1:${port}/`,
      `http://2130706433:${port}/`, // 127.0.0.1 as one decimal number
      `http://0x7f.0.0.1:${port}/`, // hex octet
      `http://0177.0.0.1:${port}/`, // octal octet
      `http://127.1:${port}/`, // short form
      `http://[::1]:${port}/`,
      `http://[::ffff:127.0.0.1]:${port}/`,
      `http://[::ffff:7f00:1]:${port}/`,
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.1/',
      'http://192.168.0.1/',
      'http://[fd00::1]/',
      'http://[fe80::1]/',
      'http://0.0.0.0/',
    ];
    // Every origin is allowlisted, so only the address check stands between the request and the target.
    const policy = createOutboundPolicy('production', { allowedOrigins: literals.map((u) => new URL(u).origin), allowHttp: true });
    for (const url of literals) await refused(policy.fetch(url), 'outbound.address-not-allowed');
    expect(hits).toEqual([]);
  });

  it('refuses a name that resolves to a private address (DNS), and a name with any private answer', async () => {
    hits = [];
    const origins = [`http://internal.example.test:${port}`];
    await refused(createOutboundPolicy('production', { allowedOrigins: origins, allowHttp: true, lookup: lookupTo('127.0.0.1') }).fetch(`${origins[0]}/`), 'outbound.address-not-allowed');
    await refused(createOutboundPolicy('production', { allowedOrigins: origins, allowHttp: true, lookup: lookupTo('10.0.0.5') }).fetch(`${origins[0]}/`), 'outbound.address-not-allowed');
    const mixed = createOutboundPolicy('production', {
      allowedOrigins: origins,
      allowHttp: true,
      lookup: async () => [{ address: '93.184.215.14', family: 4 }, { address: '127.0.0.1', family: 4 }],
    });
    await refused(mixed.fetch(`${origins[0]}/`), 'outbound.address-not-allowed');
    expect(hits).toEqual([]);
  });

  it('checks the address on every connection, so a name that changes its answer (rebinding) is caught', async () => {
    hits = [];
    let answers = 0;
    // First answer: an address the configuration allows. Second: loopback that is not allowed.
    const policy = createOutboundPolicy('production', {
      allowedOrigins: [`http://rebind.example.test:${port}`],
      allowHttp: true,
      allowPrivateNetworks: ['127.0.0.1/32'],
      lookup: async () => [{ address: answers++ === 0 ? '127.0.0.1' : '127.0.0.2', family: 4 }],
    });
    expect((await policy.fetch(`http://rebind.example.test:${port}/ok`)).status).toBe(200);
    await refused(policy.fetch(`http://rebind.example.test:${port}/ok`), 'outbound.address-not-allowed');
    expect(hits).toHaveLength(1);
  });

  it('checks every redirect hop: a redirect to a private address or another origin is refused', async () => {
    const base = `http://agent.example.test:${port}`;
    const policy = createOutboundPolicy('production', { allowedOrigins: [base], allowHttp: true, allowPrivateNetworks: ['127.0.0.1/32'], lookup: lookupTo('127.0.0.1') });
    hits = [];
    await refused(policy.fetch(`${base}/to?${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`), 'outbound.origin-not-allowed');
    await refused(policy.fetch(`${base}/to?${encodeURIComponent(`http://127.0.0.1:${port}/ok`)}`), 'outbound.origin-not-allowed');
    expect(hits).toHaveLength(2); // only the redirecting requests themselves
    // Allowlisted on both sides, but the target address is not permitted.
    const both = createOutboundPolicy('production', { allowedOrigins: [base, 'http://10.9.9.9'], allowHttp: true, allowPrivateNetworks: ['127.0.0.1/32'], lookup: lookupTo('127.0.0.1') });
    await refused(both.fetch(`${base}/to?${encodeURIComponent('http://10.9.9.9/')}`), 'outbound.address-not-allowed');
  });

  it('follows at most maxRedirects hops, each checked, and returns redirects unfollowed when asked (AppPort refuses them)', async () => {
    const base = `http://agent.example.test:${port}`;
    const policy = createOutboundPolicy('production', { allowedOrigins: [base], allowHttp: true, allowPrivateNetworks: ['127.0.0.1/32'], lookup: lookupTo('127.0.0.1'), maxRedirects: 3 });
    hits = [];
    expect((await policy.fetch(`${base}/hop/3`)).status).toBe(200);
    expect(hits).toHaveLength(4);
    await refused(policy.fetch(`${base}/hop/4`), 'outbound.too-many-redirects');
    expect((await policy.fetch(`${base}/hop/2`, { redirect: 'manual' })).status).toBe(302);
  });

  it('refuses malformed and unusual URLs', async () => {
    const policy = createOutboundPolicy('production', { allowedOrigins: ['https://agents.example.com'] });
    await refused(policy.fetch('not a url'), 'outbound.malformed-url');
    await refused(policy.fetch('https://user:secret@agents.example.com/'), 'outbound.credentials-in-url');
    await refused(policy.fetch('file:///etc/passwd'), 'outbound.scheme-not-allowed');
    await refused(policy.fetch('gopher://agents.example.com/'), 'outbound.scheme-not-allowed');
    await refused(policy.fetch('ftp://agents.example.com/'), 'outbound.scheme-not-allowed');
    await refused(policy.fetch('https://agents.example.com@evil.example.com/'), 'outbound.credentials-in-url');
    await refused(policy.fetch('https://evil.example.com#@agents.example.com/'), 'outbound.origin-not-allowed');
    await refused(policy.fetch('https://agents.example.com.evil.example.com/'), 'outbound.origin-not-allowed');
  });

  it('development allows loopback and http without configuration, and says so', () => {
    const policy = createOutboundPolicy('development');
    expect(policy.describe()).toMatchObject({ environment: 'development', mode: 'open', allowHttp: true });
    expect(policy.checkUrl(`http://127.0.0.1:${port}/`).origin).toBe(`http://127.0.0.1:${port}`);
  });
});

describe('every resolution path that contacts a destination goes through the policy', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startResolver({ runtime: { environment: 'production', outbound: { allowedOrigins: ['https://agents.example.com'] } } });
  });
  afterAll(() => h.close());

  it('an agent binding at an internal address is refused on create, on update and on rollback, and nothing is contacted', async () => {
    hits = [];
    const internal = `http://127.0.0.1:${port}`;
    for (const origin of [internal, `http://localhost:${port}`, 'https://169.254.169.254', 'https://[::1]:8443', 'https://10.0.0.1', 'https://2130706433', 'https://agents.example.com.attacker.test']) {
      await expect(h.admin.put({ ref: 'ref://prod/agents/x', kind: 'agent', binding: { value: { origin } }, expectedRevision: 0 })).rejects.toMatchObject({ reason: 'resolver.outbound-refused' });
    }
    expect(hits).toEqual([]);
  });

  it('rolling back to a revision that names an internal origin is refused: the policy, not the history, decides', async () => {
    hits = [];
    const db = createFeltDB({ namespace: `outbound-${Date.now()}`, memory: true });
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-outbound-'));
    const shared = { state: { db }, vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32) };
    // Written while agent verification was off: the history now holds an internal origin.
    const lax = await createResolverRuntime({ ...shared, environment: 'production', targets: { verifyAgents: false } });
    const operator = lax.operator('acme');
    await lax.resolver.put(operator, { ref: 'ref://prod/agents/x', kind: 'agent', binding: { value: { origin: `http://127.0.0.1:${port}` } }, expectedRevision: 0 });
    await lax.resolver.put(operator, { ref: 'ref://prod/agents/x', binding: { value: { origin: 'https://agents.example.com' } }, expectedRevision: 1 });
    await lax.close();
    const strict = await createResolverRuntime({ ...shared, environment: 'production', outbound: { allowedOrigins: ['https://agents.example.com'] } });
    await expect(strict.resolver.rollback(strict.operator('acme'), { ref: 'ref://prod/agents/x', toRevision: 1, expectedRevision: 2 })).rejects.toMatchObject({ reason: 'resolver.outbound-refused' });
    await strict.close();
    await db.close();
    rmSync(dir, { recursive: true, force: true });
    expect(hits).toEqual([]);
  });

  it('model and endpoint bindings name destinations but the resolver never contacts them', async () => {
    hits = [];
    await h.admin.put({ ref: 'ref://prod/svc/internal', kind: 'endpoint', binding: { value: { url: `http://127.0.0.1:${port}/ok` } }, expectedRevision: 0 });
    await h.admin.put({ ref: 'ref://prod/chat/local', kind: 'model', binding: { value: { provider: 'ollama', model: 'llama3', endpoint: `http://127.0.0.1:${port}` } }, expectedRevision: 0 }).catch(() => undefined);
    await h.admin.resolve('ref://prod/svc/internal');
    expect(hits).toEqual([]);
  });
});
