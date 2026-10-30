// The management surface over HTTP: discovery, pages, the JSON API, sessions and their protections.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { UI_DISCOVERY_PATH, validateUiContribution } from '@appport/protocol';
import { createUiContribution, UI_PAGES } from '@appport/resolver';
import { startResolver, type Harness } from './harness.js';

let h: Harness;
beforeAll(async () => {
  h = await startResolver();
  await h.admin.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: 'sk-ui-NEVER-SHOWN', expectedRevision: 0 });
  await h.admin.put({ ref: 'ref://prod/cfg/a', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
});
afterAll(async () => h?.close());

const origin = () => h.url;
async function signIn(apiKey: string, headers: Record<string, string> = { origin: origin() }) {
  return fetch(`${h.url}/_resolver/session`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ apiKey }) });
}
const cookieOf = (response: Response) => response.headers.get('set-cookie')!.split(';')[0]!;

describe('discovery and pages', () => {
  it('serves an AppPort/ui/1 contribution validated by the protocol, showing anonymous callers only the overview', async () => {
    expect(() => validateUiContribution(createUiContribution())).not.toThrow();
    expect(createUiContribution().surfaces.map((s) => s.route)).toEqual(UI_PAGES.map((p) => p.route));
    const response = await fetch(`${h.url}${UI_DISCOVERY_PATH}`);
    expect(response.status).toBe(200);
    const document = (await response.json()) as { protocol: string; surfaces: Array<{ id: string }> };
    expect(document.protocol).toBe('AppPort/ui/1');
    expect(document.surfaces.map((s: { id: string }) => s.id)).toEqual(['overview']);
  });

  it('serves every page with a strict content security policy and no caching', async () => {
    for (const page of [...UI_PAGES.map((p) => p.route), '/resolver/sign-in']) {
      const response = await fetch(`${h.url}${page}`);
      expect(response.status, page).toBe(200);
      const csp = response.headers.get('content-security-policy')!;
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toMatch(/script-src 'sha256-[^']+' 'sha256-[^']+'/);
      expect(csp).not.toContain('unsafe-inline');
      expect(response.headers.get('cache-control')).toBe('no-store');
      const html = await response.text();
      expect(html).not.toContain('sk-ui-NEVER-SHOWN');
      expect(html).toContain('id="resolver-page"');
    }
    expect((await fetch(`${h.url}/nope`)).status).toBe(404);
    expect((await fetch(`${h.url}/`, { redirect: 'manual' })).headers.get('location')).toBe('/resolver');
  });

  it('inlines the vendored Stack design system unmodified (SHA256SUMS)', () => {
    const dir = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '../vendor/stack-ui');
    for (const line of readFileSync(path.join(dir, 'SHA256SUMS'), 'utf8').trim().split('\n')) {
      const [sum, file] = line.split(/\s+/);
      expect(createHash('sha256').update(readFileSync(path.join(dir, file!))).digest('hex'), file).toBe(sum);
    }
  });
});

describe('sessions', () => {
  it('signs in with an API key into an HttpOnly, SameSite=Strict cookie and signs out', async () => {
    const response = await signIn(h.adminKey);
    expect(response.status).toBe(204);
    const header = response.headers.get('set-cookie')!;
    expect(header).toMatch(/HttpOnly/);
    expect(header).toMatch(/SameSite=Strict/);
    expect(header).not.toContain(h.adminKey);
    const cookie = cookieOf(response);
    const session = await (await fetch(`${h.url}/_resolver/session`, { headers: { cookie } })).json();
    expect(session).toMatchObject({ name: 'admin', tenant: 'acme', via: 'session', canSignOut: true });
    expect((await fetch(`${h.url}/_resolver/session`, { method: 'DELETE', headers: { cookie, origin: origin() } })).status).toBe(204);
    expect((await fetch(`${h.url}/_resolver/session`, { headers: { cookie } })).status).toBe(401);
  });

  it('refuses a bad key, and a missing or foreign Origin', async () => {
    expect((await signIn('app_live_bad_key')).status).toBe(401);
    expect((await signIn(h.adminKey, {})).status).toBe(403);
    expect((await signIn(h.adminKey, { origin: 'https://evil.example' })).status).toBe(403);
  });

  it('protects cookie-authenticated changes against cross-site requests', async () => {
    const cookie = cookieOf(await signIn(h.adminKey));
    const change = (headers: Record<string, string>) =>
      fetch(`${h.url}/_resolver/references`, { method: 'POST', headers: { 'content-type': 'application/json', cookie, ...headers }, body: JSON.stringify({ ref: 'ref://prod/cfg/a', binding: { value: 2 }, expectedRevision: 1 }) });
    expect((await change({})).status).toBe(403);
    expect((await change({ origin: 'https://evil.example' })).status).toBe(403);
    expect((await fetch(`${h.url}/_resolver/references`, { method: 'POST', headers: { cookie, origin: origin(), 'content-type': 'text/plain' }, body: '{}' })).status).toBe(415);
    expect((await change({ origin: origin() })).status).toBe(200);
  });

  it('ends a session when its API key is revoked', async () => {
    const key = await h.admin.createKey('ui-temp');
    await h.admin.grant(key.principal, ['read'], '*');
    const cookie = cookieOf(await signIn(key.secret));
    expect((await fetch(`${h.url}/_resolver/references`, { headers: { cookie } })).status).toBe(200);
    await h.admin.revokeKey(key.id);
    expect((await fetch(`${h.url}/_resolver/references`, { headers: { cookie } })).status).toBe(401);
  });
});

describe('the JSON API', () => {
  it('applies the same grants as the AppPort API, and never returns secret material', async () => {
    const { key } = await h.clientWith([[['read'], 'ref://prod/*']]);
    const headers = { authorization: `Bearer ${key}` };
    const detail = await (await fetch(`${h.url}/_resolver/reference?ref=${encodeURIComponent('ref://prod/llm/key')}`, { headers })).text();
    expect(detail).not.toContain('sk-ui-NEVER-SHOWN');
    expect(JSON.parse(detail).current.selected.value).toMatchObject({ version: 1 });
    const write = await fetch(`${h.url}/_resolver/references`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ ref: 'ref://prod/cfg/a', binding: { value: 9 }, expectedRevision: 2 }) });
    expect(write.status).toBe(403);
    expect((await fetch(`${h.url}/_resolver/keys`, { headers })).status).toBe(403);
    expect((await fetch(`${h.url}/_resolver/references`)).status).toBe(401);
  });

  it('reports conflicts and validation errors with their reason', async () => {
    const headers = { authorization: `Bearer ${h.adminKey}`, 'content-type': 'application/json' };
    const stale = await fetch(`${h.url}/_resolver/references`, { method: 'POST', headers, body: JSON.stringify({ ref: 'ref://prod/cfg/a', binding: { value: 3 }, expectedRevision: 1 }) });
    expect(stale.status).toBe(409);
    expect(((await stale.json()) as { error: unknown }).error).toMatchObject({ code: 'CONFLICT', reason: 'resolver.stale-revision' });
    const bad = await fetch(`${h.url}/_resolver/references`, { method: 'POST', headers, body: JSON.stringify({ ref: 'not a ref', binding: { value: 1 }, expectedRevision: 0 }) });
    expect(bad.status).toBe(400);
  });

  it('lets a host identity adapter supply the caller, and can be turned off', async () => {
    const { createResolverRuntime } = await import('@appport/resolver');
    const { randomBytes } = await import('node:crypto');
    const runtime = await createResolverRuntime({
      state: { memory: true },
      vaultDirectory: path.join(h.dir, 'vault-adapter'),
      vaultKey: randomBytes(32),
      management: { authenticate: (request) => (request.headers['x-sso-user'] === 'ops@example.com' ? { principalId: 'ops@example.com', principalType: 'resolver-operator', tenantId: 'acme' } : null) },
    });
    const server = await runtime.serve({ port: 0 });
    const url = server.url.replace(/\/$/, '');
    expect((await (await fetch(`${url}/_resolver/session`, { headers: { 'x-sso-user': 'ops@example.com' } })).json())).toMatchObject({ operator: true, via: 'host' });
    expect((await fetch(`${url}/_resolver/session`, { headers: { 'x-sso-user': 'someone-else' } })).status).toBe(401);
    await runtime.close();

    const off = await createResolverRuntime({ state: { memory: true }, vaultDirectory: path.join(h.dir, 'vault-off'), vaultKey: randomBytes(32), management: false });
    const offServer = await off.serve({ port: 0 });
    const offUrl = offServer.url.replace(/\/$/, '');
    expect((await fetch(`${offUrl}/resolver`)).status).toBe(404);
    expect((await fetch(`${offUrl}${UI_DISCOVERY_PATH}`)).status).toBe(404);
    await off.close();
  });
});

describe('sign-in throttling', () => {
  it('refuses more than 10 sign-in attempts a minute from one client', async () => {
    const fresh = await startResolver();
    const attempt = () => fetch(`${fresh.url}/_resolver/session`, { method: 'POST', headers: { 'content-type': 'application/json', origin: fresh.url }, body: JSON.stringify({ apiKey: 'app_live_guess' }) });
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await attempt()).status);
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(statuses[10]).toBe(429);
    await fresh.close();
  });
});
