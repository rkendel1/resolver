// Resolution observability: consumer registration, observed resolutions (default on), asserted usage, and adoption
// as a lifecycle. The facts are kept apart, and notification delivery is never counted as adoption.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFeltDB } from '@feltdb/core';
import { COLLECTIONS, createResolverRuntime, type ResolverRuntime } from '@appport/resolver';
import { ResolverClient } from '@appport/resolver-client';
import { generateSigningKey, signChangeAuthorization } from '@appport/resolver-client/authorization';
import { startResolver, TENANT, waitFor, type Harness } from './harness.js';

type Facts = { principal: string; registration?: { id: string; application: string; state: string }; declared: boolean; resolved: { latestRevision: number; count: number } | null; refused: Array<{ outcome: string; count: number }>; used: { latestRevision: number; outcome: string; label?: string } | null; verified: null };
const consumersOf = async (client: ResolverClient, ref: string) => (await client.consumers(ref)) as { consumers: Facts[]; notes: string[] };

describe('consumers and observed resolutions', () => {
  let h: Harness;
  beforeEach(async () => {
    h = await startResolver({ runtime: { observationWindowMs: 0, consumerGraceMs: 1500 } });
    await h.admin.set('ref://prod/search', { kind: 'endpoint', binding: { value: { url: 'https://search-a.example.com' } } });
    await h.admin.set('ref://prod/flags', { kind: 'value', binding: { strategy: 'weighted', targets: [{ value: 'a', weight: 50, label: 'stable' }, { value: 'b', weight: 50, label: 'canary' }] } });
  });
  afterEach(async () => h.close());

  it('records what a consumer resolves by default, and keeps declared, resolved and used apart', async () => {
    const { client: plain, principal: plainPrincipal } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false });
    await plain.resolve('ref://prod/search');
    // Unregistered: observed under its principal, declared nothing.
    let facts = (await consumersOf(h.admin, 'ref://prod/search')).consumers;
    expect(facts).toContainEqual(expect.objectContaining({ principal: plainPrincipal, declared: false, resolved: expect.objectContaining({ latestRevision: 1 }), used: null, verified: null }));

    const { client: app, principal } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false, consumer: { application: 'storefront', environment: 'prod', instance: 'web-7f82', dependencies: ['ref://prod/search', 'ref://prod/flags'] } });
    expect(app.registration).toMatch(/^con_/);
    // Declared, not yet resolved: a declaration alone proves nothing.
    facts = (await consumersOf(h.admin, 'ref://prod/flags')).consumers;
    const declaredOnly = facts.find((f) => f.registration?.id === app.registration)!;
    expect(declaredOnly).toMatchObject({ principal, declared: true, resolved: null, used: null });
    expect(declaredOnly.registration).toMatchObject({ application: 'storefront', state: 'live' });

    await app.resolve('ref://prod/flags', { key: 'user-123' });
    await app.report('ref://prod/flags', 1, 'succeeded', 'canary');
    const f = (await consumersOf(h.admin, 'ref://prod/flags')).consumers.find((c) => c.registration?.id === app.registration)!;
    expect(f.resolved).toMatchObject({ latestRevision: 1 });
    expect(f.used).toEqual(expect.objectContaining({ latestRevision: 1, outcome: 'succeeded', label: 'canary' }));
    // The steering key never reaches the records.
    const rows = JSON.stringify([await h.runtime.db.collection(COLLECTIONS.resolutions).find({}), await h.runtime.db.collection(COLLECTIONS.usage).find({})]);
    expect(rows).not.toContain('user-123');
  });

  it('refused resolutions are recorded, and shown to admins only', async () => {
    const { client: outsider, principal: outsiderPrincipal } = await h.clientWith([[['read'], 'ref://staging/*']], { live: false });
    await expect(outsider.resolve('ref://prod/search')).rejects.toThrow();
    const asAdmin = (await consumersOf(h.admin, 'ref://prod/search')).consumers.find((c) => c.principal === outsiderPrincipal)!;
    expect(asAdmin.refused).toEqual([expect.objectContaining({ outcome: 'forbidden', count: 1 })]);
    const { client: reader } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false });
    const asReader = (await consumersOf(reader, 'ref://prod/search')).consumers;
    expect(asReader.find((c) => c.principal === outsiderPrincipal)).toBeUndefined();
  });

  it('a consumer cannot declare what it may not read, nor borrow another principal\'s registration', async () => {
    await expect(h.clientWith([[['read'], 'ref://staging/*']], { live: false, consumer: { application: 'x', environment: 'prod', dependencies: ['ref://prod/search'] } })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const { client: owner } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false, consumer: { application: 'owner', environment: 'prod' } });
    const { principal: thief } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false });
    // Resolve with the owner's registration id but the thief's key: recorded under the thief, not the registration.
    const asThief = { principalId: thief, principalType: 'api_key', tenantId: TENANT, verifiedBy: 'appport-services' } as never;
    await h.runtime.resolver.resolve(asThief, { ref: 'ref://prod/search', consumer: owner.registration! });
    const facts = (await consumersOf(h.admin, 'ref://prod/search')).consumers;
    expect(facts.find((c) => c.principal === thief)?.registration).toBeUndefined();
    expect(facts.find((c) => c.registration?.id === owner.registration)?.resolved ?? null).toBeNull();
  });

  it('registration liveness follows the watch stream: live, stale after the grace period, deregistered on close', async () => {
    const { client: watching } = await h.clientWith([[['read'], 'ref://prod/*']], { consumer: { application: 'live-app', environment: 'prod', dependencies: ['ref://prod/search'] } });
    const { client: silent } = await h.clientWith([[['read'], 'ref://prod/*']], { live: false, consumer: { application: 'batch-job', environment: 'prod', dependencies: ['ref://prod/search'] } });
    const state = async (id: string) => (await consumersOf(h.admin, 'ref://prod/search')).consumers.find((c) => c.registration?.id === id)?.registration?.state;
    expect(await state(watching.registration!)).toBe('live');
    await new Promise((r) => setTimeout(r, 1800));
    expect(await state(silent.registration!)).toBe('stale');
    const id = watching.registration!;
    await watching.close();
    expect(await state(id)).toBe('deregistered');
  });
});

describe('adoption', () => {
  it('distinguishes authorized, committed, available, fetched and adopted, and never counts a notification as adoption', async () => {
    const h = await startResolver({ runtime: { observationWindowMs: 0 } });
    try {
      const op = h.runtime.operator(TENANT);
      await h.admin.set('ref://prod/search', { kind: 'endpoint', binding: { value: { url: 'https://search-a.example.com' } } });
      const { publicKey, privateKeyPem } = generateSigningKey();
      await h.runtime.resolver.addSigningKey(op, { kid: 'rc-1', issuer: 'resolver-control', publicKey, reason: 'approvals' });
      await h.runtime.resolver.setPolicy(op, { pattern: 'ref://prod/*', operations: ['put'], issuers: ['resolver-control'], reason: 'governed' });

      // Two live consumers of the search endpoint, both on revision 1.
      const a = await h.clientWith([[['read'], 'ref://prod/*']], { consumer: { application: 'storefront', environment: 'prod', instance: 'a', dependencies: ['ref://prod/search'] } });
      const b = await h.clientWith([[['read'], 'ref://prod/*']], { consumer: { application: 'recommendations', environment: 'prod', instance: 'b', dependencies: ['ref://prod/search'] } });
      await a.client.resolve('ref://prod/search');
      await b.client.resolve('ref://prod/search');
      const notified: number[] = [];
      b.client.watch('ref://prod/search', (e) => notified.push(e.revision));
      await new Promise((r) => setTimeout(r, 200));

      const binding = { value: { url: 'https://search-b.example.com' } };
      const token = signChangeAuthorization({ privateKey: privateKeyPem, kid: 'rc-1', issuer: 'resolver-control', tenant: TENANT, ref: 'ref://prod/search', op: 'put', expectedRevision: 1, request: { kind: 'endpoint', binding }, decision: 'CHG-9', approvers: ['linus'] });
      const { client: writer } = await h.clientWith([[['read', 'write'], '*']], { live: false });
      await writer.put({ ref: 'ref://prod/search', binding, expectedRevision: 1, authorization: token });

      // B is told about revision 2 (delivery) but does not resolve. A resolves and reports use.
      await waitFor(() => (notified.includes(2) ? true : undefined));
      await a.client.resolve('ref://prod/search');
      await a.client.report('ref://prod/search', 2, 'succeeded');

      type Adoption = { revision: number; authorized: { mode: string; decision?: string; consumedAt?: string }; committed: { actor: string }; available: { current: boolean; until: string | null }; fetched: { basis: string; count: number; consumers: Facts[] }; notYetFetched: { count: number; consumers: Facts[] }; adopted: { basis: string; count: number; consumers: Facts[] }; functionallyVerified: null };
      const adoption = (await writer.adoption('ref://prod/search')) as Adoption;
      expect(adoption.revision).toBe(2);
      expect(adoption.authorized).toMatchObject({ mode: 'authorized', decision: 'CHG-9', consumedAt: expect.any(String) });
      expect(adoption.available).toEqual({ from: expect.any(String), until: null, current: true });
      expect(adoption.fetched).toMatchObject({ basis: 'observed', count: 1 });
      expect(adoption.fetched.consumers[0]!.registration!.application).toBe('storefront');
      // B received the notification and is still not counted as having fetched revision 2.
      expect(adoption.notYetFetched.consumers.map((c) => c.registration!.application)).toEqual(['recommendations']);
      expect(adoption.adopted).toMatchObject({ basis: 'asserted', count: 1 });
      expect(adoption.functionallyVerified).toBeNull();

      // Revision 1: no longer available, ungoverned, fetched by both.
      const old = (await writer.adoption('ref://prod/search', 1)) as Adoption;
      expect(old.authorized.mode).toBe('ungoverned');
      expect(old.available.current).toBe(false);
      expect(old.available.until).toEqual(expect.any(String));
      expect(old.fetched.count).toBe(2);
    } finally {
      await h.close();
    }
  });
});

describe('recording cost and failure', () => {
  async function runtimeWith(db: unknown, extra: Record<string, unknown> = {}): Promise<{ rt: ResolverRuntime; dir: string }> {
    const dir = mkdtempSync(path.join(tmpdir(), 'resolver-obs-'));
    const rt = await createResolverRuntime({ state: { db: db as never }, environment: 'development', vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32), verifierKey: randomBytes(32).toString('hex'), ...extra });
    return { rt, dir };
  }

  it('many resolutions cost a bounded number of writes; the count is kept', async () => {
    const real = createFeltDB({ namespace: `resolver-obs-${randomBytes(4).toString('hex')}`, memory: true });
    let observationWrites = 0;
    const db = new Proxy(real, {
      get(target, prop, receiver) {
        if (prop === 'transaction') {
          return (request: { operations: Array<{ collection: string }> }) => {
            if (request.operations.some((o) => o.collection === COLLECTIONS.resolutions)) observationWrites += 1;
            return target.transaction(request as never);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const { rt, dir } = await runtimeWith(db, { observationWindowMs: 60_000 });
    try {
      const op = rt.operator(TENANT);
      await rt.resolver.put(op, { ref: 'ref://prod/x', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      for (let i = 0; i < 200; i++) await rt.resolver.resolve(op, { ref: 'ref://prod/x' });
      await rt.observations!.flush();
      expect(observationWrites).toBeLessThanOrEqual(2); // the first sighting, then one flush
      const rows = await real.collection(COLLECTIONS.resolutions).find({});
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ ref: 'ref://prod/x', revision: 1, outcome: 'ok', count: 200 });
    } finally {
      await rt.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a state store that refuses observation writes never fails a resolution; the loss is counted', async () => {
    const real = createFeltDB({ namespace: `resolver-obs-${randomBytes(4).toString('hex')}`, memory: true });
    const db = new Proxy(real, {
      get(target, prop, receiver) {
        if (prop === 'transaction') {
          return (request: { operations: Array<{ collection: string }> }) => {
            if (request.operations.some((o) => o.collection === COLLECTIONS.resolutions)) return Promise.reject(new Error('disk full'));
            return target.transaction(request as never);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const { rt, dir } = await runtimeWith(db, { observationWindowMs: 0 });
    try {
      const op = rt.operator(TENANT);
      await rt.resolver.put(op, { ref: 'ref://prod/x', kind: 'value', binding: { value: 1 }, expectedRevision: 0 });
      for (let i = 0; i < 5; i++) expect((await rt.resolver.resolve(op, { ref: 'ref://prod/x' })).revision).toBe(1);
      await rt.observations!.flush();
      expect(rt.observations!.status().failures).toBeGreaterThan(0);
    } finally {
      await rt.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('records no secret material: a revealed credential leaves only its reference and revision', async () => {
    const h = await startResolver({ runtime: { observationWindowMs: 0 } });
    try {
      const material = `sk-${randomBytes(16).toString('hex')}`;
      await h.admin.put({ ref: 'ref://prod/llm/key', kind: 'secret', secret: material, expectedRevision: 0 });
      const { client } = await h.clientWith([[['read', 'reveal'], 'ref://prod/*']], { live: false, consumer: { application: 'chat', environment: 'prod', dependencies: ['ref://prod/llm/key'] } });
      expect(await client.secret('ref://prod/llm/key')).toBe(material);
      await client.report('ref://prod/llm/key', 1, 'succeeded');
      await h.runtime.observations!.flush();
      const dump = JSON.stringify(await Promise.all([COLLECTIONS.resolutions, COLLECTIONS.usage, COLLECTIONS.consumers].map((c) => h.runtime.db.collection(c).find({}))));
      expect(dump).toContain('ref://prod/llm/key');
      expect(dump).not.toContain(material);
    } finally {
      await h.close();
    }
  });
});
