// A connection authenticates once; its session must not quietly lapse under a long-lived client (Eve's model and
// credential clients sat idle for minutes between turns and then failed every call with "an API key is required").
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ResolverClient } from '@appport/resolver-client';
import { startResolver, type Harness } from './harness.js';

let h: Harness;
beforeAll(async () => {
  h = await startResolver({ runtime: { sessionTtlMs: 300, heartbeatMs: 100 } });
  await h.admin.put({ ref: 'ref://prod/s/value', kind: 'value', binding: { value: { n: 1 } }, ttlSeconds: 0, expectedRevision: 0 });
});
afterAll(async () => h?.close());
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('long-lived connections', () => {
  it('a quiet client re-authenticates once when its session lapsed, and the call succeeds', async () => {
    const key = await h.admin.createKey('quiet');
    await h.admin.grant(key.principal, ['read'], 'ref://prod/s/*');
    const app = new ResolverClient({ url: h.url, apiKey: key.secret, live: false });
    try {
      expect((await app.resolve('ref://prod/s/value')).revision).toBe(1);
      await pause(700); // well past the 300 ms session
      expect((await app.resolve('ref://prod/s/value')).revision).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('an open watch stream keeps its connection’s session', async () => {
    const key = await h.admin.createKey('watching');
    await h.admin.grant(key.principal, ['read'], 'ref://prod/s/*');
    const app = await ResolverClient.connect({ url: h.url, apiKey: key.secret, live: true });
    try {
      expect((await app.resolve('ref://prod/s/value')).revision).toBe(1);
      await pause(700);
      expect((await app.resolve('ref://prod/s/value')).revision).toBe(1);
    } finally {
      await app.close();
    }
  });

  it('a revoked key is still refused after reconnecting', async () => {
    const key = await h.admin.createKey('revoked');
    await h.admin.grant(key.principal, ['read'], 'ref://prod/s/*');
    const app = new ResolverClient({ url: h.url, apiKey: key.secret, live: false, maxStaleSeconds: 0 });
    try {
      expect((await app.resolve('ref://prod/s/value')).revision).toBe(1);
      await h.admin.revokeKey(key.id);
      await pause(700);
      await expect(app.resolve('ref://prod/s/value')).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await app.close();
    }
  });
});
