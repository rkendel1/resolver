// The point of the resolver: running consumers follow changes without a redeploy or restart.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startResolver, waitFor, type Harness } from './harness.js';

let h: Harness;
beforeAll(async () => {
  h = await startResolver();
});
afterAll(async () => h?.close());

describe('changing a model under a running application ("DNS for models")', () => {
  it('switches provider, model and credential, and the running client follows', async () => {
    await h.admin.put({ ref: 'ref://prod/llm/openai-key', kind: 'secret', secret: 'sk-old-key', expectedRevision: 0 });
    await h.admin.put({ ref: 'ref://prod/llm/anthropic-key', kind: 'secret', secret: 'sk-ant-key', expectedRevision: 0 });
    await h.admin.put({
      ref: 'ref://prod/chat/model',
      kind: 'model',
      binding: { value: { provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/openai-key', options: { temperature: 0.2 } } },
      expectedRevision: 0,
    });
    // The application: deployed once, holding only its API key and the reference name.
    const { client: app } = await h.clientWith([
      [['read'], 'ref://prod/*'],
      [['reveal'], 'ref://prod/llm/*'],
    ]);
    const before = await app.model('ref://prod/chat/model');
    expect(before).toMatchObject({ provider: 'openai', model: 'gpt-4o', apiKey: 'sk-old-key', options: { temperature: 0.2 }, revision: 1 });

    const seen: number[] = [];
    app.watch('ref://prod/chat/model', (e) => seen.push(e.revision));

    // Operations retarget the alias. Nothing about the application changes.
    await h.admin.put({
      ref: 'ref://prod/chat/model',
      binding: { value: { provider: 'anthropic', model: 'claude-sonnet-5-5', credential: 'ref://prod/llm/anthropic-key' } },
      expectedRevision: 1,
      reason: 'cost and quality review',
    });
    const after = await waitFor(async () => {
      const m = await app.model('ref://prod/chat/model');
      return m.revision === 2 ? m : undefined;
    });
    expect(after).toMatchObject({ provider: 'anthropic', model: 'claude-sonnet-5-5', apiKey: 'sk-ant-key' });
    await waitFor(() => (seen.includes(2) ? true : undefined));

    // Rotating the credential reaches the running application too.
    await h.admin.put({ ref: 'ref://prod/llm/anthropic-key', secret: 'sk-ant-rotated', expectedRevision: 1 });
    await waitFor(async () => ((await app.model('ref://prod/chat/model')).apiKey === 'sk-ant-rotated' ? true : undefined));
  });

  it('keeps a team on an exact revision when it pins one', async () => {
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']]);
    const pinned = await client.resolve('ref://prod/chat/model', { revision: 1 });
    expect(pinned.selected.value).toMatchObject({ provider: 'openai', model: 'gpt-4o' });
    expect(pinned.currentRevision).toBeGreaterThan(1);
  });
});

describe('traffic steering', () => {
  it('splits by weight, sticks per key, and shifts live when the weights change', async () => {
    await h.admin.put({
      ref: 'ref://prod/search/model',
      kind: 'model',
      binding: {
        strategy: 'weighted',
        targets: [
          { value: { provider: 'ollama', model: 'stable-7b', endpoint: 'http://127.0.0.1:11434/v1' }, weight: 90, label: 'stable' },
          { value: { provider: 'ollama', model: 'candidate-8b', endpoint: 'http://127.0.0.1:11434/v1' }, weight: 10, label: 'canary' },
        ],
      },
      expectedRevision: 0,
    });
    const { client } = await h.clientWith([[['read'], 'ref://prod/search/*']]);
    const users = Array.from({ length: 4000 }, (_, i) => `user-${i}`);
    const labels = async () => Promise.all(users.map(async (u) => (await client.resolve('ref://prod/search/model', { key: u })).selected.label));
    const first = await labels();
    const canary = first.filter((l) => l === 'canary').length / users.length;
    expect(canary).toBeGreaterThan(0.07);
    expect(canary).toBeLessThan(0.13);
    expect(await labels()).toEqual(first); // sticky

    await h.admin.put({
      ref: 'ref://prod/search/model',
      binding: {
        strategy: 'weighted',
        targets: [
          { value: { provider: 'ollama', model: 'stable-7b', endpoint: 'http://127.0.0.1:11434/v1' }, weight: 0, label: 'stable' },
          { value: { provider: 'ollama', model: 'candidate-8b', endpoint: 'http://127.0.0.1:11434/v1' }, weight: 1, label: 'canary' },
        ],
      },
      expectedRevision: 1,
      reason: 'promote canary',
    });
    await waitFor(async () => ((await labels()).every((l) => l === 'canary') ? true : undefined));
  });

  it('fails over through the targets in order', async () => {
    await h.admin.put({
      ref: 'ref://prod/payments/endpoint',
      kind: 'endpoint',
      binding: { strategy: 'failover', targets: [{ value: { url: 'https://primary.example' }, label: 'primary' }, { value: { url: 'https://secondary.example' }, label: 'secondary' }] },
      expectedRevision: 0,
    });
    const { client } = await h.clientWith([[['read'], 'ref://prod/payments/*']]);
    const tried: string[] = [];
    const used = await client.withFailover<{ url: string }, string>('ref://prod/payments/endpoint', async (target, info) => {
      tried.push(info.label!);
      if (info.label === 'primary') throw new Error('primary is down');
      return target.url;
    });
    expect(tried).toEqual(['primary', 'secondary']);
    expect(used).toBe('https://secondary.example/');
  });
});
