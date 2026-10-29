import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startResolver, waitFor, type Harness } from './harness.js';

let h: Harness;
beforeAll(async () => {
  h = await startResolver();
});
afterAll(async () => h?.close());

describe('smoke', () => {
  it('creates, resolves and live-updates a value without the consumer restarting', async () => {
    await h.admin.put({ ref: 'ref://prod/flags/checkout', kind: 'value', binding: { value: { newFlow: false } }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/*']]);
    expect(await client.get('ref://prod/flags/checkout')).toEqual({ newFlow: false });
    await h.admin.put({ ref: 'ref://prod/flags/checkout', binding: { value: { newFlow: true } }, expectedRevision: 1 });
    await waitFor(async () => ((await client.get<{ newFlow: boolean }>('ref://prod/flags/checkout')).newFlow ? true : undefined));
  });
});
