// Agent names and addresses: a reference resolves to an AppPort agent, and a pinned contract is verified
// against the agent's real manifest before the binding is accepted.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { permissionAuthorizer } from '@appport/authorization';
import { createApplication, defineCapability } from '@appport/core';
import { capabilityDigest } from '@appport/protocol';
import { fromJSONSchema } from '@appport/schema';
import { createServer } from '@appport/server';
import { serve, type RunningServer } from '@appport/server/node';
import { AppPort } from '@appport/sdk';
import { startResolver, waitFor, type Harness } from './harness.js';

async function agent(id: string, outputField: string): Promise<RunningServer> {
  const app = createApplication({
    application: { id, name: id, version: '1.0.0' },
    authorizer: permissionAuthorizer(),
    mode: 'production',
    capabilities: [
      defineCapability({
        name: 'claims.review',
        version: 1,
        description: 'Reviews a claim.',
        effect: 'observation',
        input: fromJSONSchema({ type: 'object', properties: { claimId: { type: 'string' } }, required: ['claimId'] } as never),
        output: fromJSONSchema({ type: 'object', properties: { [outputField]: { type: 'string' } }, required: [outputField] } as never),
        handler: () => ({ [outputField]: 'approved' }),
      } as never),
    ],
  } as never);
  return serve({ server: createServer({ application: app }), port: 0 } as never);
}

let h: Harness;
let a: RunningServer;
let b: RunningServer;
let broken: RunningServer;
let digest: string;
const origin = (s: RunningServer) => s.url.replace(/\/$/, '');

beforeAll(async () => {
  h = await startResolver();
  a = await agent('com.example.claims-a', 'decision');
  b = await agent('com.example.claims-b', 'decision');
  broken = await agent('com.example.claims-c', 'verdict'); // same name and version, different contract
  const client = await AppPort.discover({ origin: origin(a) });
  digest = capabilityDigest(await client.load(), 'claims.review', 1)!;
  await client.close();
});
afterAll(async () => {
  await Promise.all([a, b, broken].map((s) => s?.close()));
  await h?.close();
});

describe('agent references', () => {
  it('accepts an agent that serves the pinned contract and moves consumers when it is replaced', async () => {
    await h.admin.put({ ref: 'ref://prod/agents/claims-review', kind: 'agent', binding: { value: { origin: origin(a), capabilities: { 'claims.review@1': digest } } }, expectedRevision: 0 });
    const { client } = await h.clientWith([[['read'], 'ref://prod/agents/*']]);
    expect(await client.get('ref://prod/agents/claims-review')).toMatchObject({ origin: origin(a) });
    await h.admin.put({ ref: 'ref://prod/agents/claims-review', binding: { value: { origin: origin(b), capabilities: { 'claims.review@1': digest } } }, expectedRevision: 1, reason: 'move to cluster b' });
    await waitFor(async () => ((await client.get<{ origin: string }>('ref://prod/agents/claims-review')).origin === origin(b) ? true : undefined));
  });

  it('refuses an agent whose contract differs from the pin, before any consumer sees it', async () => {
    const refused = await h.admin.put({ ref: 'ref://prod/agents/claims-review', binding: { value: { origin: origin(broken), capabilities: { 'claims.review@1': digest } } }, expectedRevision: 2 }).catch((e) => e);
    expect(refused).toMatchObject({ code: 'INVALID_INPUT', reason: 'resolver.incompatible-target' });
    expect(await h.admin.get('ref://prod/agents/claims-review')).toMatchObject({ origin: origin(b) });
  });

  it('refuses an unreachable agent and a wrong application id', async () => {
    const unreachable = await h.admin.put({ ref: 'ref://prod/agents/ghost', kind: 'agent', binding: { value: { origin: 'http://127.0.0.1:9' } }, expectedRevision: 0 }).catch((e) => e);
    expect(unreachable).toMatchObject({ code: 'INVALID_INPUT', reason: 'resolver.agent-unreachable' });
    const wrongApp = await h.admin.put({ ref: 'ref://prod/agents/ghost', kind: 'agent', binding: { value: { origin: origin(a), application: 'com.example.other' } }, expectedRevision: 0 }).catch((e) => e);
    expect(wrongApp).toMatchObject({ reason: 'resolver.incompatible-target' });
  });
});
