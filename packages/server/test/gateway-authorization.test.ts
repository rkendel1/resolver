// P3: Resolver's grants answer the host gateway for `resolver.*`. A real @appport/services gateway (the
// capabilities declared the way a management extension declares them) asks GrantAuthorizer, which ends
// in the same `decide` the resolver's own operations use. One policy, one store, no caching.
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServices, defineServicesExtension, type AppPortServices, type ServiceAuthorizationRequest, type VerifiedPrincipal } from '@appport/services';
import { APPLICATION_ID, GrantAuthorizer, RESOLVER_GATEWAY_CAPABILITIES, ResolverStore, createResolverRuntime, type ResolverRuntime } from '@appport/resolver';

const TENANT = 'acme';
const REF = 'ref://prod/llm/key';
const OTHER = 'ref://prod/db/url';

let runtime: ResolverRuntime;
let host: AppPortServices;
let authorizer: GrantAuthorizer;
let dir: string;

/** Resolver's capabilities, declared exactly as a management extension would declare them. */
const extension = defineServicesExtension({
  id: 'resolver',
  capabilities: Object.entries(RESOLVER_GATEWAY_CAPABILITIES).map(([name, spec]) => ({ name, operation: spec.operation, effect: spec.effect, resource: spec.resource })),
});

beforeAll(async () => {
  dir = mkdtempSync(path.join(tmpdir(), 'resolver-gateway-'));
  runtime = await createResolverRuntime({ state: { memory: true }, environment: 'development', vaultDirectory: path.join(dir, 'vault'), vaultKey: randomBytes(32) });
  authorizer = new GrantAuthorizer(new ResolverStore(runtime.db));
  host = createServices({ db: runtime.db, application: APPLICATION_ID, authorizer, extensions: [extension] } as never);
  const operator = runtime.operator(TENANT);
  await runtime.resolver.grant(operator, { subject: 'exact', actions: ['read'], pattern: REF });
  await runtime.resolver.grant(operator, { subject: 'prefix', actions: ['read', 'write'], pattern: 'ref://prod/llm/*' });
  await runtime.resolver.grant(operator, { subject: 'star', actions: ['read', 'write', 'reveal'], pattern: '*' });
  await runtime.resolver.grant(operator, { subject: 'admin', actions: ['admin'], pattern: '*' });
  // A grant in another tenant does not reach this one.
  await runtime.resolver.grant(runtime.operator('globex'), { subject: 'elsewhere', actions: ['read', 'write', 'reveal'], pattern: '*' });
});

afterAll(async () => {
  await host?.apiKeys.close();
  await runtime?.close();
  rmSync(dir, { recursive: true, force: true });
});

const as = (principalId: string, principalType = 'service_account', tenantId = TENANT): VerifiedPrincipal =>
  host.identify({ principalId, principalType, tenantId })!;
/** `attribute: null` leaves the ref attribute out. */
const reference = (ref: string, tenantId = TENANT, attribute: string | null = ref) =>
  ({ type: 'reference', tenantId, id: ref, ...(attribute === null ? {} : { attributes: { ref: attribute } }) });
const allowed = (capability: string, principal: VerifiedPrincipal, resource: object) =>
  host.gateway.authorize(capability, principal, resource as never).then(() => true, (error: { code?: string }) => {
    if (error?.code !== 'DENIED') throw error;
    return false;
  });

describe('the gateway and decide agree', () => {
  const principals = () => [as('nobody'), as('exact'), as('prefix'), as('star'), as('elsewhere'), runtime.operator(TENANT)];
  const byAction = Object.entries(RESOLVER_GATEWAY_CAPABILITIES).filter(([, spec]) => spec.action === 'read' || spec.action === 'write' || spec.action === 'reveal');

  it('for every reference capability, principal and reference', async () => {
    const rows: string[] = [];
    for (const [capability, spec] of byAction) {
      for (const principal of principals()) {
        for (const ref of [REF, OTHER]) {
          const gateway = await allowed(capability, principal, reference(ref));
          const direct = (await authorizer.decide(principal, spec.action as 'read', ref)).allowed;
          rows.push(`${capability} ${principal.principalId} ${ref}: gateway=${gateway} decide=${direct}`);
          expect(gateway, `${capability} ${principal.principalId} ${ref}`).toBe(direct);
        }
      }
    }
    // The matrix is not trivially all-deny or all-allow.
    expect(rows.some((r) => r.includes('gateway=true'))).toBe(true);
    expect(rows.some((r) => r.includes('gateway=false'))).toBe(true);
  });

  it('spot checks: actions are distinct, patterns and tenants hold, the operator is allowed', async () => {
    expect(await allowed('resolver.resolve', as('exact'), reference(REF))).toBe(true);
    expect(await allowed('resolver.put', as('exact'), reference(REF))).toBe(false); // read only
    expect(await allowed('resolver.put', as('prefix'), reference(REF))).toBe(true);
    expect(await allowed('resolver.put', as('prefix'), reference(OTHER))).toBe(false); // outside the prefix
    expect(await allowed('resolver.reveal', as('prefix'), reference(REF))).toBe(false); // read does not reveal
    expect(await allowed('resolver.reveal', as('star'), reference(OTHER))).toBe(true);
    expect(await allowed('resolver.resolve', as('elsewhere'), reference(REF))).toBe(false); // its grant is in globex
    expect(await allowed('resolver.resolve', as('star', 'service_account', 'globex'), reference(REF, TENANT))).toBe(false); // cross-tenant resource
    expect(await allowed('resolver.revoke', runtime.operator(TENANT), reference(OTHER))).toBe(true);
  });
});

describe('the resource must name one reference, consistently', () => {
  it('a ref attribute that differs from the resource id is denied, even with a grant on *', async () => {
    expect(await allowed('resolver.resolve', as('star'), reference(REF, TENANT, OTHER))).toBe(false);
  });

  it('a missing ref attribute is denied', async () => {
    expect(await allowed('resolver.resolve', as('star'), reference(REF, TENANT, null))).toBe(false);
  });

  it('admin capabilities are tenant-wide and need admin on *', async () => {
    const grantResource = { type: 'grant', tenantId: TENANT };
    expect(await allowed('resolver.grants', as('admin'), grantResource)).toBe(true);
    expect(await allowed('resolver.grant', as('star'), grantResource)).toBe(false); // read/write/reveal, no admin
    expect(await allowed('resolver.ungrant', runtime.operator(TENANT), grantResource)).toBe(true);
  });
});

describe('list and watch keep their semantics', () => {
  it('are allowed to any principal of the tenant, and list still returns [] to a caller with no grants', async () => {
    expect(await allowed('resolver.list', as('nobody'), { type: 'reference', tenantId: TENANT })).toBe(true);
    expect(await allowed('resolver.watch', as('nobody'), { type: 'reference', tenantId: TENANT })).toBe(true);
    const operator = runtime.operator(TENANT);
    await runtime.resolver.put(operator, { ref: 'ref://prod/cfg/visible', kind: 'value', binding: { value: 'v' }, expectedRevision: 0 });
    expect((await runtime.resolver.list(as('nobody'), {})).refs).toEqual([]);
    expect((await runtime.resolver.list(as('star'), {})).refs.map((r) => r.ref)).toContain('ref://prod/cfg/visible');
  });
});

describe('deny by default, no caching, evidence', () => {
  it('an unmapped resolver.* capability is denied by the policy', async () => {
    const request: ServiceAuthorizationRequest = {
      request_id: 'r', subject: { kind: 'service_account', id: 'star' }, tenant_id: TENANT, application_id: APPLICATION_ID,
      capability: 'resolver.export', capability_version: 1,
      resource: { uri: `appport://${APPLICATION_ID}/tenants/${TENANT}/reference/${encodeURIComponent(REF)}`, attributes: { ref: REF } },
      context: { timestamp: Date.now(), verified_by: 'host' },
    };
    expect((await authorizer.authorize(request)).allowed).toBe(false);
  });

  it('removing a grant denies the very next gateway call', async () => {
    const operator = runtime.operator(TENANT);
    const grant = await runtime.resolver.grant(operator, { subject: 'temporary', actions: ['write'], pattern: REF });
    expect(await allowed('resolver.put', as('temporary'), reference(REF))).toBe(true);
    await runtime.resolver.ungrant(operator, { id: grant.id });
    expect(await allowed('resolver.put', as('temporary'), reference(REF))).toBe(false);
  });

  it('an effect run through the gateway is recorded as evidence, allowed or refused', async () => {
    const ran = await host.gateway.execute('resolver.put', as('prefix'), reference(REF) as never, { service: 'resolver' }, async () => 'ok');
    expect(ran).toBe('ok');
    await expect(host.gateway.execute('resolver.put', as('exact'), reference(REF) as never, { service: 'resolver' }, async () => 'no')).rejects.toMatchObject({ code: 'DENIED' });
    const evidence = await runtime.db.collection<{ capability: string; decision: string; principalId: string }>('service_effect_evidence').find({ capability: 'resolver.put' });
    expect(evidence.map((e) => `${e.principalId}:${e.decision}`)).toEqual(expect.arrayContaining(['prefix:allow', 'exact:deny']));
  });
});
