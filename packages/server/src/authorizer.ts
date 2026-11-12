/**
 * Authorization: deny by default, grants per principal and reference pattern.
 *
 * One policy answers two callers:
 * - the @appport/services gateway, through `ServiceAuthorizer` (the AuthBoundry contract): API key
 *   management (`apikeys.*` needs `admin`), and Resolver's own declared capabilities
 *   (`RESOLVER_GATEWAY_CAPABILITIES`), each mapped to the grant action it needs on the reference the
 *   request names. The host gateway enforces and records; this policy decides.
 * - the resolver's own operations, through `decide`.
 *
 * Both paths end in `decide`, so there is one policy and one store (`resolver_grants`); removing a grant
 * still writes the authority record every instance and client reacts to.
 *
 * The operator (a host principal the CLI and the embedding process mint for themselves) is allowed
 * everything; every other principal holds exactly its grants. A grant never crosses tenants.
 * Decisions are not cached: a removed grant takes effect on the next request.
 */

import { randomUUID } from 'node:crypto';
import type { ServiceAuthorizationDecision, ServiceAuthorizationRequest, ServiceAuthorizer, VerifiedPrincipal } from '@appport/services';
import { matches, type Action } from '@appport/resolver-core';
import type { ResolverStore } from './store.js';

export const OPERATOR_TYPE = 'resolver-operator';

export interface Decision {
  allowed: boolean;
  decisionId: string;
  reason: string;
}

export function isOperator(principal: Pick<VerifiedPrincipal, 'principalType' | 'verifiedBy'>): boolean {
  return principal.principalType === OPERATOR_TYPE && principal.verifiedBy === 'host';
}

/** What `decide` reads of a principal. */
type DecisionPrincipal = Pick<VerifiedPrincipal, 'principalId' | 'principalType' | 'tenantId' | 'verifiedBy'>;

/**
 * Resolver's capabilities as a host gateway enforces them, and the grant each one needs. A management
 * extension declares exactly these. `resource` is the gateway resource type: `reference` names one ref
 * (`id` and `attributes.ref`), `grant` is tenant-wide and needs `admin` on `*`.
 *
 * - `resolver.reveal` is separate from `resolver.resolve`: revealing material needs `reveal` on top of
 *   `read`, as `#reveal` does.
 * - `resolver.list` and `resolver.watch` are allowed to any principal of the tenant. They filter each row
 *   or event by `decide(read)` themselves, so a caller with no grants gets an empty answer, as it always has.
 * - Key management is the host's own `apikeys.*`, answered below; it is not redeclared here.
 */
export const RESOLVER_GATEWAY_CAPABILITIES = Object.freeze({
  'resolver.resolve': { action: 'read', resource: 'reference', effect: 'observation', operation: 'resolve' },
  'resolver.history': { action: 'read', resource: 'reference', effect: 'observation', operation: 'history' },
  'resolver.reveal': { action: 'reveal', resource: 'reference', effect: 'consequential', operation: 'reveal' },
  'resolver.put': { action: 'write', resource: 'reference', effect: 'consequential', operation: 'put' },
  'resolver.rollback': { action: 'write', resource: 'reference', effect: 'consequential', operation: 'rollback' },
  'resolver.revoke': { action: 'write', resource: 'reference', effect: 'consequential', operation: 'revoke' },
  'resolver.list': { action: 'tenant', resource: 'reference', effect: 'observation', operation: 'list' },
  'resolver.watch': { action: 'tenant', resource: 'reference', effect: 'observation', operation: 'watch' },
  'resolver.grant': { action: 'admin', resource: 'grant', effect: 'consequential', operation: 'grant' },
  'resolver.ungrant': { action: 'admin', resource: 'grant', effect: 'consequential', operation: 'ungrant' },
  'resolver.grants': { action: 'admin', resource: 'grant', effect: 'observation', operation: 'grants' },
  'resolver.consumers.register': { action: 'tenant', resource: 'reference', effect: 'consequential', operation: 'register' },
  'resolver.consumers.update': { action: 'tenant', resource: 'reference', effect: 'consequential', operation: 'updateRegistration' },
  'resolver.consumers.deregister': { action: 'tenant', resource: 'reference', effect: 'consequential', operation: 'deregister' },
  'resolver.consumers.report': { action: 'read', resource: 'reference', effect: 'consequential', operation: 'report' },
  'resolver.consumers.list': { action: 'read', resource: 'reference', effect: 'observation', operation: 'consumers' },
  'resolver.adoption': { action: 'read', resource: 'reference', effect: 'observation', operation: 'adoption' },
  'resolver.policies.list': { action: 'admin', resource: 'grant', effect: 'observation', operation: 'policies' },
  'resolver.signingkeys.list': { action: 'admin', resource: 'grant', effect: 'observation', operation: 'signingKeys' },
  'resolver.governance.events': { action: 'admin', resource: 'grant', effect: 'observation', operation: 'governanceEvents' },
} as const satisfies Record<string, { action: Action | 'tenant'; resource: 'reference' | 'grant'; effect: 'observation' | 'consequential'; operation: string }>);

export type ResolverGatewayCapability = keyof typeof RESOLVER_GATEWAY_CAPABILITIES;

/** The URI the gateway builds: `appport://<application>/tenants/<tenant>/<type>/<id or *>`. */
function parseResourceUri(uri: string): { tenantId: string; type: string; id: string } | null {
  const match = /^appport:\/\/[^/]+\/tenants\/([^/]+)\/([^/]+)\/([^/]+)$/.exec(uri);
  if (!match) return null;
  try {
    return { tenantId: decodeURIComponent(match[1]!), type: decodeURIComponent(match[2]!), id: decodeURIComponent(match[3]!) };
  } catch {
    return null;
  }
}

export class GrantAuthorizer implements ServiceAuthorizer {
  constructor(private readonly store: ResolverStore) {}

  async decide(principal: DecisionPrincipal, action: Action, ref: string): Promise<Decision> {
    const decisionId = `dec_${randomUUID()}`;
    if (isOperator(principal)) return { allowed: true, decisionId, reason: 'operator' };
    const grants = await this.store.grantsFor(principal.tenantId, principal.principalId);
    const grant = grants.find((g) => g.actions.includes(action) && matches(ref, g.pattern));
    return grant
      ? { allowed: true, decisionId, reason: `grant ${grant.id}` }
      : { allowed: false, decisionId, reason: `no grant allows ${action} on ${ref}` };
  }

  /** Called by the @appport/services gateway. Only key management is delegated to it. */
  async authorize(request: ServiceAuthorizationRequest): Promise<ServiceAuthorizationDecision> {
    const decisionId = `dec_${randomUUID()}`;
    const base = {
      decision_id: decisionId,
      capability: request.capability,
      tenant_id: request.tenant_id,
      application_id: request.application_id,
      subject: request.subject,
      resource: request.resource,
      evaluated_at: Date.now(),
    };
    if (Object.hasOwn(RESOLVER_GATEWAY_CAPABILITIES, request.capability)) {
      return { ...base, ...(await this.#resolverCapability(request)) };
    }
    if (!request.capability.startsWith('apikeys.')) {
      return { ...base, allowed: false, reason: `${request.capability} is not used by the resolver` };
    }
    if (request.subject.kind === OPERATOR_TYPE && request.context.verified_by === 'host') {
      return { ...base, allowed: true, reason: 'operator' };
    }
    const grants = await this.store.grantsFor(request.tenant_id, request.subject.id);
    const admin = grants.some((g) => g.actions.includes('admin') && g.pattern === '*');
    return { ...base, allowed: admin, reason: admin ? 'admin grant' : 'API key management needs an admin grant on *' };
  }

  /** A declared `resolver.*` capability: the resource must be well formed, then `decide` answers. */
  async #resolverCapability(request: ServiceAuthorizationRequest): Promise<{ allowed: boolean; reason: string }> {
    const spec = RESOLVER_GATEWAY_CAPABILITIES[request.capability as ResolverGatewayCapability];
    const resource = parseResourceUri(request.resource.uri);
    if (!resource || resource.tenantId !== request.tenant_id || resource.type !== spec.resource) {
      return { allowed: false, reason: `${request.capability} needs a ${spec.resource} resource in tenant ${request.tenant_id}` };
    }
    const principal: DecisionPrincipal = {
      principalId: request.subject.id,
      principalType: request.subject.kind,
      tenantId: request.tenant_id,
      verifiedBy: request.context.verified_by as VerifiedPrincipal['verifiedBy'],
    };
    if (spec.action === 'tenant') {
      // Any principal of the tenant; the operation filters what it returns by `read` on each reference.
      return { allowed: true, reason: `${request.capability} is filtered per reference` };
    }
    if (spec.action === 'admin') {
      if (resource.id !== '*') return { allowed: false, reason: `${request.capability} applies to the whole tenant, not ${resource.id}` };
      const decision = await this.decide(principal, 'admin', '*');
      return { allowed: decision.allowed, reason: decision.reason };
    }
    const ref = request.resource.attributes?.['ref'];
    // The reference is named twice (URI id and `ref` attribute); they must agree, so a policy reading
    // either one decides about the same reference.
    if (typeof ref !== 'string' || ref !== resource.id) {
      return { allowed: false, reason: `${request.capability} needs the reference in both the resource id and its ref attribute` };
    }
    const decision = await this.decide(principal, spec.action, ref);
    return { allowed: decision.allowed, reason: decision.reason };
  }
}
