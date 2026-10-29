/**
 * Authorization: deny by default, grants per principal and reference pattern.
 *
 * One policy answers two callers:
 * - the @appport/services gateway, through `ServiceAuthorizer` (the AuthBoundry contract), for API key
 *   management (`apikeys.*` needs `admin`);
 * - the resolver's own operations, through `decide`.
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

export class GrantAuthorizer implements ServiceAuthorizer {
  constructor(private readonly store: ResolverStore) {}

  async decide(principal: VerifiedPrincipal, action: Action, ref: string): Promise<Decision> {
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
}
