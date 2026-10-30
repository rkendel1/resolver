import type { AppPortServices, VerifiedPrincipal } from '@appport/services';

/**
 * Whether an API-key principal's key is still valid: not revoked and not expired. Re-read on every request,
 * so revoking a key stops an open connection, a watch stream or a browser session at once.
 * Principals that did not come from an API key (a host adapter, the operator) are valid by construction.
 */
export async function isLive(services: AppPortServices, principal: VerifiedPrincipal): Promise<boolean> {
  if (principal.verifiedBy !== 'api_key') return true;
  return keyIsLive(services, principal.tenantId, principal.principalId);
}

/** Whether the API key `keyId` of `tenantId` is still valid (management sessions record the key they came from). */
export async function keyIsLive(services: AppPortServices, tenantId: string, keyId: string): Promise<boolean> {
  const key = await services.apiKeys.getApiKey(tenantId, keyId).catch(() => null);
  if (!key || key.revokedAt || key.status === 'revoked') return false;
  return !key.expiresAt || Date.parse(key.expiresAt) > Date.now();
}
