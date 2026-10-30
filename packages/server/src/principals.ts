import type { AppPortServices, VerifiedPrincipal } from '@appport/services';

/**
 * Whether an API-key principal's key is still valid: not revoked and not expired. Re-read on every request,
 * so revoking a key stops an open connection, a watch stream or a browser session at once.
 * Principals that did not come from an API key (a host adapter, the operator) are valid by construction.
 */
export async function isLive(services: AppPortServices, principal: VerifiedPrincipal): Promise<boolean> {
  if (principal.verifiedBy !== 'api_key') return true;
  const key = await services.apiKeys.getApiKey(principal.tenantId, principal.principalId).catch(() => null);
  if (!key || key.revokedAt || key.status === 'revoked') return false;
  return !key.expiresAt || Date.parse(key.expiresAt) > Date.now();
}
