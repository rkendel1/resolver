export { createResolverRuntime, type ResolverRuntime, type ResolverRuntimeOptions } from './runtime.js';
export { Resolver, ResolverError, type ResolverOptions } from './resolver.js';
export { createResolverApplication, serveResolver, APPLICATION_ID } from './app.js';
export { GrantAuthorizer, OPERATOR_TYPE, isOperator } from './authorizer.js';
export { ResolverStore, COLLECTIONS, referenceId } from './store.js';
export { createVault, parseVaultKey, isVersionedCustody, VaultError, type VersionedCustody } from './vault.js';
export { checkTargets, type TargetCheckOptions } from './targets.js';
export { createManagementHandler, type ManagementOptions } from './ui/router.js';
export { createUiContribution, PAGES as UI_PAGES } from './ui/contribution.js';
