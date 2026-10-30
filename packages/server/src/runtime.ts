/**
 * Assembles a resolver from existing parts, all on one FeltDB instance:
 * FeltDB (state), AppPort Services (API keys, principals, custody contract), the encrypted vault
 * (secret material, outside FeltDB) and the grant authorizer.
 */

import path from 'node:path';
import { createFeltDB, type StateFirstDB } from '@feltdb/core';
import { createServices, type AppPortServices, type SecretCustody, type VerifiedPrincipal } from '@appport/services';
import { APPLICATION_ID, createResolverApplication, serveResolver, type ResolverApplication } from './app.js';
import { GrantAuthorizer, OPERATOR_TYPE } from './authorizer.js';
import { Resolver } from './resolver.js';
import { ResolverStore } from './store.js';
import type { TargetCheckOptions } from './targets.js';
import { createVault } from './vault.js';
import { createManagementHandler, type ManagementOptions } from './ui/router.js';

export interface ResolverRuntimeOptions {
  /**
   * Where state lives. `{ local: dir }` (FeltDB file runtime, one process), `{ memory: true }` (tests),
   * `{ remote: { url, token } }` (a FeltDB server), or an already-open FeltDB instance.
   */
  state: { local: string } | { memory: true } | { remote: { url: string; token?: string; applicationId?: string; environment?: string } } | { db: StateFirstDB };
  /** Secret custody. Default: the encrypted vault in `vaultDirectory` under `vaultKey`. */
  custody?: SecretCustody<string>;
  vaultDirectory?: string;
  /** 32 bytes. Required unless `custody` is given. */
  vaultKey?: Buffer;
  /** Server-held API key verifier key (at least 32 bytes), mixed into new key verifiers. Never persisted. */
  verifierKey?: string;
  targets?: Omit<TargetCheckOptions, 'lookup'>;
  /**
   * The management UI and its JSON API, on the same server. Default on; `false` serves only the AppPort API.
   * `authenticate` is the host's identity adapter (an SSO proxy, an embedding application).
   */
  management?: false | Omit<ManagementOptions, 'resolver' | 'services'>;
  now?: () => Date;
}

export interface ResolverRuntime {
  resolver: Resolver;
  services: AppPortServices;
  store: ResolverStore;
  db: StateFirstDB;
  app: ResolverApplication;
  /** A principal with every permission in `tenantId`, for bootstrap and embedding. Never leaves this process. */
  operator(tenantId: string): VerifiedPrincipal;
  serve(options?: { port?: number; host?: string }): ReturnType<typeof serveResolver>;
  close(): Promise<void>;
}

function openState(state: ResolverRuntimeOptions['state']): { db: StateFirstDB; owned: boolean } {
  if ('db' in state) return { db: state.db, owned: false };
  if ('memory' in state) return { db: createFeltDB({ namespace: 'resolver', memory: true }), owned: true };
  if ('remote' in state) {
    return { db: createFeltDB({ namespace: 'resolver', mode: 'remote', server: state.remote } as never), owned: true };
  }
  return { db: createFeltDB({ namespace: 'resolver', mode: 'local', path: path.join(state.local, 'state') } as never), owned: true };
}

export async function createResolverRuntime(options: ResolverRuntimeOptions): Promise<ResolverRuntime> {
  const { db, owned } = openState(options.state);
  const store = new ResolverStore(db);
  const authorizer = new GrantAuthorizer(store);
  let custody = options.custody;
  if (!custody) {
    if (!options.vaultKey) throw new Error('a vault key (32 bytes) is required unless a custody is given');
    const directory = options.vaultDirectory ?? ('local' in options.state ? path.join(options.state.local, 'vault') : undefined);
    if (!directory) throw new Error('vaultDirectory is required with this state option');
    custody = createVault({ directory, key: options.vaultKey, ...(options.now ? { now: options.now } : {}) });
  }
  const services = await createServices({
    db,
    application: APPLICATION_ID,
    authorizer,
    credentials: custody,
    ...(options.verifierKey ? { verifierKey: options.verifierKey } : {}),
  } as never);
  const resolver = new Resolver({
    store,
    authorizer,
    custody,
    services,
    ...(options.targets ? { targets: options.targets } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  const app = createResolverApplication(resolver, services, { ui: options.management !== false });
  const management = options.management === false ? undefined : createManagementHandler({ resolver, services, ...options.management });
  const running: Array<{ close(): Promise<void> }> = [];
  return {
    resolver,
    services,
    store,
    db,
    app,
    operator(tenantId: string) {
      const principal = services.identify({ principalId: 'operator', principalType: OPERATOR_TYPE, tenantId });
      if (!principal) throw new Error('could not mint the operator principal');
      return principal;
    },
    async serve(serveOptions) {
      const server = await serveResolver(app, { ...serveOptions, ...(management ? { fallback: management.handle } : {}) });
      running.push(server);
      return server;
    },
    async close() {
      for (const server of running.splice(0)) await server.close();
      if (owned) await Promise.resolve(db.close());
    },
  };
}
