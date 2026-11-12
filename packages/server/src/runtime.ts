/**
 * Assembles a resolver from existing parts, all on one FeltDB instance:
 * FeltDB (state), AppPort Services (API keys, principals, custody contract), the encrypted vault
 * (secret material, outside FeltDB), the grant authorizer, the outbound policy, and the sync loop that
 * keeps watchers in step with other instances sharing the state.
 */

import { randomUUID } from 'node:crypto';
import { access, constants } from 'node:fs/promises';
import { hostname } from 'node:os';
import path from 'node:path';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createFeltDB, type StateFirstDB } from '@feltdb/core';
import { createServices, type AppPortServices, type SecretCustody, type VerifiedPrincipal } from '@appport/services';
import { APPLICATION_ID, createResolverApplication, serveResolver, type ResolverApplication } from './app.js';
import { GrantAuthorizer, OPERATOR_TYPE } from './authorizer.js';
import { verifyIntegrity, type IntegrityReport } from './integrity.js';
import { createLogger, silentLogger, type Logger } from './log.js';
import { createOutboundPolicy, type Environment, type OutboundOptions, type OutboundPolicy } from './outbound.js';
import { ObservationRecorder } from './observe.js';
import { Resolver } from './resolver.js';
import { ResolverStore } from './store.js';
import { RevisionSync, type SyncOptions } from './sync.js';
import type { TargetCheckOptions } from './targets.js';
import { createVault, requireVersionedCustody, type Vault, type VersionedCustody } from './vault.js';
import { createManagementHandler, type ManagementOptions } from './ui/router.js';

export interface ResolverRuntimeOptions {
  /**
   * Where state lives. `{ local: dir }` (FeltDB file runtime; `shared: true` lets several processes on one
   * host open it), `{ memory: true }` (tests), `{ remote: { url, token } }` (a FeltDB server: the state for
   * several instances behind a load balancer), or an already-open FeltDB instance.
   */
  state: { local: string; shared?: boolean } | { memory: true } | { remote: { url: string; token?: string; applicationId?: string; environment?: string } } | { db: StateFirstDB };
  /**
   * `production` (default) fails closed: outbound requests need an explicit allowlist. `development` allows
   * any origin, `http:` and private addresses unless `outbound` says otherwise.
   */
  environment?: Environment;
  /** Destinations the resolver itself may contact (agent discovery). See `outbound.ts`. */
  outbound?: OutboundOptions;
  /**
   * Several instances share this state. Requires state every instance sees (a FeltDB server, or local
   * state opened `shared`) and custody that keeps versions (the vault, on a directory every instance sees).
   */
  multiInstance?: boolean;
  /** Secret custody. Default: the encrypted vault in `vaultDirectory` under `vaultKey`. It must keep versions (`VersionedCustody`); a latest-only custody is refused at startup. */
  custody?: VersionedCustody;
  vaultDirectory?: string;
  /** 32 bytes: the key new secret versions are sealed with. Required unless `custody` is given. */
  vaultKey?: Buffer;
  /** Earlier vault keys, accepted for opening until `vault.rotate()` has re-sealed everything. */
  previousVaultKeys?: Buffer[];
  /** Server-held API key verifier key (at least 32 bytes), mixed into new key verifiers. Never persisted. */
  verifierKey?: string;
  targets?: Omit<TargetCheckOptions, 'lookup' | 'outbound'>;
  sync?: SyncOptions;
  /** Record observed resolutions and reported usage (default true). Never blocks or fails a resolution. */
  observeResolutions?: boolean;
  /** How long increments of one observation are held before they are added to its row. Default 60 000 ms. */
  observationWindowMs?: number;
  /** A consumer registration is live while its watch stream was seen within this. Default 120 000 ms. */
  consumerGraceMs?: number;
  /**
   * The management UI and its JSON API, on the same server. Default on; `false` serves only the AppPort API.
   * `authenticate` is the host's identity adapter (an SSO proxy, an embedding application).
   */
  management?: false | Omit<ManagementOptions, 'resolver' | 'services' | 'store' | 'log'>;
  /** Structured logs. Default: none (`createLogger` writes JSON lines). */
  logger?: Logger;
  /**
   * Check the state against the custody once at startup (`integrity.ts`); the instance is not ready while
   * problems remain. Use after a restore or a vault migration.
   */
  verifyIntegrityOnStart?: boolean;
  /** This instance's name in logs and readiness. Default: host name and a random suffix. */
  instanceId?: string;
  now?: () => Date;
}

export interface ReadinessReport {
  ready: boolean;
  instance: string;
  checks: {
    config: { ok: boolean; environment: Environment; outbound: OutboundPolicy['mode']; multiInstance: boolean };
    state: { ok: boolean; error?: string };
    sync: { ok: boolean; applied: number; latest: number; sinceSuccessMs: number | null; consecutiveFailures: number };
    custody: { ok: boolean; kind: 'vault' | 'external'; error?: string };
    integrity: { ok: boolean; checked: boolean; problems: number };
  };
}

export interface ResolverRuntime {
  resolver: Resolver;
  services: AppPortServices;
  store: ResolverStore;
  db: StateFirstDB;
  app: ResolverApplication;
  sync: RevisionSync;
  outbound: OutboundPolicy;
  /** The vault, when the runtime created one (not when `custody` was given). */
  vault: Vault | undefined;
  custody: VersionedCustody;
  log: Logger;
  instanceId: string;
  /** A principal with every permission in `tenantId`, for bootstrap and embedding. Never leaves this process. */
  operator(tenantId: string): VerifiedPrincipal;
  /** Observed resolutions and reported usage (absent when `observeResolutions` is false). */
  observations: ObservationRecorder | undefined;
  readiness(): Promise<ReadinessReport>;
  /** Checks every secret revision against the custody (no material leaves the process). */
  integrity(): Promise<IntegrityReport>;
  serve(options?: { port?: number; host?: string }): ReturnType<typeof serveResolver>;
  close(): Promise<void>;
}

function openState(state: ResolverRuntimeOptions['state']): { db: StateFirstDB; owned: boolean } {
  if ('db' in state) return { db: state.db, owned: false };
  // FeltDB memory instances with the same namespace share their data within a process: each memory runtime
  // gets its own, or two resolvers (two tests, two embedded instances) would see each other's state.
  if ('memory' in state) return { db: createFeltDB({ namespace: `resolver-${randomUUID()}`, memory: true }), owned: true };
  if ('remote' in state) {
    return { db: createFeltDB({ namespace: 'resolver', mode: 'remote', server: state.remote } as never), owned: true };
  }
  return {
    db: createFeltDB({ namespace: 'resolver', mode: 'local', path: path.join(state.local, 'state'), ...(state.shared ? { access: 'shared' } : {}) } as never),
    owned: true,
  };
}

function checkMultiInstance(options: ResolverRuntimeOptions, custody: VersionedCustody) {
  if (!options.multiInstance) return;
  const state = options.state;
  if ('memory' in state) throw new Error('multiInstance: memory state is private to one process; use a FeltDB server');
  if ('local' in state && !state.shared) throw new Error('multiInstance: local state must be opened with shared: true (one host only); across hosts use a FeltDB server');
  // A custody that keeps one version cannot keep a committed revision revealable when two instances
  // write the same secret at once (only one commit wins, but both stored).
  if (!custody.discardVersion) {
    throw new Error('multiInstance: secret custody must keep versions (withSecretVersion, discardVersion), like the vault');
  }
}

async function timed<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([work, new Promise<never>((_, reject) => (timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'TIMEOUT' })), ms)))]);
  } finally {
    clearTimeout(timer);
  }
}

export async function createResolverRuntime(options: ResolverRuntimeOptions): Promise<ResolverRuntime> {
  const environment = options.environment ?? 'production';
  const instanceId = options.instanceId ?? `${hostname()}-${randomUUID().slice(0, 8)}`;
  const log = options.logger ?? silentLogger(instanceId);
  // Invalid outbound configuration is a startup error, not a quiet fallback.
  const outbound = createOutboundPolicy(environment, options.outbound ?? {});

  let vault: Vault | undefined;
  let custody = options.custody;
  if (!custody) {
    if (!options.vaultKey) throw new Error('a vault key (32 bytes) is required unless a custody is given');
    const directory = options.vaultDirectory ?? ('local' in options.state ? path.join(options.state.local, 'vault') : undefined);
    if (!directory) throw new Error('vaultDirectory is required with this state option');
    vault = createVault({ directory, key: options.vaultKey, ...(options.previousVaultKeys ? { previousKeys: options.previousVaultKeys } : {}), ...(options.now ? { now: options.now } : {}) });
    custody = vault;
  }
  requireVersionedCustody(custody);
  checkMultiInstance(options, custody);

  const { db, owned } = openState(options.state);
  const store = new ResolverStore(db);
  const authorizer = new GrantAuthorizer(store);
  const services = await createServices({
    db,
    application: APPLICATION_ID,
    authorizer,
    credentials: custody,
    // AppPort Services reads the API-key verifier key as `apiKeyVerifierKey`.
    ...(options.verifierKey ? { apiKeyVerifierKey: options.verifierKey } : {}),
  });
  const observations = options.observeResolutions === false ? undefined : new ObservationRecorder({ store, log, ...(options.observationWindowMs !== undefined ? { windowMs: options.observationWindowMs } : {}), ...(options.now ? { now: options.now } : {}) });
  const resolver = new Resolver({
    store,
    authorizer,
    custody,
    services,
    targets: { ...(options.targets ?? {}), outbound },
    ...(options.now ? { now: options.now } : {}),
    ...(observations ? { observations } : {}),
    ...(options.consumerGraceMs !== undefined ? { consumerGraceMs: options.consumerGraceMs } : {}),
  });
  const sync = new RevisionSync(store, db, resolver, log, options.sync);
  resolver.onCommitted(() => void sync.pass());
  await sync.start();
  const app = createResolverApplication(resolver, services, { ui: options.management !== false, log });
  const management = options.management === false ? undefined : createManagementHandler({ resolver, services, store, log, ...options.management });
  const running: Array<{ close(): Promise<void> }> = [];
  const integrity = () => verifyIntegrity(store, custody!, vault);
  let startupIntegrity: IntegrityReport | undefined;
  if (options.verifyIntegrityOnStart) {
    startupIntegrity = await integrity();
    for (const problem of startupIntegrity.problems.slice(0, 50)) {
      log.error('integrity.problem', { reason: `integrity.${problem.problem}`, tenant: problem.tenantId, ref: problem.ref, ...(problem.revision !== undefined ? { revision: problem.revision } : {}) });
    }
    log.info('integrity.checked', { count: startupIntegrity.checked.secretVersions, detail: startupIntegrity.ok ? 'ok' : `${startupIntegrity.problems.length} problems` });
  }
  log.info('runtime.started', { detail: `${environment}; outbound ${outbound.mode}; ${options.multiInstance ? 'multi-instance' : 'single-instance'}`, applied: sync.status.applied });

  async function readiness(): Promise<ReadinessReport> {
    const state: ReadinessReport['checks']['state'] = { ok: true };
    try {
      await timed(store.sequence(), 2000);
    } catch (error) {
      state.ok = false;
      state.error = (error as { code?: string }).code ?? (error as Error).name;
    }
    const custodyCheck: ReadinessReport['checks']['custody'] = { ok: true, kind: vault ? 'vault' : 'external' };
    if (vault) {
      try {
        await access(vault.directory, constants.R_OK | constants.W_OK);
      } catch (error) {
        // A vault directory not created yet (no secret stored) is fine; one that cannot be used is not.
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          custodyCheck.ok = false;
          custodyCheck.error = (error as NodeJS.ErrnoException).code ?? 'ERROR';
        }
      }
    }
    const status = sync.status;
    const report: ReadinessReport = {
      ready: false,
      instance: instanceId,
      checks: {
        config: { ok: true, environment, outbound: outbound.mode, multiInstance: Boolean(options.multiInstance) },
        state,
        sync: { ok: sync.healthy, applied: status.applied, latest: status.latest, sinceSuccessMs: status.sinceSuccessMs, consecutiveFailures: status.consecutiveFailures },
        custody: custodyCheck,
        integrity: { ok: startupIntegrity ? startupIntegrity.ok : true, checked: Boolean(startupIntegrity), problems: startupIntegrity?.problems.length ?? 0 },
      },
    };
    report.ready = Object.values(report.checks).every((check) => check.ok);
    return report;
  }

  /** `/_resolver/health` (process up) and `/_resolver/ready` (safe to route traffic here); then the UI. */
  async function operational(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
    const url = request.url?.split('?')[0];
    if (request.method !== 'GET' || (url !== '/_resolver/health' && url !== '/_resolver/ready')) return false;
    const headers = { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
    if (url === '/_resolver/health') {
      response.writeHead(200, headers).end(JSON.stringify({ status: 'ok', instance: instanceId }));
      return true;
    }
    const report = await readiness();
    if (!report.ready) log.warn('runtime.not-ready', { reason: 'runtime.not-ready', detail: Object.entries(report.checks).filter(([, c]) => !c.ok).map(([k]) => k).join(',') });
    response.writeHead(report.ready ? 200 : 503, headers).end(JSON.stringify(report));
    return true;
  }

  return {
    resolver,
    services,
    store,
    db,
    app,
    sync,
    outbound,
    vault,
    custody,
    log,
    instanceId,
    observations,
    operator(tenantId: string) {
      const principal = services.identify({ principalId: 'operator', principalType: OPERATOR_TYPE, tenantId });
      if (!principal) throw new Error('could not mint the operator principal');
      return principal;
    },
    readiness,
    integrity,
    async serve(serveOptions) {
      const fallback = (request: IncomingMessage, response: ServerResponse) => {
        void operational(request, response).then((handled) => {
          if (handled) return;
          if (management) return management.handle(request, response);
          response.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { code: 'NOT_FOUND', message: 'not found' } }));
        });
      };
      const server = await serveResolver(app, { ...serveOptions, fallback });
      running.push(server);
      return server;
    },
    async close() {
      // Held observations are written before the state closes: a clean shutdown loses none.
      await observations?.close();
      await sync.stop();
      for (const server of running.splice(0)) await server.close();
      if (owned) await Promise.resolve(db.close());
    },
  };
}

export { createLogger };
