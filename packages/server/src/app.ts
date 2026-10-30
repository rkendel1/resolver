/**
 * The resolver as an AppPort application: every operation is an AppPort capability, so any AppPort
 * client (the resolver client, the AppPort SDK, Stack-Agent, a plain HTTP client) can call it.
 *
 * Authentication: `Authorization: Bearer <API key>`, verified by AppPort Services' `ApiKeyService`
 * (scrypt verifiers, rotation, revocation). An unauthenticated caller holds no permission and every
 * capability refuses it. Authorization is then per reference, by grant (`authorizer.ts`).
 */

import { randomUUID } from 'node:crypto';
import { permissionAuthorizer } from '@appport/authorization';
import { createApplication, defineCapability, defineStreamCapability, type AppPortApplication } from '@appport/core';
import { AppPortError } from '@appport/protocol';
import { fromJSONSchema } from '@appport/schema';
import { createServer, type AppPortServer } from '@appport/server';
import { serve, type RunningServer } from '@appport/server/node';
import type { AppPortServices, VerifiedPrincipal } from '@appport/services';
import { CAPABILITIES } from '@appport/resolver-core';
import { silentLogger, type Logger } from './log.js';
import { isLive } from './principals.js';
import { Resolver, ResolverError } from './resolver.js';
import { createUiContribution } from './ui/contribution.js';

export const APPLICATION_ID = 'dev.appport.resolver';
const PERMISSION = 'resolver.call';
const HEARTBEAT_MS = 15_000;
const SESSION_TTL_MS = 2 * 60_000;
const SWEEP_EVERY_MS = 30_000;

const object = (properties: Record<string, unknown> = {}, required: string[] = []) =>
  fromJSONSchema({ type: 'object', properties, required } as never);
const any = fromJSONSchema({} as never);
const str = { type: 'string' };
const int = { type: 'integer' };

/** Maps the session a request was authenticated with to its verified principal. */
class Sessions {
  readonly #byId = new Map<string, { principal: VerifiedPrincipal; expires: number }>();
  #sweptAt = Date.now();
  add(principal: VerifiedPrincipal): string {
    const id = `ses_${randomUUID().replaceAll('-', '')}`;
    const now = Date.now();
    this.#byId.set(id, { principal, expires: now + SESSION_TTL_MS });
    if (now - this.#sweptAt > SWEEP_EVERY_MS) {
      this.#sweptAt = now;
      for (const [key, entry] of this.#byId) if (entry.expires < now) this.#byId.delete(key);
    }
    return id;
  }
  /** Sliding expiry: a WebSocket session stays known while it is used. */
  get(id: string | undefined): VerifiedPrincipal {
    const entry = id ? this.#byId.get(id) : undefined;
    if (!entry || entry.expires < Date.now()) throw new AppPortError('UNAUTHORIZED', 'an API key is required');
    entry.expires = Date.now() + SESSION_TTL_MS;
    return entry.principal;
  }
  drop(id: string | undefined) {
    if (id) this.#byId.delete(id);
  }
}

function toAppPortError(error: unknown): never {
  if (error instanceof ResolverError) {
    throw new AppPortError(error.code, error.message, { details: { reason: error.reason, ...error.details } as never });
  }
  if (AppPortError.is(error)) throw error;
  const code = (error as { code?: string }).code;
  if (code === 'DENIED' || code === 'FORBIDDEN') throw new AppPortError('FORBIDDEN', 'not allowed');
  throw new AppPortError('INTERNAL_ERROR', 'the resolver could not complete the request');
}

export interface ResolverApplication {
  application: AppPortApplication;
  server: AppPortServer;
}

export function createResolverApplication(resolver: Resolver, services: AppPortServices, options: { ui?: boolean; log?: Logger } = {}): ResolverApplication {
  const sessions = new Sessions();
  const log = options.log ?? silentLogger();
  /**
   * A WebSocket connection authenticates once; the key may be revoked or expire while it stays open.
   * The key's record is re-read on every call and every streamed event, so revocation is immediate.
   */
  const live = (principal: VerifiedPrincipal) => isLive(services, principal);
  const authenticated = async (sessionId: string | undefined): Promise<VerifiedPrincipal> => {
    const principal = sessions.get(sessionId);
    if (!(await live(principal))) {
      sessions.drop(sessionId);
      throw new AppPortError('UNAUTHORIZED', 'the API key was revoked or has expired');
    }
    return principal;
  };
  /**
   * One log line per call: operation, outcome code and reason, duration, the caller's tenant and key id,
   * the reference name and resulting revision. Never the input, binding, secret or error message.
   */
  const call =
    <I, O>(operation: string, fn: (principal: VerifiedPrincipal, input: I) => Promise<O>) =>
    async (input: I, context: { session?: { id: string } }) => {
      const started = performance.now();
      const requestId = `req_${randomUUID().replaceAll('-', '').slice(0, 20)}`;
      const ref = typeof (input as { ref?: unknown })?.ref === 'string' && ((input as { ref: string }).ref.length <= 512) ? (input as { ref: string }).ref : undefined;
      let principal: VerifiedPrincipal | undefined;
      try {
        principal = await authenticated(context.session?.id);
        const result = await fn(principal, input);
        const revision = (result as { revision?: unknown })?.revision;
        log.info('call', { requestId, operation, code: 'OK', durationMs: Math.round(performance.now() - started), tenant: principal.tenantId, principal: principal.principalId, ...(ref ? { ref } : {}), ...(typeof revision === 'number' ? { revision } : {}) });
        return result;
      } catch (error) {
        const code = error instanceof ResolverError ? error.code : AppPortError.is(error) ? (error as { code: string }).code : 'INTERNAL_ERROR';
        const reason = error instanceof ResolverError ? error.reason : undefined;
        (code === 'INTERNAL_ERROR' ? log.error : log.info)('call', { requestId, operation, code, ...(reason ? { reason } : {}), durationMs: Math.round(performance.now() - started), ...(principal ? { tenant: principal.tenantId, principal: principal.principalId } : {}), ...(ref ? { ref } : {}) });
        if (!principal) throw error;
        toAppPortError(error);
      }
    };

  const capability = (name: string, effect: 'observation' | 'consequential', input: ReturnType<typeof object>, handler: ReturnType<typeof call>, description: string) =>
    defineCapability({ name, version: 1, description, effect, authorization: [PERMISSION], input, output: any, handler: handler as never } as never);

  const capabilities = [
    capability(CAPABILITIES.resolve, 'observation', object({ ref: str, revision: int, key: str, reveal: { type: 'boolean' } }, ['ref']), call(CAPABILITIES.resolve, (p, i) => resolver.resolve(p, i as never)), 'Resolves a reference to its current (or pinned) binding.'),
    capability(CAPABILITIES.put, 'consequential', object({ ref: str, kind: str, schema: {}, binding: {}, secret: str, expectedRevision: int, reason: str, ttlSeconds: int }, ['ref', 'expectedRevision']), call(CAPABILITIES.put, (p, i) => resolver.put(p, i as never)), 'Creates or updates a reference, conditional on its current revision.'),
    capability(CAPABILITIES.history, 'observation', object({ ref: str, limit: int }, ['ref']), call(CAPABILITIES.history, (p, i) => resolver.history(p, i as never)), 'Every revision of a reference, with actor and reason.'),
    capability(CAPABILITIES.rollback, 'consequential', object({ ref: str, toRevision: int, expectedRevision: int, reason: str }, ['ref', 'toRevision', 'expectedRevision']), call(CAPABILITIES.rollback, (p, i) => resolver.rollback(p, i as never)), 'Restores an earlier revision as a new revision.'),
    capability(CAPABILITIES.revoke, 'consequential', object({ ref: str, expectedRevision: int, reason: str }, ['ref', 'expectedRevision']), call(CAPABILITIES.revoke, (p, i) => resolver.revoke(p, i as never)), 'Revokes a reference: every resolution fails from now on.'),
    capability(CAPABILITIES.list, 'observation', object({ prefix: str }), call(CAPABILITIES.list, (p, i) => resolver.list(p, i as never)), 'References the caller may read.'),
    capability(CAPABILITIES.grant, 'consequential', object({ subject: str, actions: { type: 'array', items: str }, pattern: str }, ['subject', 'actions', 'pattern']), call(CAPABILITIES.grant, (p, i) => resolver.grant(p, i as never)), 'Grants actions on references to a principal.'),
    capability(CAPABILITIES.ungrant, 'consequential', object({ id: str }, ['id']), call(CAPABILITIES.ungrant, (p, i) => resolver.ungrant(p, i as never)), 'Removes a grant.'),
    capability(CAPABILITIES.grants, 'observation', object(), call(CAPABILITIES.grants, (p) => resolver.grants(p)), 'Grants in the caller\'s tenant.'),
    capability(CAPABILITIES.createKey, 'consequential', object({ name: str, expiresAt: str }, ['name']), call(CAPABILITIES.createKey, (p, i) => resolver.createKey(p, i as never)), 'Issues an API key (the secret is returned once).'),
    capability(CAPABILITIES.revokeKey, 'consequential', object({ id: str }, ['id']), call(CAPABILITIES.revokeKey, (p, i) => resolver.revokeKey(p, i as never)), 'Revokes an API key.'),
    capability(CAPABILITIES.listKeys, 'observation', object(), call(CAPABILITIES.listKeys, (p) => resolver.listKeys(p)), 'API keys in the caller\'s tenant.'),
    defineStreamCapability({
      name: CAPABILITIES.watch,
      version: 1,
      description: 'Streams change notifications for references the caller may read; heartbeats keep the stream alive.',
      effect: 'observation',
      authorization: [PERMISSION],
      input: object({ refs: { type: 'array', items: str }, prefix: str }),
      output: any,
      timeoutMs: 24 * 3600_000,
      handler: async (input: { refs?: string[]; prefix?: string }, context: { session?: { id: string }; signal: AbortSignal }) => {
        const principal = await authenticated(context.session?.id);
        return whileLive(withHeartbeat(resolver.watch(principal, input, context.signal), context.signal), () => live(principal));
      },
    } as never),
  ];

  const application = createApplication({
    application: { id: APPLICATION_ID, name: 'Resolver', version: '0.1.0', description: 'Stable references to models, providers, secrets, endpoints, agents and configuration.' },
    authorizer: permissionAuthorizer(),
    mode: 'production',
    capabilities,
  } as never);

  const server = createServer({
    application,
    // `GET /v1/ui`: the management pages as an AppPort/ui/1 contribution, filtered per caller by AppPort.
    ...(options.ui === false ? {} : { ui: createUiContribution() }),
    authenticate: async ({ headers }) => {
      const header = headers?.['authorization'];
      if (!header?.startsWith('Bearer ')) return {};
      const principal = (await services.apiKeys.authenticateApiKey(header.slice('Bearer '.length).trim())) as VerifiedPrincipal | null;
      if (!principal) return {};
      const id = sessions.add(principal);
      return {
        session: { id, applicationId: APPLICATION_ID, createdAt: new Date().toISOString(), principal: { id: principal.principalId, type: 'service' }, permissions: [PERMISSION] },
        principal: { id: principal.principalId, type: 'service' },
      } as never;
    },
  });
  return { application, server };
}

/** Ends a stream as soon as its caller's key is no longer valid (checked before every chunk). */
async function* whileLive<T>(source: AsyncGenerator<T>, isLive: () => Promise<boolean>): AsyncGenerator<T> {
  try {
    for await (const chunk of source) {
      if (!(await isLive())) throw new AppPortError('UNAUTHORIZED', 'the API key was revoked or has expired');
      yield chunk;
    }
  } finally {
    await source.return?.(undefined);
  }
}

async function* withHeartbeat<T>(source: AsyncGenerator<T>, signal: AbortSignal): AsyncGenerator<T | { heartbeat: string }> {
  const iterator = source[Symbol.asyncIterator]();
  // Starting the source subscribes it; the first heartbeat tells the client that changes from now on reach it.
  let pending = iterator.next();
  try {
    yield { heartbeat: new Date().toISOString() };
    while (!signal.aborted) {
      let timer: NodeJS.Timeout | undefined;
      const tick = new Promise<'tick'>((resolve) => (timer = setTimeout(() => resolve('tick'), HEARTBEAT_MS)));
      const next = await Promise.race([pending, tick]);
      clearTimeout(timer);
      if (next === 'tick') {
        yield { heartbeat: new Date().toISOString() };
        continue;
      }
      if (next.done) return;
      yield next.value;
      pending = iterator.next();
    }
  } finally {
    await iterator.return?.(undefined);
  }
}

export async function serveResolver(
  app: ResolverApplication,
  options: { port?: number; host?: string; fallback?: (request: import('node:http').IncomingMessage, response: import('node:http').ServerResponse) => void } = {},
): Promise<RunningServer> {
  const running = await serve({
    server: app.server,
    port: options.port ?? 4300,
    host: options.host ?? '127.0.0.1',
    ...(options.fallback ? { fallback: options.fallback } : {}),
  } as never);
  // Long-lived watch streams and WebSocket sessions would otherwise keep close() waiting forever.
  const sockets = new Set<import('node:net').Socket>();
  running.httpServer.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  return {
    get url() {
      return running.url;
    },
    get port() {
      return running.port;
    },
    get httpServer() {
      return running.httpServer;
    },
    async close() {
      const closing = running.close();
      for (const socket of sockets) socket.destroy();
      await closing;
    },
  };
}
