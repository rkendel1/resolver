/**
 * The management HTTP surface: the packaged pages and the JSON API they call (`/_resolver/*`), mounted on
 * the resolver's own server through AppPort's `fallback` (the AppPort binding keeps `/appport`,
 * `/.well-known/appport` and `/v1/ui`).
 *
 * Who is calling, in order:
 * 1. the host's identity adapter (`authenticate`), as AppPort Services' management host does: an SSO proxy
 *    or an embedding application supplies the identity;
 * 2. `Authorization: Bearer <API key>`;
 * 3. a browser session: an operator signs in with an API key once and gets an HttpOnly, SameSite=Strict
 *    cookie. The browser's script never sees the key or the session, and keeps nothing in storage.
 *
 * Every operation goes through the same `Resolver` methods and grants as the AppPort API: the UI can do
 * nothing a key could not. Secret values can be set from the UI but are never returned to it.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AppPortServices, PrincipalClaims, VerifiedPrincipal } from '@appport/services';
import { INTELLIGENCE_CATALOG } from '@appport/services';
import { REASONS } from '@appport/resolver-core';
import { isOperator } from '../authorizer.js';
import { isLive } from '../principals.js';
import { checkGrant, ResolverError, type Resolver } from '../resolver.js';
import { PAGES } from './contribution.js';
import { renderPage, SIGN_IN } from './pages.js';

export interface ManagementOptions {
  resolver: Resolver;
  services: AppPortServices;
  /**
   * Host identity adapter (an SSO proxy header, an embedding application's session). Identity only:
   * what the principal may do comes from grants. Return `principalType: 'resolver-operator'` for full access.
   */
  authenticate?: (request: IncomingMessage) => PrincipalClaims | null | undefined | Promise<PrincipalClaims | null | undefined>;
  /** Let operators sign in with an API key and get a session cookie. Default true. */
  signIn?: boolean;
  /** Session lifetime and idle timeout. Defaults 8 hours and 30 minutes. */
  sessionTtlMs?: number;
  sessionIdleMs?: number;
}

const COOKIE = 'resolver_session';
const MAX_BODY = 64 * 1024;
const SIGN_IN_LIMIT = 10;
const SIGN_IN_WINDOW_MS = 60_000;

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly reason?: string) {
    super(message);
  }
}

interface Session {
  principal: VerifiedPrincipal;
  created: number;
  lastUsed: number;
}

type Caller = { principal: VerifiedPrincipal; via: 'host' | 'bearer' | 'session' };

const STATUS: Record<string, number> = { INVALID_INPUT: 400, UNAUTHORIZED: 401, FORBIDDEN: 403, NOT_FOUND: 404, CONFLICT: 409 };

export function createManagementHandler(options: ManagementOptions) {
  const { resolver, services } = options;
  const signInEnabled = options.signIn !== false;
  const ttl = options.sessionTtlMs ?? 8 * 3600_000;
  const idle = options.sessionIdleMs ?? 30 * 60_000;
  const sessions = new Map<string, Session>();
  const attempts = new Map<string, { count: number; since: number }>();
  const pageRoutes = new Map([...PAGES, SIGN_IN].map((p) => [p.route, p]));

  const tokenKey = (token: string) => createHash('sha256').update(token).digest('hex');

  function cookieToken(request: IncomingMessage): string | undefined {
    for (const part of (request.headers.cookie ?? '').split(';')) {
      const [name, ...rest] = part.trim().split('=');
      if (name === COOKIE) return rest.join('=');
    }
    return undefined;
  }

  const secure = (request: IncomingMessage) =>
    Boolean((request.socket as { encrypted?: boolean }).encrypted) || request.headers['x-forwarded-proto'] === 'https';

  async function caller(request: IncomingMessage): Promise<Caller | null> {
    if (options.authenticate) {
      const claims = await options.authenticate(request);
      if (claims) {
        const principal = services.identify(claims);
        if (principal) return { principal, via: 'host' };
      }
    }
    const header = request.headers.authorization;
    if (header?.startsWith('Bearer ')) {
      const principal = (await services.apiKeys.authenticateApiKey(header.slice(7).trim())) as VerifiedPrincipal | null;
      return principal ? { principal, via: 'bearer' } : null;
    }
    const token = cookieToken(request);
    if (token) {
      const key = tokenKey(token);
      const session = sessions.get(key);
      const now = Date.now();
      if (!session || now - session.created > ttl || now - session.lastUsed > idle || !(await isLive(services, session.principal))) {
        sessions.delete(key);
        return null;
      }
      session.lastUsed = now;
      return { principal: session.principal, via: 'session' };
    }
    return null;
  }

  async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
    const type = request.headers['content-type'] ?? '';
    if (!type.startsWith('application/json')) throw new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'send application/json');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += (chunk as Buffer).length;
      if (size > MAX_BODY) throw new HttpError(413, 'PAYLOAD_TOO_LARGE', 'the request body is too large');
      chunks.push(chunk as Buffer);
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error();
      return parsed as Record<string, unknown>;
    } catch {
      throw new HttpError(400, 'INVALID_INPUT', 'the body is not a JSON object');
    }
  }

  /** A cookie-authenticated change must come from a page of this origin (CSRF). */
  function sameOrigin(request: IncomingMessage) {
    const origin = request.headers.origin;
    const host = request.headers.host;
    if (!origin || !host) throw new HttpError(403, 'FORBIDDEN', 'cross-origin request refused');
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new HttpError(403, 'FORBIDDEN', 'cross-origin request refused');
    }
    if (parsed.host !== host) throw new HttpError(403, 'FORBIDDEN', 'cross-origin request refused');
  }

  /** Drops expired sessions and stale sign-in counters, so neither map grows without bound. */
  function sweep(now: number) {
    for (const [key, session] of sessions) if (now - session.created > ttl || now - session.lastUsed > idle) sessions.delete(key);
    for (const [ip, entry] of attempts) if (now - entry.since > SIGN_IN_WINDOW_MS) attempts.delete(ip);
  }

  function throttle(request: IncomingMessage) {
    const ip = request.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    sweep(now);
    const entry = attempts.get(ip);
    if (!entry || now - entry.since > SIGN_IN_WINDOW_MS) {
      attempts.set(ip, { count: 1, since: now });
      return;
    }
    entry.count += 1;
    if (entry.count > SIGN_IN_LIMIT) throw new HttpError(429, 'RATE_LIMITED', 'too many sign-in attempts; wait a minute');
  }

  const send = (response: ServerResponse, status: number, payload?: unknown, headers: Record<string, string> = {}) => {
    response.writeHead(status, { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...(payload === undefined ? {} : { 'content-type': 'application/json' }), ...headers });
    response.end(payload === undefined ? undefined : JSON.stringify(payload));
  };

  const query = (url: URL, name: string) => {
    const value = url.searchParams.get(name);
    if (!value) throw new HttpError(400, 'INVALID_INPUT', `${name} is required`);
    return value;
  };

  async function api(request: IncomingMessage, response: ServerResponse, url: URL) {
    const method = request.method ?? 'GET';
    const path = url.pathname;

    if (path === '/_resolver/session' && method === 'POST') {
      if (!signInEnabled) throw new HttpError(404, 'NOT_FOUND', 'sign-in is disabled on this resolver');
      sameOrigin(request);
      throttle(request);
      const { apiKey } = await body(request);
      if (typeof apiKey !== 'string' || !apiKey) throw new HttpError(400, 'INVALID_INPUT', 'apiKey is required');
      const principal = (await services.apiKeys.authenticateApiKey(apiKey.trim())) as VerifiedPrincipal | null;
      if (!principal) throw new HttpError(401, 'UNAUTHORIZED', 'that API key is not valid');
      const token = randomBytes(32).toString('base64url');
      sessions.set(tokenKey(token), { principal, created: Date.now(), lastUsed: Date.now() });
      const cookie = `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(ttl / 1000)}${secure(request) ? '; Secure' : ''}`;
      return send(response, 204, undefined, { 'set-cookie': cookie });
    }

    const who = await caller(request);
    if (!who) throw new HttpError(401, 'UNAUTHORIZED', 'sign in with an API key');
    if (method !== 'GET' && who.via === 'session') sameOrigin(request);
    const p = who.principal;

    if (path === '/_resolver/session') {
      if (method === 'DELETE') {
        const token = cookieToken(request);
        if (token) sessions.delete(tokenKey(token));
        return send(response, 204, undefined, { 'set-cookie': `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure(request) ? '; Secure' : ''}` });
      }
      const key = p.verifiedBy === 'api_key' ? await services.apiKeys.getApiKey(p.tenantId, p.principalId).catch(() => null) : null;
      return send(response, 200, {
        principal: p.principalId,
        ...(key ? { name: key.name } : {}),
        tenant: p.tenantId,
        operator: isOperator(p),
        via: who.via,
        canSignOut: who.via === 'session',
      });
    }

    if (method === 'GET') {
      switch (path) {
        case '/_resolver/references':
          return send(response, 200, await resolver.list(p, { ...(url.searchParams.get('prefix') ? { prefix: url.searchParams.get('prefix')! } : {}) }));
        case '/_resolver/reference': {
          const ref = query(url, 'ref');
          const history = await resolver.history(p, { ref });
          let current: unknown = null;
          let revoked = false;
          try {
            const key = url.searchParams.get('key');
            current = await resolver.resolve(p, { ref, ...(key ? { key } : {}) });
          } catch (error) {
            if (error instanceof ResolverError && error.reason === REASONS.revoked) revoked = true;
            else throw error;
          }
          const summary = (await resolver.list(p, { prefix: ref })).refs.find((r) => r.ref === ref) ?? null;
          return send(response, 200, { summary, current, revoked, history: history.entries });
        }
        case '/_resolver/catalog':
          return send(response, 200, {
            providers: INTELLIGENCE_CATALOG.map((provider) => ({
              id: provider.id,
              name: provider.displayName,
              models: provider.models.map((m) => ({ id: m.id, name: m.displayName })),
              modelSelection: provider.modelSelection,
              customEndpoint: provider.customEndpoint,
              credential: provider.credential,
            })),
          });
        case '/_resolver/keys':
          return send(response, 200, await resolver.listKeys(p));
        case '/_resolver/grants':
          return send(response, 200, await resolver.grants(p));
        case '/_resolver/reveals':
          return send(response, 200, await resolver.reveals(p, { ref: query(url, 'ref') }));
      }
    }

    if (method === 'POST') {
      const input = await body(request);
      switch (path) {
        case '/_resolver/references':
          return send(response, 200, await resolver.put(p, input as never));
        case '/_resolver/rollback':
          return send(response, 200, await resolver.rollback(p, input as never));
        case '/_resolver/revoke':
          return send(response, 200, await resolver.revoke(p, input as never));
        case '/_resolver/keys': {
          // Every grant is checked before the key exists: a refused grant must not leave a key whose secret
          // was never shown.
          const grants = input['grants'] ?? [];
          if (!Array.isArray(grants)) throw new HttpError(400, 'INVALID_INPUT', 'grants must be a list');
          for (const grant of grants as Array<{ actions: unknown; pattern: unknown }>) checkGrant(grant ?? {});
          const created = await resolver.createKey(p, { name: String(input['name'] ?? '') });
          for (const grant of grants as Array<{ actions: string[]; pattern: string }>) {
            await resolver.grant(p, { subject: created.principal, actions: grant.actions, pattern: grant.pattern });
          }
          return send(response, 200, created);
        }
        case '/_resolver/keys/revoke':
          return send(response, 200, await resolver.revokeKey(p, { id: String(input['id'] ?? '') }));
        case '/_resolver/grants':
          return send(response, 200, await resolver.grant(p, input as never));
        case '/_resolver/grants/remove':
          return send(response, 200, await resolver.ungrant(p, { id: String(input['id'] ?? '') }));
      }
    }
    throw new HttpError(404, 'NOT_FOUND', 'no such management route');
  }

  async function handle(request: IncomingMessage, response: ServerResponse) {
    const url = new URL(request.url ?? '/', 'http://resolver.local');
    try {
      if (url.pathname.startsWith('/_resolver/')) return await api(request, response, url);
      if (request.method !== 'GET' && request.method !== 'HEAD') throw new HttpError(405, 'METHOD_NOT_ALLOWED', 'method not allowed');
      if (url.pathname === '/' || url.pathname === '') return send(response, 302, undefined, { location: '/resolver' });
      const page = pageRoutes.get(url.pathname);
      if (!page || (page === SIGN_IN && !signInEnabled)) throw new HttpError(404, 'NOT_FOUND', 'not found');
      const rendered = renderPage(page);
      response.writeHead(200, rendered.headers);
      response.end(request.method === 'HEAD' ? undefined : rendered.html);
    } catch (error) {
      if (error instanceof HttpError) return send(response, error.status, { error: { code: error.code, message: error.message, ...(error.reason ? { reason: error.reason } : {}) } });
      if (error instanceof ResolverError) {
        return send(response, STATUS[error.code] ?? 500, { error: { ...error.details, code: error.code, message: error.message, reason: error.reason } });
      }
      const code = (error as { code?: string }).code;
      if (code === 'DENIED') return send(response, 403, { error: { code: 'FORBIDDEN', message: 'not allowed' } });
      send(response, 500, { error: { code: 'INTERNAL_ERROR', message: 'the resolver could not complete the request' } });
    }
  }

  return {
    handle: (request: IncomingMessage, response: ServerResponse) => void handle(request, response),
    /** For tests and hosts: the number of live browser sessions. */
    get sessionCount() {
      return sessions.size;
    },
  };
}
