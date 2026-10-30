/**
 * The resolver client: an application resolves references at run time instead of reading values from
 * its deployment. Change a reference and every running consumer picks it up; nothing is redeployed.
 *
 * - Results are cached until a change notification arrives (live) or the reference's TTL passes, whichever
 *   is first. A live connection never extends a result past its TTL: a notification can be missed (another
 *   resolver instance, a reconnect), and the TTL bounds how long that goes unnoticed.
 * - Pinned resolutions (`revision`) are cached the same way: the binding of a revision never changes, but
 *   revocation and grants do, and they are rechecked.
 * - Weighted bindings are steered locally from the cached targets: the same key always gets the same
 *   target, with no request per call.
 * - If the resolver is unreachable, the last known good result is served for at most `maxStaleSeconds`.
 *   Authoritative answers (revoked, forbidden, not found) are never papered over: they evict the cache.
 * - Secret material is held in memory only, for the reference's TTL, and never written anywhere.
 */

import { AppPort, type AppPortClient } from '@appport/sdk';
import {
  CAPABILITIES,
  REASONS,
  select,
  type Binding,
  type ChangeEvent,
  type Grant,
  type HistoryEntry,
  type ModelTarget,
  type PutInput,
  type ReferenceSummary,
  type ResolveResult,
  type Target,
  type WriteResult,
} from '@appport/resolver-core';

export interface ResolverClientOptions {
  /** The resolver's origin, e.g. `https://resolver.internal.example.com`. */
  url: string;
  apiKey: string;
  /** Subscribe to change notifications so updates arrive immediately. Default true. */
  live?: boolean;
  /** How long a cached result may be served while the resolver is unreachable. Default 300; 0 fails closed. */
  maxStaleSeconds?: number;
  /** Called when the client serves stale results or loses its live connection. */
  /** Per-request timeout in milliseconds. A slow resolver becomes a transport failure. Default 5000. */
  timeoutMs?: number;
  onWarning?: (warning: { kind: 'stale' | 'disconnected' | 'reconnected'; ref?: string; error?: unknown }) => void;
  fetch?: typeof globalThis.fetch;
}

export class ResolverClientError extends Error {
  constructor(
    readonly code: string,
    readonly reason: string | undefined,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
  /** True when the resolver answered (the answer is authoritative); false when it could not be reached. */
  get authoritative(): boolean {
    return ['NOT_FOUND', 'FORBIDDEN', 'UNAUTHORIZED', 'INVALID_INPUT', 'CONFLICT'].includes(this.code);
  }
}

interface Cached {
  result: ResolveResult;
  fetchedAt: number;
  /** Set when a change notification invalidated it while a refetch was not yet done. */
  invalid: boolean;
}

interface CachedSecret {
  value: string;
  revision: number;
  fetchedAt: number;
}

export interface ResolvedModel extends ModelTarget {
  /** The provider credential, when the model names one and this client may reveal it. */
  apiKey?: string;
  ref: string;
  revision: number;
  label?: string;
  /** The revision of the credential reference whose material is in `apiKey`: with `ref` and `revision`, a receipt of what was used. */
  credentialRevision?: number;
}

const AUTHORITATIVE = new Set(['NOT_FOUND', 'FORBIDDEN', 'UNAUTHORIZED', 'INVALID_INPUT', 'CONFLICT']);

function toError(error: unknown): ResolverClientError {
  if (error instanceof ResolverClientError) return error;
  const e = error as { code?: string; message?: string; details?: Record<string, unknown> };
  const details = (e.details ?? {}) as Record<string, unknown>;
  return new ResolverClientError(e.code ?? 'UNAVAILABLE', details['reason'] as string | undefined, e.message ?? String(error), details);
}

export class ResolverClient {
  readonly #options: Required<Pick<ResolverClientOptions, 'live' | 'maxStaleSeconds' | 'timeoutMs'>> & ResolverClientOptions;
  #client: AppPortClient | undefined;
  #connecting: Promise<AppPortClient> | undefined;
  readonly #cache = new Map<string, Cached>();
  readonly #secrets = new Map<string, CachedSecret>();
  readonly #inflight = new Map<string, Promise<ResolveResult>>();
  /**
   * Bumped by every change notification for a reference (and, for all references, by every reconnect).
   * A fetch that was in flight across a bump may carry the old binding, so its result is cached as invalid.
   */
  readonly #generations = new Map<string, number>();
  #epoch = 0;
  readonly #listeners = new Map<string, Set<(event: ChangeEvent) => void>>();
  #watching = false;
  #closed = false;
  #stream: { cancel(reason?: string): void } | undefined;

  constructor(options: ResolverClientOptions) {
    this.#options = { live: true, maxStaleSeconds: 300, timeoutMs: 5000, ...options };
  }

  /** Connects (and starts the live subscription). Optional: the first request connects on its own. */
  static async connect(options: ResolverClientOptions): Promise<ResolverClient> {
    const client = new ResolverClient(options);
    await client.#connection();
    if (client.#options.live) client.#startWatch();
    return client;
  }

  // ---- resolution -------------------------------------------------------------------------------

  /** The full resolution: binding, revision, and the target selected for `key`. */
  async resolve(ref: string, options: { key?: string; revision?: number } = {}): Promise<ResolveResult> {
    return this.#steer(await this.#current(ref, options.revision), options.key);
  }

  /** The selected target's value. */
  async get<T = Target>(ref: string, options: { key?: string } = {}): Promise<T> {
    return (await this.resolve(ref, options)).selected.value as T;
  }

  /** Secret material for a `secret` reference. Needs a `reveal` grant. Held in memory for the TTL only. */
  async secret(ref: string): Promise<string> {
    return (await this.#secretWithRevision(ref)).value;
  }

  async #secretWithRevision(ref: string): Promise<CachedSecret> {
    const current = await this.#current(ref);
    const cached = this.#secrets.get(ref);
    if (cached && cached.revision === current.revision && Date.now() - cached.fetchedAt < current.ttlSeconds * 1000) return cached;
    const revealed = await this.#call<ResolveResult>(CAPABILITIES.resolve, { ref, reveal: true });
    if (revealed.secret === undefined) throw new ResolverClientError('INTERNAL_ERROR', undefined, `${ref} returned no material`);
    const entry = { value: revealed.secret, revision: revealed.revision, fetchedAt: Date.now() };
    this.#secrets.set(ref, entry);
    return entry;
  }

  /**
   * A `model` reference, steered for `key`, with its credential revealed when it names one.
   * Pass the result straight to your provider SDK: provider, model, endpoint, options, apiKey.
   */
  async model(ref: string, options: { key?: string } = {}): Promise<ResolvedModel> {
    const result = await this.resolve(ref, options);
    if (result.kind !== 'model') throw new ResolverClientError('INVALID_INPUT', REASONS.kindMismatch, `${ref} is a ${result.kind}, not a model`);
    return this.#withCredential(result, result.selected.value as ModelTarget, result.selected.label);
  }

  /**
   * Runs `use` with the selected target, falling back through the binding's other targets (failover or
   * weighted order) when it throws. Throws the last error if every target fails.
   */
  async withFailover<T, R>(ref: string, use: (target: T, info: { index: number; label?: string }) => Promise<R>, options: { key?: string } = {}): Promise<R> {
    const result = await this.resolve(ref, options);
    const order = select(result as unknown as Binding<T>, { ref, ...(options.key !== undefined ? { key: options.key } : {}) }).order;
    let last: unknown;
    for (const target of order) {
      const index = result.targets.indexOf(target as never);
      try {
        const value = result.kind === 'model' ? ((await this.#withCredential(result, target.value as never, target.label)) as unknown as T) : target.value;
        return await use(value, { index, ...(target.label ? { label: target.label } : {}) });
      } catch (error) {
        last = error;
      }
    }
    throw last;
  }

  /** Called with every change to `refs` (exact names, or a prefix ending in `/`). Returns an unsubscribe. */
  watch(refs: string | string[], listener: (event: ChangeEvent) => void): () => void {
    const keys = Array.isArray(refs) ? refs : [refs];
    for (const key of keys) {
      const set = this.#listeners.get(key) ?? new Set();
      set.add(listener);
      this.#listeners.set(key, set);
    }
    if (!this.#watching && this.#options.live) this.#startWatch();
    return () => {
      for (const key of keys) this.#listeners.get(key)?.delete(listener);
    };
  }

  // ---- management (operators and CI) -------------------------------------------------------------

  put(input: PutInput): Promise<WriteResult> {
    return this.#call(CAPABILITIES.put, input);
  }
  /** Creates or replaces a binding, reading the current revision first. Not for concurrent writers. */
  async set(ref: string, input: Omit<PutInput, 'ref' | 'expectedRevision'>): Promise<WriteResult> {
    const current = await this.#call<ResolveResult>(CAPABILITIES.resolve, { ref }).catch((error) => {
      if (toError(error).reason === REASONS.notFound) return null;
      throw toError(error);
    });
    return this.put({ ...input, ref, expectedRevision: current?.currentRevision ?? 0 });
  }
  history(ref: string, limit?: number): Promise<{ entries: HistoryEntry[] }> {
    return this.#call(CAPABILITIES.history, { ref, ...(limit ? { limit } : {}) });
  }
  rollback(ref: string, toRevision: number, expectedRevision: number, reason?: string): Promise<WriteResult> {
    return this.#call(CAPABILITIES.rollback, { ref, toRevision, expectedRevision, ...(reason ? { reason } : {}) });
  }
  revoke(ref: string, expectedRevision: number, reason?: string): Promise<WriteResult> {
    return this.#call(CAPABILITIES.revoke, { ref, expectedRevision, ...(reason ? { reason } : {}) });
  }
  list(prefix?: string): Promise<{ refs: ReferenceSummary[] }> {
    return this.#call(CAPABILITIES.list, prefix ? { prefix } : {});
  }
  grant(subject: string, actions: string[], pattern: string): Promise<Grant> {
    return this.#call(CAPABILITIES.grant, { subject, actions, pattern });
  }
  ungrant(id: string): Promise<{ removed: boolean }> {
    return this.#call(CAPABILITIES.ungrant, { id });
  }
  grants(): Promise<{ grants: Grant[] }> {
    return this.#call(CAPABILITIES.grants, {});
  }
  createKey(name: string, expiresAt?: string): Promise<{ id: string; name: string; prefix: string; secret: string; principal: string }> {
    return this.#call(CAPABILITIES.createKey, { name, ...(expiresAt ? { expiresAt } : {}) });
  }
  revokeKey(id: string): Promise<{ revoked: boolean }> {
    return this.#call(CAPABILITIES.revokeKey, { id });
  }
  listKeys(): Promise<{ keys: { id: string; name: string; prefix: string; status: string }[] }> {
    return this.#call(CAPABILITIES.listKeys, {});
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#stream?.cancel('closed');
    this.#secrets.clear();
    await this.#client?.close();
  }

  // ---- internals --------------------------------------------------------------------------------

  async #current(ref: string, revision?: number): Promise<ResolveResult> {
    const key = cacheKey(ref, revision);
    const hit = this.#cache.get(key);
    const age = hit ? Date.now() - hit.fetchedAt : Infinity;
    if (hit && !hit.invalid && age < hit.result.ttlSeconds * 1000) return hit.result;
    try {
      return await this.#fetchShared(ref, revision);
    } catch (error) {
      const failure = toError(error);
      if (AUTHORITATIVE.has(failure.code)) {
        this.#cache.delete(key);
        if (revision === undefined) this.#secrets.delete(ref);
        throw failure;
      }
      if (hit && age < (hit.result.ttlSeconds + this.#options.maxStaleSeconds) * 1000) {
        this.#options.onWarning?.({ kind: 'stale', ref, error: failure });
        return hit.result;
      }
      throw failure;
    }
  }

  #fetchShared(ref: string, revision?: number): Promise<ResolveResult> {
    const key = cacheKey(ref, revision);
    const running = this.#inflight.get(key);
    if (running) return running;
    const generation = this.#generation(ref);
    const request = this.#fetch(ref, revision !== undefined ? { revision } : {})
      .then((result) => {
        this.#cache.set(key, { result, fetchedAt: Date.now(), invalid: this.#generation(ref) !== generation });
        return result;
      })
      .finally(() => this.#inflight.delete(key));
    this.#inflight.set(key, request);
    return request;
  }

  #generation(ref: string): string {
    return `${this.#epoch}.${this.#generations.get(ref) ?? 0}`;
  }

  #invalidateAll() {
    this.#epoch += 1;
    for (const entry of this.#cache.values()) entry.invalid = true;
  }

  #fetch(ref: string, extra: { revision?: number }): Promise<ResolveResult> {
    return this.#call<ResolveResult>(CAPABILITIES.resolve, { ref, ...extra });
  }

  #steer(result: ResolveResult, key?: string): ResolveResult {
    if (result.strategy !== 'weighted' && key === undefined) return result;
    const selection = select(result as unknown as Binding, { ref: result.ref, ...(key !== undefined ? { key } : {}) });
    return { ...result, selected: { value: selection.value, index: selection.index, ...(selection.label ? { label: selection.label } : {}) } };
  }

  async #withCredential(result: ResolveResult, target: ModelTarget, label?: string): Promise<ResolvedModel> {
    const model: ResolvedModel = { ...target, ref: result.ref, revision: result.revision, ...(label ? { label } : {}) };
    if (target.credential) {
      const credential = await this.#secretWithRevision(target.credential);
      model.apiKey = credential.value;
      model.credentialRevision = credential.revision;
    }
    return model;
  }

  async #connection(): Promise<AppPortClient> {
    if (this.#client) return this.#client;
    this.#connecting ??= AppPort.discover({
      origin: this.#options.url,
      headers: { authorization: `Bearer ${this.#options.apiKey}` },
      ...(this.#options.fetch ? { fetch: this.#options.fetch } : {}),
      timeoutMs: this.#options.timeoutMs,
    })
      .then((client) => (this.#client = client))
      .finally(() => (this.#connecting = undefined));
    return this.#connecting;
  }

  async #call<T>(name: string, input: unknown): Promise<T> {
    try {
      const client = await this.#connection();
      return await client.call<T>(name, input, { timeoutMs: this.#options.timeoutMs });
    } catch (error) {
      const failure = toError(error);
      if (!AUTHORITATIVE.has(failure.code)) {
        // Drop the connection so the next call rediscovers (the resolver may have moved or restarted).
        const client = this.#client;
        this.#client = undefined;
        await client?.close().catch(() => undefined);
      }
      throw failure;
    }
  }

  #startWatch() {
    if (this.#watching || this.#closed) return;
    this.#watching = true;
    void this.#watchLoop();
  }

  async #watchLoop() {
    let delay = 500;
    while (!this.#closed) {
      try {
        const client = await this.#connection();
        const stream = client.stream<ChangeEvent | { heartbeat: string }>(CAPABILITIES.watch, { prefix: 'ref://' });
        this.#stream = stream;
        // Anything cached before (re)connecting may have missed a change: revalidate it. Again on the first
        // chunk, which the resolver sends once it is subscribed: a change between the two is not lost.
        this.#invalidateAll();
        let subscribed = false;
        for await (const chunk of stream) {
          if (!subscribed) {
            subscribed = true;
            this.#invalidateAll();
            if (delay > 500) this.#options.onWarning?.({ kind: 'reconnected' });
            delay = 500;
          }
          if ('heartbeat' in chunk) continue;
          this.#apply(chunk);
        }
      } catch (error) {
        if (this.#closed) return;
        this.#options.onWarning?.({ kind: 'disconnected', error: toError(error) });
      }
      this.#stream = undefined;
      if (this.#closed) return;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, 30_000);
    }
  }

  #apply(event: ChangeEvent) {
    this.#generations.set(event.ref, (this.#generations.get(event.ref) ?? 0) + 1);
    for (const [key, entry] of this.#cache) {
      if (key !== event.ref && !key.startsWith(`${event.ref}#`)) continue;
      // Revocation also ends every pinned resolution of the name.
      if (event.state === 'revoked') this.#cache.delete(key);
      else entry.invalid = true;
    }
    this.#secrets.delete(event.ref);
    for (const [key, listeners] of this.#listeners) {
      if (key === event.ref || (key.endsWith('/') && event.ref.startsWith(key))) for (const listener of listeners) listener(event);
    }
  }
}

function cacheKey(ref: string, revision?: number): string {
  return revision === undefined ? ref : `${ref}#${revision}`;
}
