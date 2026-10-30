/**
 * The resolver: references, revisions, steering, secrets and grants, independent of any transport.
 * The AppPort host (`app.ts`) exposes it; an application can also embed it in-process.
 */

import { EventEmitter } from 'node:events';
import type { AppPortServices, SecretCustody, VerifiedPrincipal } from '@appport/services';
import { formatCredentialRef, MAX_CREDENTIAL_VALUE_LENGTH } from '@appport/services';
import {
  checkBinding,
  isKind,
  isPattern,
  isRef,
  matches,
  parseRef,
  REASONS,
  select,
  ACTIONS,
  type Action,
  type Binding,
  type ChangeEvent,
  type Grant,
  type HistoryEntry,
  type Json,
  type PutInput,
  type ReferenceSummary,
  type RefName,
  type ResolveInput,
  type ResolveResult,
  type RevokeInput,
  type RollbackInput,
  type SecretTarget,
  type WatchInput,
  type WriteResult,
} from '@appport/resolver-core';
import { GrantAuthorizer } from './authorizer.js';
import { referenceId, type ChangeRow, type ReferenceRecord, type ResolverStore, type RevisionRecord } from './store.js';
import { checkSchema, checkTargets, type TargetCheckOptions } from './targets.js';
import { isVersionedCustody, VaultError } from './vault.js';

export type ResolverErrorCode = 'INVALID_INPUT' | 'NOT_FOUND' | 'FORBIDDEN' | 'CONFLICT' | 'INTERNAL_ERROR';

export class ResolverError extends Error {
  constructor(
    readonly code: ResolverErrorCode,
    readonly reason: string,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

const DEFAULT_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 86_400;

export interface ResolverOptions {
  store: ResolverStore;
  authorizer: GrantAuthorizer;
  custody: SecretCustody<string>;
  /** AppPort Services on the same FeltDB: API keys and principals. */
  services: AppPortServices;
  /** Target checks, including the outbound policy agent verification must go through. */
  targets: Omit<TargetCheckOptions, 'lookup'>;
  now?: () => Date;
}

type Principal = VerifiedPrincipal;

export class Resolver {
  readonly #store: ResolverStore;
  readonly #authorizer: GrantAuthorizer;
  readonly #custody: SecretCustody<string>;
  readonly #services: AppPortServices;
  readonly #targets: Omit<TargetCheckOptions, 'lookup'>;
  readonly #now: () => Date;
  readonly #changes = new EventEmitter();
  /**
   * Writes to one reference run one at a time in this process. A writer that loses the race then fails its
   * revision check before it touches custody, so no secret version is stored that no revision points at.
   */
  readonly #writes = new Map<string, Promise<unknown>>();
  /** Set by the runtime: a commit wakes the sync loop, which notifies watchers in sequence order. */
  #onCommitted: ((seq: number) => void) | undefined;

  constructor(options: ResolverOptions) {
    this.#store = options.store;
    this.#authorizer = options.authorizer;
    this.#custody = options.custody;
    this.#services = options.services;
    this.#targets = options.targets;
    this.#now = options.now ?? (() => new Date());
    this.#changes.setMaxListeners(0);
  }

  // ---- reads ------------------------------------------------------------------------------------

  async resolve(principal: Principal, input: ResolveInput): Promise<ResolveResult> {
    const ref = this.#ref(input.ref);
    await this.#require(principal, 'read', ref);
    const record = await this.#existing(principal.tenantId, ref);
    if (record.state === 'revoked') {
      throw new ResolverError('NOT_FOUND', REASONS.revoked, `${ref} was revoked at revision ${record.revision}`, { revision: record.revision });
    }
    let binding = record.binding;
    let revision = record.revision;
    if (input.revision !== undefined) {
      if (!Number.isSafeInteger(input.revision) || input.revision < 1) {
        throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'revision must be a positive integer');
      }
      const pinned = await this.#store.revision(principal.tenantId, ref, input.revision);
      if (!pinned?.binding) throw new ResolverError('NOT_FOUND', REASONS.notFound, `${ref} has no binding at revision ${input.revision}`);
      binding = pinned.binding;
      revision = pinned.revision;
    }
    if (input.key !== undefined && (typeof input.key !== 'string' || input.key.length > 256)) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'key must be a string of at most 256 characters');
    }
    const selection = select(binding, { ref, ...(input.key !== undefined ? { key: input.key } : {}) });
    const result: ResolveResult = {
      ref,
      kind: record.kind,
      revision,
      currentRevision: record.revision,
      strategy: binding.strategy,
      targets: binding.targets,
      selected: { value: selection.value, index: selection.index, ...(selection.label ? { label: selection.label } : {}) },
      ttlSeconds: record.ttlSeconds,
      updatedAt: record.updatedAt,
    };
    if (input.reveal) {
      if (record.kind !== 'secret') throw new ResolverError('INVALID_INPUT', REASONS.kindMismatch, `${ref} is a ${record.kind}, not a secret`);
      result.secret = await this.#reveal(principal, ref, revision, selection.value as SecretTarget);
    }
    return result;
  }

  async history(principal: Principal, input: { ref: string; limit?: number }): Promise<{ entries: HistoryEntry[] }> {
    const ref = this.#ref(input.ref);
    await this.#require(principal, 'read', ref);
    await this.#existing(principal.tenantId, ref);
    const limit = Math.min(Math.max(input.limit ?? 100, 1), 1000);
    const rows = await this.#store.history(principal.tenantId, ref);
    return { entries: rows.slice(-limit).map(toHistory) };
  }

  async list(principal: Principal, input: { prefix?: string }): Promise<{ refs: ReferenceSummary[] }> {
    const prefix = input.prefix ?? 'ref://';
    if (!prefix.startsWith('ref://')) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'prefix must start with ref://');
    const out: ReferenceSummary[] = [];
    for (const record of await this.#store.references(principal.tenantId)) {
      if (!record.ref.startsWith(prefix)) continue;
      if (!(await this.#authorizer.decide(principal, 'read', record.ref)).allowed) continue;
      out.push({ ref: record.ref, kind: record.kind, revision: record.revision, state: record.state, updatedAt: record.updatedAt });
    }
    return { refs: out };
  }

  /**
   * Change notifications for the caller's tenant, filtered by the caller's current grants on every event.
   * Events name what changed; the caller re-resolves with its own authority.
   */
  async *watch(principal: Principal, input: WatchInput, signal: AbortSignal): AsyncGenerator<ChangeEvent> {
    const refs = input.refs?.map((r) => this.#ref(r));
    const prefix = input.prefix;
    if (prefix !== undefined && !prefix.startsWith('ref://')) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'prefix must start with ref://');
    }
    const queue: ChangeEvent[] = [];
    let wake: (() => void) | undefined;
    const listener = (tenantId: string, event: ChangeEvent) => {
      if (tenantId !== principal.tenantId) return;
      if (refs && !refs.includes(event.ref)) return;
      if (prefix && !event.ref.startsWith(prefix)) return;
      queue.push(event);
      wake?.();
    };
    let ended = false;
    const end = () => {
      ended = true;
      wake?.();
    };
    this.#changes.on('change', listener);
    this.#changes.on('resync', end);
    // The watcher's access shrank: end the stream, so its client revalidates everything with its own authority.
    const shrank = (tenantId: string, subject: string) => {
      if (tenantId === principal.tenantId && subject === principal.principalId) end();
    };
    this.#changes.on('authority', shrank);
    const stop = () => wake?.();
    signal.addEventListener('abort', stop);
    try {
      while (!signal.aborted && !ended) {
        const event = queue.shift();
        if (!event) {
          await new Promise<void>((resolve) => (wake = resolve));
          wake = undefined;
          continue;
        }
        if ((await this.#authorizer.decide(principal, 'read', event.ref)).allowed) yield event;
      }
    } finally {
      this.#changes.off('change', listener);
      this.#changes.off('resync', end);
      this.#changes.off('authority', shrank);
      signal.removeEventListener('abort', stop);
    }
  }

  /** Routes this resolver's change notifications through `listener` (the sync loop) instead of announcing them at once. */
  onCommitted(listener: (seq: number) => void): void {
    this.#onCommitted = listener;
  }

  /**
   * A committed revision, from the shared state in sequence order (`sync.ts`): notifies this instance's
   * watchers. The sync loop calls it once per sequence number.
   */
  applyCommitted(row: ChangeRow): void {
    if (row.type === 'authority') {
      this.#changes.emit('authority', row.tenantId, row.subject);
      return;
    }
    const event: ChangeEvent = {
      ref: row.ref,
      kind: row.kind!,
      revision: row.revision,
      state: row.state ?? (row.action === 'revoke' ? 'revoked' : 'active'),
      at: row.at,
    };
    this.#changes.emit('change', row.tenantId, event);
  }

  /**
   * Ends every watch stream on this instance. Clients reconnect and revalidate everything they hold; used
   * when this instance cannot tell exactly which changes it missed.
   */
  resyncWatchers(): void {
    this.#changes.emit('resync');
  }

  // ---- writes -----------------------------------------------------------------------------------

  async put(principal: Principal, input: PutInput): Promise<WriteResult> {
    const ref = this.#ref(input.ref);
    return this.#serial(principal.tenantId, ref, () => this.#put(principal, ref, input));
  }

  async #put(principal: Principal, ref: RefName, input: PutInput): Promise<WriteResult> {
    const decision = await this.#require(principal, 'write', ref);
    const expected = expectedRevision(input.expectedRevision);
    const current = await this.#store.reference(principal.tenantId, ref);
    if (current && current.state === 'revoked') {
      throw new ResolverError('CONFLICT', REASONS.revoked, `${ref} was revoked; revoked names are never reused`);
    }
    if (!current && expected !== 0) throw this.#stale(ref, 0);
    if (current && current.revision !== expected) throw this.#stale(ref, current.revision);
    if (!current && input.kind === undefined) throw new ResolverError('INVALID_INPUT', REASONS.kindMismatch, 'kind is required to create a reference');
    if (input.kind !== undefined && !isKind(input.kind)) throw new ResolverError('INVALID_INPUT', REASONS.kindMismatch, `unknown kind ${String(input.kind)}`);
    const kind = current?.kind ?? input.kind!;
    if (input.kind !== undefined && input.kind !== kind) {
      throw new ResolverError('INVALID_INPUT', REASONS.kindMismatch, `${ref} is a ${kind}; its kind never changes`);
    }
    if (input.schema !== undefined) {
      if (current) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'the schema is fixed when the reference is created');
      if (kind !== 'value') throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'only value references take a schema');
      const ok = checkSchema(input.schema);
      if (!ok.ok) throw new ResolverError('INVALID_INPUT', ok.reason, ok.error);
    }
    const schema = current?.schema ?? (input.schema as Json | undefined) ?? null;
    const ttlSeconds = ttl(input.ttlSeconds, current?.ttlSeconds);

    let binding: Binding;
    if (kind === 'secret') {
      if (input.binding !== undefined) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'a secret takes `secret`, not a binding');
      if (typeof input.secret !== 'string' || input.secret.length === 0 || input.secret.length > MAX_CREDENTIAL_VALUE_LENGTH) {
        throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `secret must be 1 to ${MAX_CREDENTIAL_VALUE_LENGTH} characters`);
      }
      binding = await this.#storeSecret(principal, ref, input.secret, decision);
    } else {
      if (input.secret !== undefined) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `${kind} references take a binding, not a secret`);
      const checked = checkBinding(kind, input.binding);
      if (!checked.ok) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, checked.error);
      binding = checked.value;
      await this.#checkTargets(principal, kind, binding, schema);
    }
    try {
      return await this.#commit(principal, current, { ref, kind, schema, binding, ttlSeconds }, current ? 'update' : 'create', expected, input.reason);
    } catch (error) {
      // A definite conflict means the revision was never committed (another writer won): no revision will
      // ever point at the stored version, so its material is deleted rather than kept. Any other failure
      // (a lost response) may hide a commit that did apply, so the version is left for `verify` to report.
      if (kind === 'secret' && error instanceof ResolverError && error.reason === REASONS.stale) {
        await this.#discard(principal, ref, binding).catch(() => undefined);
      }
      throw error;
    }
  }

  async rollback(principal: Principal, input: RollbackInput): Promise<WriteResult> {
    const ref = this.#ref(input.ref);
    return this.#serial(principal.tenantId, ref, () => this.#rollback(principal, ref, input));
  }

  async #rollback(principal: Principal, ref: RefName, input: RollbackInput): Promise<WriteResult> {
    await this.#require(principal, 'write', ref);
    const expected = expectedRevision(input.expectedRevision);
    const current = await this.#existing(principal.tenantId, ref);
    if (current.state === 'revoked') throw new ResolverError('CONFLICT', REASONS.revoked, `${ref} was revoked`);
    if (current.revision !== expected) throw this.#stale(ref, current.revision);
    const target = await this.#store.revision(principal.tenantId, ref, input.toRevision);
    if (!target?.binding) throw new ResolverError('NOT_FOUND', REASONS.notFound, `${ref} has no binding at revision ${input.toRevision}`);
    // The restored binding must still be valid now (a credential may have been revoked, an agent replaced).
    if (current.kind !== 'secret') await this.#checkTargets(principal, current.kind, target.binding, current.schema);
    return this.#commit(
      principal,
      current,
      { ref, kind: current.kind, schema: current.schema, binding: target.binding, ttlSeconds: current.ttlSeconds },
      'rollback',
      expected,
      input.reason,
      target.revision,
    );
  }

  /** Revocation is total: every resolution of the name fails from now on, and secret material is destroyed. */
  async revoke(principal: Principal, input: RevokeInput): Promise<WriteResult> {
    const ref = this.#ref(input.ref);
    return this.#serial(principal.tenantId, ref, () => this.#revoke(principal, ref, input));
  }

  async #revoke(principal: Principal, ref: RefName, input: RevokeInput): Promise<WriteResult> {
    await this.#require(principal, 'write', ref);
    const expected = expectedRevision(input.expectedRevision);
    const current = await this.#existing(principal.tenantId, ref);
    if (current.state === 'revoked') {
      // The name is already revoked, but destroying the material may have failed then: finish it now.
      if (current.kind === 'secret') await this.#destroy(principal, ref);
      throw new ResolverError('CONFLICT', REASONS.revoked, `${ref} is already revoked`);
    }
    if (current.revision !== expected) throw this.#stale(ref, current.revision);
    const result = await this.#commit(
      principal,
      current,
      { ref, kind: current.kind, schema: current.schema, binding: current.binding, ttlSeconds: current.ttlSeconds },
      'revoke',
      expected,
      input.reason,
      undefined,
      'revoked',
    );
    if (current.kind === 'secret') await this.#destroy(principal, ref);
    return { ...result, dependents: await this.#dependents(principal, ref) };
  }

  /** Active references whose current binding names `ref`. Today the only such edge is a model's credential. */
  async #dependents(principal: Principal, ref: string): Promise<RefName[]> {
    const out: RefName[] = [];
    for (const record of await this.#store.references(principal.tenantId)) {
      if (record.state !== 'active' || record.kind !== 'model') continue;
      if (!record.binding.targets.some((t) => (t.value as { credential?: string }).credential === ref)) continue;
      if ((await this.#authorizer.decide(principal, 'read', record.ref)).allowed) out.push(record.ref);
    }
    return out;
  }

  async #discard(principal: Principal, ref: string, binding: Binding) {
    const custody = this.#custody;
    if (!isVersionedCustody(custody) || !custody.discardVersion) return;
    const version = (binding.targets[0]?.value as SecretTarget | undefined)?.version;
    if (version === undefined) return;
    await custody.discardVersion({ reference: { secretId: referenceId(principal.tenantId, ref), tenantId: principal.tenantId }, version });
  }

  async #destroy(principal: Principal, ref: string) {
    if (!this.#custody.remove) return;
    try {
      await this.#custody.remove({
        reference: { secretId: referenceId(principal.tenantId, ref), tenantId: principal.tenantId, kind: 'resolver-secret' },
        context: { tenantId: principal.tenantId, principalId: principal.principalId, purpose: 'resolver.revoke' },
      });
    } catch {
      throw new ResolverError('INTERNAL_ERROR', REASONS.custody, `${ref} is revoked, but its material could not be destroyed; revoke it again to retry`);
    }
  }

  #serial<T>(tenantId: string, ref: string, task: () => Promise<T>): Promise<T> {
    const key = referenceId(tenantId, ref);
    const previous = this.#writes.get(key) ?? Promise.resolve();
    const next = previous.then(task, task);
    const settled = next.catch(() => undefined);
    this.#writes.set(key, settled);
    void settled.then(() => {
      if (this.#writes.get(key) === settled) this.#writes.delete(key);
    });
    return next;
  }

  // ---- grants and keys (admin) -------------------------------------------------------------------

  async grant(principal: Principal, input: { subject: string; actions: string[]; pattern: string }): Promise<Grant> {
    await this.#require(principal, 'admin', '*');
    if (typeof input.subject !== 'string' || !input.subject) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'subject is required');
    checkGrant(input);
    const record = await this.#store.addGrant({
      tenantId: principal.tenantId,
      subject: input.subject,
      actions: [...new Set(input.actions)] as Action[],
      pattern: input.pattern,
      createdBy: actor(principal),
      createdAt: this.#now().toISOString(),
    });
    const { tenantId: _tenant, ...grant } = record;
    return grant;
  }

  async ungrant(principal: Principal, input: { id: string }): Promise<{ removed: boolean }> {
    await this.#require(principal, 'admin', '*');
    const result = await this.#store.removeGrant(principal.tenantId, input.id);
    if (result.removed) this.#onCommitted?.(result.seq);
    return { removed: result.removed };
  }

  async grants(principal: Principal): Promise<{ grants: Grant[] }> {
    await this.#require(principal, 'admin', '*');
    return { grants: (await this.#store.grants(principal.tenantId)).map(({ tenantId: _t, ...g }) => g) };
  }

  /** Issues an AppPort Services API key. The secret is returned once; grants are added separately. */
  async createKey(principal: Principal, input: { name: string; expiresAt?: string }): Promise<{ id: string; name: string; prefix: string; secret: string; principal: string }> {
    await this.#require(principal, 'admin', '*');
    const created = await this.#services.apiKeys.createApiKey(
      { name: input.name, ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}) } as never,
      principal,
    );
    return { id: created.id, name: created.name, prefix: created.prefix, secret: created.secret, principal: created.id };
  }

  async revokeKey(principal: Principal, input: { id: string }): Promise<{ revoked: boolean }> {
    await this.#require(principal, 'admin', '*');
    const result = await this.#services.apiKeys.revokeApiKey({ id: input.id } as never, principal);
    return { revoked: result !== null };
  }

  async listKeys(principal: Principal): Promise<{ keys: { id: string; name: string; prefix: string; status: string }[] }> {
    await this.#require(principal, 'admin', '*');
    const keys = await this.#services.apiKeys.listApiKeys(principal.tenantId, {} as never);
    return {
      keys: keys.map((k) => ({ id: k.id, name: k.name, prefix: k.keyPrefix, status: k.status })),
    };
  }

  /** Every recorded reveal of a secret: who, which revision and custody version, when. Never the material. */
  async reveals(principal: Principal, input: { ref: string }) {
    await this.#require(principal, 'admin', '*');
    const ref = this.#ref(input.ref);
    return { reveals: (await this.#store.reveals(principal.tenantId, ref)).map(({ tenantId: _t, id: _id, ...r }) => r) };
  }

  // ---- internals --------------------------------------------------------------------------------

  #ref(input: unknown) {
    const parsed = parseRef(input);
    if (!parsed.ok) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, parsed.error);
    return parsed.value.ref;
  }

  async #require(principal: Principal, action: Action, ref: string) {
    const decision = await this.#authorizer.decide(principal, action, ref);
    if (!decision.allowed) {
      throw new ResolverError('FORBIDDEN', REASONS.forbidden, `not allowed to ${action} ${ref}`, { decisionId: decision.decisionId });
    }
    return decision;
  }

  async #existing(tenantId: string, ref: string): Promise<ReferenceRecord> {
    const record = await this.#store.reference(tenantId, ref);
    if (!record) throw new ResolverError('NOT_FOUND', REASONS.notFound, `${ref} does not exist`);
    return record;
  }

  #stale(ref: string, currentRevision: number) {
    return new ResolverError('CONFLICT', REASONS.stale, `${ref} is at revision ${currentRevision}; re-read it and retry`, { currentRevision });
  }

  async #checkTargets(principal: Principal, kind: ReferenceRecord['kind'], binding: Binding, schema: Json | null) {
    const check = await checkTargets(kind, binding, schema, {
      ...this.#targets,
      lookup: async (other) => {
        if (!isRef(other)) return null;
        const found = await this.#store.reference(principal.tenantId, other);
        return found ? { kind: found.kind, state: found.state } : null;
      },
    });
    if (!check.ok) throw new ResolverError('INVALID_INPUT', check.reason, check.error);
  }

  async #storeSecret(principal: Principal, ref: string, value: string, decision: { decisionId: string }): Promise<Binding> {
    const secretId = referenceId(principal.tenantId, ref);
    try {
      const stored = await this.#custody.store({
        reference: { secretId, tenantId: principal.tenantId, kind: 'resolver-secret' },
        value,
        context: { tenantId: principal.tenantId, principalId: principal.principalId, purpose: 'resolver.put', authorizationRef: decision.decisionId },
      });
      const seal = (stored as { seal?: unknown }).seal;
      const target: SecretTarget = { credentialRef: formatCredentialRef(secretId), version: stored.version, ...(typeof seal === 'string' ? { seal } : {}) };
      return { strategy: 'single', targets: [{ value: target as never }] };
    } catch {
      // Nothing the custody raised is passed on: it could echo the material.
      throw new ResolverError('INTERNAL_ERROR', REASONS.custody, 'secret custody did not accept the value');
    }
  }

  async #reveal(principal: Principal, ref: string, revision: number, target: SecretTarget): Promise<string> {
    const decision = await this.#require(principal, 'reveal', ref);
    const input = {
      reference: { secretId: referenceId(principal.tenantId, ref), tenantId: principal.tenantId, kind: 'resolver-secret' },
      context: { tenantId: principal.tenantId, principalId: principal.principalId, purpose: 'resolver.resolve', authorizationRef: decision.decisionId },
    };
    let value: string;
    try {
      if (isVersionedCustody(this.#custody)) {
        value = await this.#custody.withSecretVersion({ ...input, version: target.version }, (s) => s.value);
      } else {
        // A custody without versions can only reveal the version it holds now.
        value = await this.#custody.withSecret(input, (s) => {
          if (s.version !== target.version) throw new VaultError('VERSION_MISSING', 'custody holds a different version');
          return s.value;
        });
      }
    } catch (error) {
      if (error instanceof VaultError && error.code === 'REVOKED') throw new ResolverError('NOT_FOUND', REASONS.revoked, `${ref} material was removed`);
      throw new ResolverError('INTERNAL_ERROR', REASONS.custody, `the secret for ${ref} could not be opened`);
    }
    await this.#store.recordReveal({
      tenantId: principal.tenantId,
      ref: ref as never,
      revision,
      custodyVersion: target.version,
      principalId: principal.principalId,
      decisionId: decision.decisionId,
      at: this.#now().toISOString(),
    });
    return value;
  }

  async #commit(
    principal: Principal,
    current: ReferenceRecord | null,
    next: { ref: ReferenceRecord['ref']; kind: ReferenceRecord['kind']; schema: Json | null; binding: Binding; ttlSeconds: number },
    action: HistoryEntry['action'],
    expected: number,
    reason: string | undefined,
    restoredFrom?: number,
    state: ReferenceRecord['state'] = 'active',
  ): Promise<WriteResult> {
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > 500)) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'reason must be at most 500 characters');
    }
    const at = this.#now().toISOString();
    const revision = expected + 1;
    const record: Omit<ReferenceRecord, 'id' | '__version'> = {
      tenantId: principal.tenantId,
      ref: next.ref,
      kind: next.kind,
      schema: next.schema,
      revision,
      state,
      binding: next.binding,
      ttlSeconds: next.ttlSeconds,
      createdAt: current?.createdAt ?? at,
      updatedAt: at,
      updatedBy: actor(principal),
    };
    const entry: Omit<RevisionRecord, 'id' | 'referenceId' | 'tenantId' | 'ref' | 'revision'> = {
      action,
      binding: action === 'revoke' ? null : next.binding,
      actor: actor(principal),
      at,
      ...(reason ? { reason } : {}),
      ...(restoredFrom !== undefined ? { restoredFrom } : {}),
    };
    const committed = await this.#store.commit(record, entry, expected);
    if (!committed.ok) throw this.#stale(next.ref, committed.currentRevision);
    if (this.#onCommitted) {
      // Watchers hear of it through the sync loop, in sequence order with every other instance's changes:
      // announcing it here first could deliver a reference's revision 10 before revisions 2-9 written elsewhere.
      this.#onCommitted(committed.seq);
    } else {
      this.#changes.emit('change', principal.tenantId, { ref: next.ref, kind: next.kind, revision, state, at } satisfies ChangeEvent);
    }
    return { ref: next.ref, revision };
  }
}

/** Throws unless `actions` on `pattern` is a grant the resolver accepts. */
export function checkGrant(input: { actions: unknown; pattern: unknown }): void {
  const actions = input.actions;
  if (!Array.isArray(actions) || actions.length === 0 || !actions.every((a) => (ACTIONS as readonly string[]).includes(a))) {
    throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `actions must be a non-empty list of ${ACTIONS.join(', ')}`);
  }
  if (typeof input.pattern !== 'string' || !isPattern(input.pattern)) {
    throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'pattern must be *, a ref:// name, or a ref:// prefix ending in /*');
  }
  if (actions.includes('admin') && input.pattern !== '*') {
    throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'admin is granted on * only');
  }
}

function actor(principal: Principal): string {
  return `${principal.principalType}:${principal.principalId}`;
}

function expectedRevision(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'expectedRevision must be 0 (create) or the current revision');
  }
  return value as number;
}

function ttl(input: unknown, current: number | undefined): number {
  if (input === undefined) return current ?? DEFAULT_TTL_SECONDS;
  if (!Number.isSafeInteger(input) || (input as number) < 0 || (input as number) > MAX_TTL_SECONDS) {
    throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `ttlSeconds must be 0 to ${MAX_TTL_SECONDS}`);
  }
  return input as number;
}

function toHistory(row: RevisionRecord): HistoryEntry {
  return {
    revision: row.revision,
    action: row.action,
    ...(row.binding ? { strategy: row.binding.strategy, targets: row.binding.targets } : {}),
    actor: row.actor,
    ...(row.reason ? { reason: row.reason } : {}),
    at: row.at,
    ...(row.restoredFrom !== undefined ? { restoredFrom: row.restoredFrom } : {}),
  };
}

