/**
 * The resolver: references, revisions, steering, secrets and grants, independent of any transport.
 * The AppPort host (`app.ts`) exposes it; an application can also embed it in-process.
 */

import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { AppPortServices, VerifiedPrincipal } from '@appport/services';
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
  GOVERNED_OPERATIONS,
  type GovernedOperation,
  type GovernedRequest,
  type GovernanceEvent,
  type MutationPolicy,
  type RevisionGovernance,
  type SigningKey,
} from '@appport/resolver-core';
import { GrantAuthorizer, isOperator } from './authorizer.js';
import { authorizationId, changeDigest, ed25519PublicKey, GovernanceError, policyFor, verifyAuthorization } from './governance.js';
import { referenceId, signingKeyId, type ChangeRow, type CommitGovernance, type ConsumerRecord, type ReferenceRecord, type ResolverStore, type RevisionRecord } from './store.js';
import { checkSchema, checkTargets, type TargetCheckOptions } from './targets.js';
import type { ObservationRecorder, ResolutionOutcome } from './observe.js';
import { requireVersionedCustody, VaultError, type VersionedCustody } from './vault.js';

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
  /** Must keep versions (`withSecretVersion`); refused otherwise. */
  custody: VersionedCustody;
  /** AppPort Services on the same FeltDB: API keys and principals. */
  services: AppPortServices;
  /** Target checks, including the outbound policy agent verification must go through. */
  targets: Omit<TargetCheckOptions, 'lookup'>;
  now?: () => Date;
  /** Records observed resolutions and asserted usage. Absent: nothing is recorded (embedding without it). */
  observations?: ObservationRecorder;
  /** A registration is live while its watch stream was seen within this many ms. Default 120 000. */
  consumerGraceMs?: number;
}

type Principal = VerifiedPrincipal;

/** How often an open watch stream refreshes its registration's `lastSeenAt`. */
const CONSUMER_TOUCH_MS = 30_000;

export class Resolver {
  readonly #store: ResolverStore;
  readonly #authorizer: GrantAuthorizer;
  readonly #custody: VersionedCustody;
  readonly #services: AppPortServices;
  readonly #targets: Omit<TargetCheckOptions, 'lookup'>;
  readonly #now: () => Date;
  readonly #observations: ObservationRecorder | undefined;
  readonly #consumerGraceMs: number;
  /** Registrations confirmed to belong to a principal, so a resolution does not read the registration each time. */
  readonly #knownConsumers = new Map<string, number>();
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
    requireVersionedCustody(options.custody);
    this.#custody = options.custody;
    this.#services = options.services;
    this.#targets = options.targets;
    this.#now = options.now ?? (() => new Date());
    this.#observations = options.observations;
    this.#consumerGraceMs = options.consumerGraceMs ?? 120_000;
    this.#changes.setMaxListeners(0);
  }

  // ---- reads ------------------------------------------------------------------------------------

  /**
   * Resolves, and records the resolution Resolver observed: the revision served (or the refusal), by which principal
   * and registration. Recording happens after the answer is decided and never changes or delays it.
   */
  async resolve(principal: Principal, input: ResolveInput): Promise<ResolveResult> {
    if (!this.#observations) return this.#resolve(principal, input);
    const consumer = await this.#ownConsumer(principal, input?.consumer);
    try {
      const result = await this.#resolve(principal, input);
      this.#observe(principal, consumer, result.ref, result.revision, 'ok');
      return result;
    } catch (error) {
      if (error instanceof ResolverError && isRef(input?.ref)) {
        const outcome: ResolutionOutcome | null =
          error.reason === REASONS.revoked ? 'revoked' : error.reason === REASONS.notFound ? 'not_found' : error.reason === REASONS.forbidden ? 'forbidden' : null;
        if (outcome) this.#observe(principal, consumer, input.ref as RefName, outcome === 'revoked' ? Number(error.details['revision'] ?? 0) : 0, outcome);
      }
      throw error;
    }
  }

  #observe(principal: Principal, consumer: string | undefined, ref: RefName, revision: number, outcome: ResolutionOutcome) {
    try {
      this.#observations!.resolution({ tenantId: principal.tenantId, principalId: principal.principalId, ...(consumer ? { consumer } : {}), ref, revision, outcome });
    } catch {
      // Never let recording affect the resolution.
    }
  }

  /** The registration id, if it is the caller's own live registration; otherwise nothing (never trusted as given). */
  async #ownConsumer(principal: Principal, id: unknown): Promise<string | undefined> {
    if (typeof id !== 'string' || !id || id.length > 64) return undefined;
    const cacheKey = `${principal.tenantId}\u0000${principal.principalId}\u0000${id}`;
    const seen = this.#knownConsumers.get(cacheKey);
    if (seen !== undefined && Date.now() - seen < 60_000) return id;
    const row = await this.#store.consumer(id).catch(() => null);
    if (!row || row.tenantId !== principal.tenantId || row.principalId !== principal.principalId || row.deregisteredAt) {
      this.#knownConsumers.delete(cacheKey);
      return undefined;
    }
    this.#knownConsumers.set(cacheKey, Date.now());
    return id;
  }

  async #resolve(principal: Principal, input: ResolveInput): Promise<ResolveResult> {
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
    // An open stream is the registration's liveness: no second heartbeat protocol.
    const consumer = await this.#ownConsumer(principal, input.consumer);
    const touch = consumer ? () => void this.#touchConsumer(consumer).catch(() => undefined) : undefined;
    touch?.();
    const toucher = touch ? setInterval(touch, CONSUMER_TOUCH_MS) : undefined;
    toucher?.unref();
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
      if (toucher) clearInterval(toucher);
      touch?.();
    }
  }

  // ---- consumers, usage and adoption --------------------------------------------------------------

  async #touchConsumer(id: string): Promise<void> {
    for (let attempt = 0; attempt < 4; attempt++) {
      const row = await this.#store.consumer(id);
      if (!row || row.deregisteredAt) return;
      try {
        await this.#store.saveConsumer({ ...row, lastSeenAt: this.#now().toISOString() }, false);
        return;
      } catch {
        // A concurrent touch or update won; read again.
      }
    }
  }

  #consumerState(row: ConsumerRecord): 'live' | 'stale' | 'deregistered' {
    if (row.deregisteredAt) return 'deregistered';
    return this.#now().getTime() - Date.parse(row.lastSeenAt) <= this.#consumerGraceMs ? 'live' : 'stale';
  }

  async #dependencies(principal: Principal, input: unknown): Promise<ConsumerRecord['dependencies']> {
    if (input === undefined) return [];
    if (!Array.isArray(input) || input.length > 500) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'dependencies must be a list of at most 500 { ref, contract? }');
    const out: ConsumerRecord['dependencies'] = [];
    const unreadable: string[] = [];
    for (const item of input) {
      const ref = (item as { ref?: unknown })?.ref;
      const contract = (item as { contract?: unknown })?.contract;
      if (!isRef(ref)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'each dependency names a ref://');
      if (contract !== undefined && (typeof contract !== 'string' || contract.length > 200)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'a dependency contract is a string of at most 200 characters');
      // A consumer cannot declare dependencies it may not read: no probing of names through declarations.
      if (!(await this.#authorizer.decide(principal, 'read', ref)).allowed) unreadable.push(ref);
      out.push({ ref: ref as RefName, ...(contract ? { contract } : {}) });
    }
    if (unreadable.length) throw new ResolverError('FORBIDDEN', REASONS.forbidden, `the caller may not read ${unreadable.length} declared dependenc${unreadable.length === 1 ? 'y' : 'ies'}`);
    return out;
  }

  /** Registers a running consumer (asserted application, environment and instance; verified principal). */
  async register(principal: Principal, input: { application: string; environment: string; instance?: string; dependencies?: Array<{ ref: string; contract?: string }> }) {
    const text = (v: unknown, name: string) => {
      if (typeof v !== 'string' || !/^[A-Za-z0-9._:@/-]{1,128}$/.test(v)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `${name} must be 1 to 128 of A-Z a-z 0-9 . _ : @ / -`);
      return v;
    };
    const at = this.#now().toISOString();
    const row: ConsumerRecord = {
      id: `con_${randomUUID().replaceAll('-', '').slice(0, 24)}`,
      tenantId: principal.tenantId,
      principalId: principal.principalId,
      application: text(input.application, 'application'),
      environment: text(input.environment, 'environment'),
      instance: text(input.instance ?? 'default', 'instance'),
      dependencies: await this.#dependencies(principal, input.dependencies),
      registeredAt: at,
      lastSeenAt: at,
    };
    await this.#store.saveConsumer(row, true);
    return { registration: row.id, graceSeconds: Math.round(this.#consumerGraceMs / 1000) };
  }

  async #own(principal: Principal, id: unknown): Promise<ConsumerRecord> {
    const row = typeof id === 'string' ? await this.#store.consumer(id) : null;
    if (!row || row.tenantId !== principal.tenantId || row.principalId !== principal.principalId) throw new ResolverError('NOT_FOUND', REASONS.notFound, 'no such registration of this caller');
    return row;
  }

  async updateRegistration(principal: Principal, input: { registration: string; dependencies?: Array<{ ref: string; contract?: string }> }) {
    const row = await this.#own(principal, input.registration);
    if (row.deregisteredAt) throw new ResolverError('CONFLICT', REASONS.invalidBinding, 'the registration was deregistered');
    await this.#store.saveConsumer({ ...row, dependencies: await this.#dependencies(principal, input.dependencies), lastSeenAt: this.#now().toISOString() }, false);
    return { registration: row.id };
  }

  async deregister(principal: Principal, input: { registration: string }) {
    const row = await this.#own(principal, input.registration);
    if (!row.deregisteredAt) await this.#store.saveConsumer({ ...row, deregisteredAt: this.#now().toISOString() }, false);
    this.#knownConsumers.clear();
    return { registration: row.id, deregistered: true };
  }

  /** A consumer reports using a resolved target: asserted, kept apart from what Resolver observed. */
  async report(principal: Principal, input: { ref: string; revision: number; outcome: 'succeeded' | 'failed'; label?: string; consumer?: string }) {
    const ref = this.#ref(input.ref);
    await this.#require(principal, 'read', ref);
    const record = await this.#existing(principal.tenantId, ref);
    if (!Number.isSafeInteger(input.revision) || input.revision < 1 || input.revision > record.revision) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `revision must be 1 to ${record.revision}`);
    if (input.outcome !== 'succeeded' && input.outcome !== 'failed') throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'outcome is succeeded or failed');
    if (input.label !== undefined && (typeof input.label !== 'string' || input.label.length > 64)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'label is at most 64 characters');
    const consumer = await this.#ownConsumer(principal, input.consumer);
    this.#observations?.usage({ tenantId: principal.tenantId, principalId: principal.principalId, ...(consumer ? { consumer } : {}), ref, revision: input.revision, ...(input.label ? { label: input.label } : {}), outcome: input.outcome });
    return { recorded: Boolean(this.#observations) };
  }

  /**
   * The five facts per consumer of a reference, never merged: declared (registration), registered (liveness),
   * resolved (observed by Resolver), used (reported by the consumer), verified (no verifier in this milestone).
   * Refused resolutions (forbidden, not found) and unregistered principals are shown to admins only.
   */
  async consumers(principal: Principal, input: { ref: string }) {
    const ref = this.#ref(input.ref);
    await this.#require(principal, 'read', ref);
    await this.#observations?.flush();
    const admin = (await this.#authorizer.decide(principal, 'admin', '*')).allowed;
    const [registrations, resolutions, usage] = await Promise.all([
      this.#store.consumers(principal.tenantId),
      this.#store.resolutionsFor(principal.tenantId, ref),
      this.#store.usageFor(principal.tenantId, ref),
    ]);
    const byKey = new Map<string, ConsumerFacts>();
    const facts = (principalId: string, consumer?: string): ConsumerFacts => {
      const key = `${principalId}\u0000${consumer ?? ''}`;
      let entry = byKey.get(key);
      if (!entry) {
        const reg = consumer ? registrations.find((r) => r.id === consumer) : undefined;
        entry = {
          principal: principalId,
          ...(reg ? { registration: { id: reg.id, application: reg.application, environment: reg.environment, instance: reg.instance, state: this.#consumerState(reg), lastSeenAt: reg.lastSeenAt } } : {}),
          declared: reg ? reg.dependencies.some((d) => d.ref === ref) : false,
          resolved: null,
          refused: [],
          used: null,
          verified: null,
        };
        byKey.set(key, entry);
      }
      return entry;
    };
    for (const reg of registrations) if (reg.dependencies.some((d) => d.ref === ref)) facts(reg.principalId, reg.id);
    for (const row of resolutions) {
      const entry = facts(row.principalId, row.consumer);
      if (row.outcome === 'ok') {
        if (!entry.resolved || row.revision > entry.resolved.latestRevision) entry.resolved = { latestRevision: row.revision, lastAt: row.lastAt, count: row.count };
        else if (row.revision === entry.resolved.latestRevision) entry.resolved = { ...entry.resolved, count: entry.resolved.count + row.count, lastAt: row.lastAt > entry.resolved.lastAt ? row.lastAt : entry.resolved.lastAt };
      } else entry.refused.push({ outcome: row.outcome, revision: row.revision, lastAt: row.lastAt, count: row.count });
    }
    for (const row of usage) {
      const entry = facts(row.principalId, row.consumer);
      if (!entry.used || row.revision > entry.used.latestRevision || (row.revision === entry.used.latestRevision && row.lastAt > entry.used.lastAt)) {
        entry.used = { latestRevision: row.revision, outcome: row.outcome, ...(row.label ? { label: row.label } : {}), lastAt: row.lastAt };
      }
    }
    const visible = [...byKey.values()].filter((f) => admin || f.declared || f.resolved || f.used).map((f) => (admin ? f : { ...f, refused: [] }));
    return { ref, consumers: visible, notes: CONSUMER_NOTES };
  }

  /**
   * Adoption of one revision, stage by stage: authorized, committed, available, fetched (observed), adopted
   * (reported), functionally verified (not produced in this milestone). Notification delivery is not a stage.
   */
  async adoption(principal: Principal, input: { ref: string; revision?: number }) {
    const ref = this.#ref(input.ref);
    await this.#require(principal, 'read', ref);
    const record = await this.#existing(principal.tenantId, ref);
    const revision = input.revision ?? record.revision;
    const row = await this.#store.revision(principal.tenantId, ref, revision);
    if (!row) throw new ResolverError('NOT_FOUND', REASONS.notFound, `${ref} has no revision ${revision}`);
    const next = revision < record.revision ? await this.#store.revision(principal.tenantId, ref, revision + 1) : null;
    const consumers = await this.consumers(principal, { ref });
    const authorization = row.governance?.mode === 'authorized' ? (await this.#store.authorizationsFor(principal.tenantId, ref)).find((a) => a.revision === revision) : undefined;
    const live = consumers.consumers.filter((c) => c.registration?.state === 'live');
    const fetched = consumers.consumers.filter((c) => c.resolved && c.resolved.latestRevision >= revision);
    const adopted = consumers.consumers.filter((c) => c.used && c.used.latestRevision >= revision && c.used.outcome === 'succeeded');
    return {
      ref,
      revision,
      currentRevision: record.revision,
      authorized: row.governance
        ? { ...row.governance, ...(authorization ? { consumedAt: authorization.consumedAt, consumedBy: authorization.consumedBy } : {}) }
        : { mode: 'ungoverned' as const },
      committed: { at: row.at, actor: row.actor, action: row.action, ...(row.seq !== undefined ? { seq: row.seq } : {}) },
      available: {
        from: row.at,
        until: next?.at ?? (record.state === 'revoked' && revision === record.revision ? record.updatedAt : null),
        current: revision === record.revision && record.state === 'active',
      },
      fetched: { basis: 'observed' as const, count: fetched.length, consumers: fetched },
      notYetFetched: { basis: 'derived' as const, count: live.filter((c) => !fetched.includes(c)).length, consumers: live.filter((c) => !fetched.includes(c)) },
      adopted: { basis: 'asserted' as const, count: adopted.length, consumers: adopted },
      functionallyVerified: null,
      notes: [
        'fetched: Resolver served this revision (or a later one) to the consumer; at the TTL granularity of the consumer\'s cache.',
        'adopted: the consumer reported using this revision (or a later one) successfully; asserted, not observed.',
        'functionallyVerified: no verifier exists in this milestone.',
        'A change notification reaching a consumer is not adoption: only a resolution shows a fetch, only a report shows use.',
      ],
    };
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
      ...(row.governance ? { governance: row.governance.mode } : {}),
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
    let governed: Governed;
    if (kind === 'secret') {
      if (input.binding !== undefined) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'a secret takes `secret`, not a binding');
      if (typeof input.secret !== 'string' || input.secret.length === 0 || input.secret.length > MAX_CREDENTIAL_VALUE_LENGTH) {
        throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `secret must be 1 to ${MAX_CREDENTIAL_VALUE_LENGTH} characters`);
      }
      // Decided before the material reaches custody: a refused write stores nothing. The authorization is bound
      // to the kind and ttl, never to the material.
      governed = await this.#governance(principal, ref, 'put-secret', expected, { kind: 'secret', ttlSeconds: input.ttlSeconds }, input);
      binding = await this.#storeSecret(principal, ref, input.secret, decision);
    } else {
      if (input.secret !== undefined) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `${kind} references take a binding, not a secret`);
      const checked = checkBinding(kind, input.binding);
      if (!checked.ok) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, checked.error);
      binding = checked.value;
      // Decided before the target checks: an unauthorized writer cannot make the resolver contact an agent origin.
      governed = await this.#governance(principal, ref, 'put', expected, { kind, schema: input.schema as Json | undefined, binding: input.binding, ttlSeconds: input.ttlSeconds }, input);
      await this.#checkTargets(principal, kind, binding, schema);
    }
    try {
      return await this.#commit(principal, current, { ref, kind, schema, binding, ttlSeconds }, current ? 'update' : 'create', expected, input.reason, undefined, 'active', governed);
    } catch (error) {
      // A definite conflict means the revision was never committed (another writer won, or the authorization was
      // already consumed): no revision will ever point at the stored version, so its material is deleted rather than
      // kept. Any other failure (a lost response) may hide a commit that did apply, so the version is left for `verify`.
      if (kind === 'secret' && error instanceof ResolverError && (error.reason === REASONS.stale || error.reason === REASONS.authorizationConsumed)) {
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
    const governed = await this.#governance(principal, ref, 'rollback', expected, { toRevision: input.toRevision }, input);
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
      'active',
      governed,
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
    const governed = await this.#governance(principal, ref, 'revoke', expected, {}, input);
    const result = await this.#commit(
      principal,
      current,
      { ref, kind: current.kind, schema: current.schema, binding: current.binding, ttlSeconds: current.ttlSeconds },
      'revoke',
      expected,
      input.reason,
      undefined,
      'revoked',
      governed,
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
    if (!custody.discardVersion) return;
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

  // ---- mutation governance ------------------------------------------------------------------------

  /**
   * Decides whether a write may proceed under the reference's mutation policy, and what it commits as evidence.
   * Called by every governed write after its revision check and before any side effect.
   *
   * - A break-glass write: the host operator only, with a reason, where a policy governs. Never silent.
   * - No authorization: allowed only where no policy governs this reference and operation (today's behaviour).
   * - An authorization, whenever presented: verified locally and consumed with the revision, governed or not.
   */
  async #governance(principal: Principal, ref: RefName, op: GovernedOperation, expected: number, request: GovernedRequest, input: { authorization?: unknown; breakGlass?: unknown }): Promise<Governed> {
    const policy = policyFor(await this.#store.policies(principal.tenantId), ref, op);
    if (input.breakGlass !== undefined) {
      if (!isOperator(principal)) throw new ResolverError('FORBIDDEN', REASONS.breakGlassRefused, 'break-glass is reserved to the host operator');
      const reason = (input.breakGlass as { reason?: unknown } | null)?.reason;
      if (typeof reason !== 'string' || !reason.trim() || reason.length > 500) {
        throw new ResolverError('INVALID_INPUT', REASONS.breakGlassRefused, 'break-glass needs a reason of 1 to 500 characters');
      }
      if (input.authorization !== undefined) throw new ResolverError('INVALID_INPUT', REASONS.breakGlassRefused, 'give a change authorization or break-glass, not both');
      if (!policy) throw new ResolverError('INVALID_INPUT', REASONS.breakGlassRefused, `no mutation policy governs ${op} on ${ref}: break-glass is not needed and is not recorded`);
      const by = actor(principal);
      return {
        governance: { mode: 'break-glass', actor: by, reason },
        commit: { event: { id: `gov_${randomUUID()}`, tenantId: principal.tenantId, type: 'break-glass', actor: by, reason, at: this.#now().toISOString(), ref, operation: op, policyId: policy.id } },
      };
    }
    if (input.authorization === undefined) {
      if (policy) {
        throw new ResolverError('FORBIDDEN', REASONS.authorizationRequired, `${ref} is governed by mutation policy ${policy.id} (${policy.pattern}): ${op} needs a change authorization from ${policy.issuers.join(', ')}`, { policy: policy.id });
      }
      return { commit: {} };
    }
    let digest: string;
    try {
      digest = changeDigest(op, request);
    } catch (error) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, (error as Error).message);
    }
    const keys = new Map((await this.#store.signingKeys(principal.tenantId)).map((k) => [k.kid, k as SigningKey]));
    let verified;
    try {
      verified = verifyAuthorization(input.authorization, { tenantId: principal.tenantId, ref, op, expectedRevision: expected, digest, policy, now: this.#now() }, (kid) => keys.get(kid) ?? null);
    } catch (error) {
      if (error instanceof GovernanceError) throw new ResolverError('FORBIDDEN', error.reason, error.message);
      throw error;
    }
    const { claims, kid } = verified;
    // Evidence copied from the token is bounded; it is the issuer's record, not checked by the resolver.
    const decision = typeof claims.decision === 'string' ? claims.decision.slice(0, 200) : undefined;
    const approvers = Array.isArray(claims.approvers) ? claims.approvers.filter((a): a is string => typeof a === 'string').slice(0, 20).map((a) => a.slice(0, 200)) : undefined;
    return {
      governance: { mode: 'authorized', issuer: claims.iss, kid, jti: claims.jti, ...(decision ? { decision } : {}), ...(approvers?.length ? { approvers } : {}) },
      commit: {
        authorization: { id: authorizationId(principal.tenantId, claims.iss, claims.jti), tenantId: principal.tenantId, issuer: claims.iss, kid, jti: claims.jti, ref, operation: op, ...(decision ? { decision } : {}), consumedBy: actor(principal) },
      },
    };
  }

  /** Policies, signing keys and the governance trail: readable with `admin`; changed by the host operator only. */
  async policies(principal: Principal): Promise<{ policies: MutationPolicy[] }> {
    await this.#require(principal, 'admin', '*');
    return { policies: (await this.#store.policies(principal.tenantId)).map(({ tenantId: _t, __version: _v, ...p }) => p) };
  }

  async signingKeys(principal: Principal): Promise<{ keys: SigningKey[] }> {
    await this.#require(principal, 'admin', '*');
    return { keys: (await this.#store.signingKeys(principal.tenantId)).map(({ tenantId: _t, id: _i, __version: _v, ...k }) => k) };
  }

  async governanceEvents(principal: Principal, input: { limit?: number } = {}): Promise<{ events: GovernanceEvent[] }> {
    await this.#require(principal, 'admin', '*');
    const limit = Math.min(Math.max(input.limit ?? 200, 1), 1000);
    return { events: (await this.#store.governanceEvents(principal.tenantId, limit)).map(({ tenantId: _t, id: _i, ...e }) => e) };
  }

  #operatorOnly(principal: Principal, what: string, reason: unknown): string {
    if (!isOperator(principal)) throw new ResolverError('FORBIDDEN', REASONS.forbidden, `${what} is changed by the host operator only (resolver CLI on the state host)`);
    if (typeof reason !== 'string' || !reason.trim() || reason.length > 500) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `${what} changes need a reason of 1 to 500 characters`);
    return reason;
  }

  #event(principal: Principal, type: GovernanceEvent['type'], reason: string, extra: Partial<GovernanceEvent>) {
    return { id: `gov_${randomUUID()}`, tenantId: principal.tenantId, type, actor: actor(principal), reason, at: this.#now().toISOString(), ...extra };
  }

  async setPolicy(principal: Principal, input: { id?: string; pattern: string; operations: string[]; issuers: string[]; maxValiditySeconds?: number; reason: string }): Promise<MutationPolicy> {
    const reason = this.#operatorOnly(principal, 'mutation policy', input.reason);
    if (typeof input.pattern !== 'string' || !isPattern(input.pattern)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'pattern must be *, a ref:// name, or a ref:// prefix ending in /*');
    const operations = input.operations;
    if (!Array.isArray(operations) || !operations.length || !operations.every((o) => (GOVERNED_OPERATIONS as readonly string[]).includes(o))) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `operations must be a non-empty list of ${GOVERNED_OPERATIONS.join(', ')}`);
    }
    if (!Array.isArray(input.issuers) || !input.issuers.length || !input.issuers.every((i) => typeof i === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(i))) {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'issuers must be a non-empty list of issuer ids');
    }
    const maxValiditySeconds = input.maxValiditySeconds ?? 3600;
    if (!Number.isSafeInteger(maxValiditySeconds) || maxValiditySeconds < 60 || maxValiditySeconds > 86_400) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'maxValiditySeconds must be 60 to 86400');
    const id = input.id ?? `pol_${randomUUID().replaceAll('-', '').slice(0, 16)}`;
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'a policy id is letters, digits, _ and -');
    const existing = await this.#store.policy(id);
    if (existing && existing.tenantId !== principal.tenantId) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, `policy id ${id} is taken`);
    const policy: MutationPolicy = { id, pattern: input.pattern, operations: [...new Set(operations)] as GovernedOperation[], issuers: [...new Set(input.issuers)], maxValiditySeconds, createdBy: actor(principal), createdAt: this.#now().toISOString(), reason };
    await this.#store.governanceChange(
      { collection: 'policies', id, value: { ...policy, tenantId: principal.tenantId }, ...(existing ? { ifVersion: existing.__version! } : {}) },
      this.#event(principal, 'policy.set', reason, { policyId: id, pattern: policy.pattern }),
    );
    return policy;
  }

  async removePolicy(principal: Principal, input: { id: string; reason: string }): Promise<{ removed: boolean }> {
    const reason = this.#operatorOnly(principal, 'mutation policy', input.reason);
    const existing = await this.#store.policy(input.id);
    if (!existing || existing.tenantId !== principal.tenantId) return { removed: false };
    await this.#store.governanceChange({ collection: 'policies', id: input.id, value: null, ifVersion: existing.__version! }, this.#event(principal, 'policy.removed', reason, { policyId: input.id, pattern: existing.pattern }));
    return { removed: true };
  }

  async addSigningKey(principal: Principal, input: { kid: string; issuer: string; publicKey: string; reason: string }): Promise<SigningKey> {
    const reason = this.#operatorOnly(principal, 'a signing key', input.reason);
    if (typeof input.kid !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(input.kid)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'kid must be 1 to 128 of A-Z a-z 0-9 . _ : -');
    if (typeof input.issuer !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(input.issuer)) throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'issuer must be 1 to 128 of A-Z a-z 0-9 . _ : -');
    try {
      ed25519PublicKey(input.publicKey);
    } catch {
      throw new ResolverError('INVALID_INPUT', REASONS.invalidBinding, 'publicKey must be a raw Ed25519 public key (32 bytes, base64url)');
    }
    if (await this.#store.signingKey(principal.tenantId, input.kid)) throw new ResolverError('CONFLICT', REASONS.invalidBinding, `signing key ${input.kid} exists; key ids are never reused`);
    const key: SigningKey = { kid: input.kid, issuer: input.issuer, publicKey: input.publicKey, state: 'active', createdAt: this.#now().toISOString(), createdBy: actor(principal), reason };
    await this.#store.governanceChange(
      { collection: 'signingKeys', id: signingKeyId(principal.tenantId, input.kid), value: { ...key, id: signingKeyId(principal.tenantId, input.kid), tenantId: principal.tenantId } },
      this.#event(principal, 'signing-key.added', reason, { kid: key.kid, issuer: key.issuer }),
    );
    return key;
  }

  /** Rotation: a retired key still verifies authorizations issued before now, so approvals in flight survive. */
  async retireSigningKey(principal: Principal, input: { kid: string; reason: string }): Promise<SigningKey> {
    return this.#keyState(principal, input, 'retired');
  }

  /** Compromise: a revoked key verifies nothing from now on, including authorizations issued before. */
  async revokeSigningKey(principal: Principal, input: { kid: string; reason: string }): Promise<SigningKey> {
    return this.#keyState(principal, input, 'revoked');
  }

  async #keyState(principal: Principal, input: { kid: string; reason: string }, state: 'retired' | 'revoked'): Promise<SigningKey> {
    const reason = this.#operatorOnly(principal, 'a signing key', input.reason);
    const existing = await this.#store.signingKey(principal.tenantId, input.kid);
    if (!existing) throw new ResolverError('NOT_FOUND', REASONS.notFound, `no signing key ${input.kid}`);
    if (existing.state === 'revoked' || existing.state === state) throw new ResolverError('CONFLICT', REASONS.invalidBinding, `signing key ${input.kid} is already ${existing.state}`);
    const at = this.#now().toISOString();
    const { __version, ...rest } = existing;
    const next = { ...rest, state, reason, ...(state === 'retired' ? { retiredAt: at } : { revokedAt: at }) };
    await this.#store.governanceChange({ collection: 'signingKeys', id: existing.id, value: next, ifVersion: __version! }, this.#event(principal, state === 'retired' ? 'signing-key.retired' : 'signing-key.revoked', reason, { kid: existing.kid, issuer: existing.issuer }));
    const { id: _i, tenantId: _t, ...key } = next;
    return key as SigningKey;
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
      value = await this.#custody.withSecretVersion({ ...input, version: target.version }, (s) => s.value);
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
    governed: Governed = { commit: {} },
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
      ...(governed.governance ? { governance: governed.governance } : {}),
    };
    const committed = await this.#store.commit(record, entry, expected, governed.commit);
    if (!committed.ok) {
      if ('consumed' in committed) throw new ResolverError('FORBIDDEN', REASONS.authorizationConsumed, `the authorization for ${next.ref} was already used`);
      throw this.#stale(next.ref, committed.currentRevision);
    }
    if (this.#onCommitted) {
      // Watchers hear of it through the sync loop, in sequence order with every other instance's changes:
      // announcing it here first could deliver a reference's revision 10 before revisions 2-9 written elsewhere.
      this.#onCommitted(committed.seq);
    } else {
      this.#changes.emit('change', principal.tenantId, { ref: next.ref, kind: next.kind, revision, state, at, ...(governed.governance ? { governance: governed.governance.mode } : {}) } satisfies ChangeEvent);
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
    ...(row.governance ? { governance: row.governance } : {}),
  };
}


/** What a governed write commits besides its revision: the revision's evidence and the rows written with it. */
interface Governed {
  governance?: RevisionGovernance;
  commit: CommitGovernance;
}

/** One consumer of a reference, its five facts kept apart. */
interface ConsumerFacts {
  principal: string;
  registration?: { id: string; application: string; environment: string; instance: string; state: 'live' | 'stale' | 'deregistered'; lastSeenAt: string };
  /** The registration declares this reference (asserted by the consumer). */
  declared: boolean;
  /** Observed by Resolver: the latest revision served to this consumer. */
  resolved: { latestRevision: number; lastAt: string; count: number } | null;
  /** Observed refusals (admins only). */
  refused: Array<{ outcome: string; revision: number; lastAt: string; count: number }>;
  /** Reported by the consumer (asserted). */
  used: { latestRevision: number; outcome: 'succeeded' | 'failed'; label?: string; lastAt: string } | null;
  /** No verifier in this milestone. */
  verified: null;
}

const CONSUMER_NOTES = [
  'declared and used are asserted by the consumer; resolved is observed by Resolver; registration state is from the watch stream.',
  'resolved counts are lower bounds (coalesced per instance); a consumer serving its cache is not seen again until its TTL or a change.',
  'Weighted steering runs in the client: Resolver observes the revision served, not the target selected; a usage report carries the label.',
];
