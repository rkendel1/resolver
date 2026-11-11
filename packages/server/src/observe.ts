/**
 * Records what Resolver observes consumers resolve, and what consumers report using, as aggregates: one row per
 * (tenant, principal, consumer registration, reference, revision, outcome[, label]). Never one row per request.
 *
 * - The first observation of a key in this instance is written at once; later ones within `windowMs` are counted
 *   in memory and added to the row when the window passes, on a timer, or at close. Counts are lower bounds: a
 *   process that dies holds back at most one window's increments, never a first sighting already written.
 * - Recording never blocks or fails what is being observed: writes run in the background; a failure is logged and
 *   counted (`failures`), and the resolution is served regardless. Observability never reduces availability.
 * - Nothing recorded carries secret material, selected target values, steering keys or headers.
 */
import type { RefName } from '@appport/resolver-core';
import type { Logger } from './log.js';
import { observationId, type ResolutionRecord, type ResolverStore, type UsageRecord } from './store.js';

export type ResolutionOutcome = ResolutionRecord['outcome'];

interface Pending {
  kind: 'resolutions' | 'usage';
  key: Omit<ResolutionRecord, 'firstAt' | 'lastAt' | 'count' | '__version'> | Omit<UsageRecord, 'firstAt' | 'lastAt' | 'count' | '__version'>;
  count: number;
  lastAt: string;
  writtenAt: number;
}

export interface ObservationStatus {
  /** Background writes that failed (the observations they carried are lost; resolutions were still served). */
  failures: number;
  /** Increments held in memory, waiting for their window. */
  pending: number;
}

export class ObservationRecorder {
  readonly #store: ResolverStore;
  readonly #log: Logger;
  readonly #windowMs: number;
  readonly #now: () => Date;
  readonly #held = new Map<string, Pending>();
  readonly #inflight = new Set<Promise<void>>();
  readonly #timer: NodeJS.Timeout | undefined;
  #failures = 0;

  constructor(options: { store: ResolverStore; log: Logger; windowMs?: number; now?: () => Date }) {
    this.#store = options.store;
    this.#log = options.log;
    this.#windowMs = options.windowMs ?? 60_000;
    this.#now = options.now ?? (() => new Date());
    if (this.#windowMs > 0) {
      this.#timer = setInterval(() => this.#flushDue(), Math.max(1000, Math.floor(this.#windowMs / 2)));
      this.#timer.unref();
    }
  }

  resolution(entry: { tenantId: string; principalId: string; consumer?: string; ref: RefName; revision: number; outcome: ResolutionOutcome }): void {
    const id = observationId(['resolution', entry.tenantId, entry.principalId, entry.consumer, entry.ref, entry.revision, entry.outcome]);
    this.#observe('resolutions', { id, ...entry }, id);
  }

  usage(entry: { tenantId: string; principalId: string; consumer?: string; ref: RefName; revision: number; label?: string; outcome: UsageRecord['outcome'] }): void {
    const id = observationId(['usage', entry.tenantId, entry.principalId, entry.consumer, entry.ref, entry.revision, entry.label, entry.outcome]);
    this.#observe('usage', { id, ...entry }, id);
  }

  /** Writes every held increment now (tests, shutdown, before a read that must include them). */
  async flush(): Promise<void> {
    for (const [id, pending] of this.#held) {
      if (pending.count > 0) this.#write(id, pending);
    }
    await Promise.allSettled([...this.#inflight]);
  }

  status(): ObservationStatus {
    return { failures: this.#failures, pending: [...this.#held.values()].reduce((sum, p) => sum + p.count, 0) };
  }

  async close(): Promise<void> {
    if (this.#timer) clearInterval(this.#timer);
    await this.flush();
  }

  #observe(kind: Pending['kind'], key: Pending['key'], id: string): void {
    const at = this.#now().toISOString();
    const held = this.#held.get(id);
    if (!held) {
      const pending: Pending = { kind, key, count: 1, lastAt: at, writtenAt: 0 };
      this.#held.set(id, pending);
      this.#write(id, pending);
      return;
    }
    held.count += 1;
    held.lastAt = at;
    if (this.#windowMs === 0 || Date.now() - held.writtenAt >= this.#windowMs) this.#write(id, held);
  }

  #flushDue(): void {
    const now = Date.now();
    for (const [id, pending] of this.#held) {
      if (pending.count > 0 && now - pending.writtenAt >= this.#windowMs) this.#write(id, pending);
    }
  }

  #write(_id: string, pending: Pending): void {
    const count = pending.count;
    const at = pending.lastAt;
    pending.count = 0;
    pending.writtenAt = Date.now();
    const work = this.#store
      .addObservation(pending.kind, pending.key as never, at, count)
      .catch((error: unknown) => {
        this.#failures += 1;
        this.#log.warn('observation', { operation: `observation.${pending.kind}`, reason: 'observation.write-failed', error: (error as Error).message });
      })
      .finally(() => this.#inflight.delete(work));
    this.#inflight.add(work);
  }
}
