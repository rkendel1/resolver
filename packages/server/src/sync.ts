/**
 * Keeps one resolver instance's watchers in step with changes committed by any instance sharing the state.
 *
 * Every committed revision carries the next number of one change sequence, written in the same FeltDB
 * transaction (`store.ts`). Each instance holds `applied`: the highest sequence number up to which it has
 * notified its own watchers of every change. A pass:
 *
 * 1. asks FeltDB whether anything changed (`db.revision()` where the runtime offers revision validation;
 *    otherwise it reads the sequence row, which is just as correct and one read more);
 * 2. reads the revisions numbered above `applied`, in order, and notifies watchers of each one;
 * 3. advances `applied` one number at a time, only after that number was handled.
 *
 * Changes this instance commits go the same way (a commit starts a pass at once), so every watcher on
 * every instance hears of every change in one order: the sequence's.
 *
 * So `applied` never moves past a change that was not processed. A failed pass changes nothing and the
 * next pass starts from the same place. Seeing a revision twice is harmless: numbers at or below `applied`
 * are skipped.
 *
 * A missing number (which a correct FeltDB never produces, because the number and the revision commit
 * together) is waited for; if it stays missing, every watch stream on the instance is ended so clients
 * revalidate everything they hold, and the instance moves past it. Nothing is skipped silently.
 *
 * Server-side reads never depend on this: every request reads FeltDB directly. This loop only decides
 * how soon connected clients hear about a change; their TTLs bound it when it is late.
 */

import type { StateFirstDB } from '@feltdb/core';
import type { Logger } from './log.js';
import type { Resolver } from './resolver.js';
import type { ResolverStore } from './store.js';

export interface SyncOptions {
  /** How often to look for changes. Default 1000 ms. */
  intervalMs?: number;
  /** Revisions read per query. Default 256. */
  batch?: number;
  /** How long a missing sequence number is waited for before watchers are resynchronized. Default 10 s. */
  gapTimeoutMs?: number;
  /** After this long without a successful pass, the instance reports itself not ready. Default 10 s. */
  staleAfterMs?: number;
}

export interface SyncStatus {
  /** Every change up to this sequence number has been processed. */
  applied: number;
  /** The latest sequence number seen in the state. */
  latest: number;
  /** The initial pass completed. */
  started: boolean;
  /** Milliseconds since the last successful pass (null before the first). */
  sinceSuccessMs: number | null;
  lastError: string | null;
  consecutiveFailures: number;
  resyncs: number;
}

export class RevisionSync {
  readonly #store: ResolverStore;
  readonly #db: StateFirstDB;
  readonly #resolver: Resolver;
  readonly #log: Logger;
  readonly #interval: number;
  readonly #batch: number;
  readonly #gapTimeout: number;
  readonly #staleAfter: number;
  #applied = 0;
  #latest = 0;
  #started = false;
  #lastSuccess: number | null = null;
  #lastError: string | null = null;
  #failures = 0;
  #resyncs = 0;
  #gapSince: number | null = null;
  #revisionValidation: boolean | undefined;
  #seenRevision: number | undefined;
  #timer: NodeJS.Timeout | undefined;
  #running: Promise<void> | undefined;
  #stopped = false;

  constructor(store: ResolverStore, db: StateFirstDB, resolver: Resolver, log: Logger, options: SyncOptions = {}) {
    this.#store = store;
    this.#db = db;
    this.#resolver = resolver;
    this.#log = log;
    this.#interval = options.intervalMs ?? 1000;
    this.#batch = options.batch ?? 256;
    this.#gapTimeout = options.gapTimeoutMs ?? 10_000;
    this.#staleAfter = options.staleAfterMs ?? 10_000;
  }

  /**
   * Starts from the current end of the sequence: clients that connect to this instance revalidate what
   * they hold on connect, so nothing before now needs replaying. If the state does not answer, the instance
   * keeps trying in the background and reports itself not ready until it does.
   */
  async start(): Promise<void> {
    const attempt = async (): Promise<void> => {
      if (this.#stopped) return;
      try {
        this.#applied = this.#latest = await this.#store.sequence();
        this.#started = true;
        this.#succeeded();
        this.#log.info('sync.started', { applied: this.#applied });
        this.#schedule();
      } catch (error) {
        this.#failed(error);
        this.#timer = setTimeout(() => void attempt(), this.#interval);
        this.#timer.unref?.();
      }
    };
    await attempt();
  }

  /**
   * One pass now (a local commit, tests). A call while a pass runs makes another pass follow it, so a
   * change committed after the running pass read the sequence is not left for the next interval.
   */
  pass(): Promise<void> {
    if (this.#running) {
      this.#again = true;
      return this.#running;
    }
    this.#running = (async () => {
      do {
        this.#again = false;
        await this.#pass();
      } while (this.#again && !this.#stopped);
    })().finally(() => (this.#running = undefined));
    return this.#running;
  }

  #again = false;

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer) clearTimeout(this.#timer);
    await this.#running?.catch(() => undefined);
  }

  get status(): SyncStatus {
    return {
      applied: this.#applied,
      latest: this.#latest,
      started: this.#started,
      sinceSuccessMs: this.#lastSuccess === null ? null : Date.now() - this.#lastSuccess,
      lastError: this.#lastError,
      consecutiveFailures: this.#failures,
      resyncs: this.#resyncs,
    };
  }

  /** Started, and the last successful pass is recent enough that watchers are not silently behind. */
  get healthy(): boolean {
    return this.#started && this.#lastSuccess !== null && Date.now() - this.#lastSuccess <= this.#staleAfter;
  }

  #schedule() {
    if (this.#stopped) return;
    this.#timer = setTimeout(() => {
      void this.pass().finally(() => this.#schedule());
    }, this.#interval);
    this.#timer.unref?.();
  }

  async #changed(): Promise<boolean> {
    if (this.#revisionValidation === undefined) {
      this.#revisionValidation = (await this.#db.freshness()).validation === 'revision';
    }
    if (!this.#revisionValidation) return true;
    const revision = (await this.#db.revision()).value;
    if (revision === this.#seenRevision && this.#applied >= this.#latest && this.#gapSince === null) return false;
    // Remembered only once the pass completes without leaving work behind (see #pass).
    this.#pendingRevision = revision;
    return true;
  }

  #pendingRevision: number | undefined;

  async #pass(): Promise<void> {
    if (!this.#started || this.#stopped) return;
    try {
      if (!(await this.#changed())) {
        this.#succeeded();
        return;
      }
      this.#latest = await this.#store.sequence();
      while (this.#applied < this.#latest) {
        const rows = await this.#store.changesAfter(this.#applied, this.#batch);
        let progressed = false;
        for (const row of rows) {
          const seq = row.seq!;
          if (seq <= this.#applied) continue; // seen already
          if (seq !== this.#applied + 1) break; // a gap: handled below
          this.#resolver.applyCommitted(row);
          this.#applied = seq;
          this.#gapSince = null;
          progressed = true;
        }
        if (this.#applied >= this.#latest) break;
        if (!progressed) {
          this.#gap();
          break;
        }
      }
      if (this.#applied >= this.#latest) this.#seenRevision = this.#pendingRevision;
      this.#succeeded();
    } catch (error) {
      // Nothing advanced past what was processed; the next pass resumes from `applied`.
      this.#failed(error);
    }
  }

  /** The next number is not readable yet. Wait for it; if it never appears, resynchronize watchers. */
  #gap() {
    const now = Date.now();
    this.#gapSince ??= now;
    if (now - this.#gapSince < this.#gapTimeout) return;
    const missing = this.#applied + 1;
    this.#resolver.resyncWatchers();
    this.#applied = missing;
    this.#gapSince = null;
    this.#resyncs += 1;
    this.#log.warn('sync.gap-resynced', { reason: 'sync.gap', missing, applied: this.#applied });
  }

  #succeeded() {
    if (this.#failures > 0) this.#log.info('sync.recovered', { applied: this.#applied, latest: this.#latest, failures: this.#failures });
    this.#lastSuccess = Date.now();
    this.#lastError = null;
    this.#failures = 0;
  }

  #failed(error: unknown) {
    this.#failures += 1;
    this.#lastError = (error as { code?: string }).code ?? (error as Error).name ?? 'Error';
    // Logged once per outage and then every 30 failures, never with the error's message (it may echo data).
    if (this.#failures === 1 || this.#failures % 30 === 0) {
      this.#log.warn('sync.failed', { reason: 'sync.state-unavailable', error: this.#lastError, applied: this.#applied, failures: this.#failures });
    }
  }
}
