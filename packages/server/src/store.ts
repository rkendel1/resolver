/**
 * Durable state on FeltDB.
 *
 * - `resolver_references`: one row per reference, its current binding and revision.
 * - `resolver_revisions`: one row per revision, written once (`requireAbsent`) and never updated.
 * - `resolver_grants`: who may do what on which references.
 * - `resolver_reveals`: every reveal of secret material (who, which version, when), never the material.
 *
 * - `resolver_meta`: the change sequence (one row).
 * - `resolver_authority`: authority changes that must reach connected clients (a removed grant), one row
 *   per sequence number, written in the same transaction as the change.
 * - `resolver_sessions`: management UI sessions, so a browser can be served by any resolver instance.
 *
 * Every change to a reference is one FeltDB transaction: the new revision row, the updated reference row
 * and the next value of the change sequence, conditional on the reference's version and the sequence's.
 * Two writers basing a change on the same revision cannot both commit, the history can never miss a
 * change that the current state shows, and every committed revision has exactly one sequence number:
 * no number is skipped and no number is used twice. Resolver instances sharing the state follow the
 * sequence to learn of each other's changes (`sync.ts`); it is derived from the same transactions, not a
 * second record of them.
 */

import { createHash, randomUUID } from 'node:crypto';
import { ConditionalConflictError, type StateFirstDB } from '@feltdb/core';
import type { Action, Binding, HistoryEntry, Json, Kind, ReferenceState, RefName } from '@appport/resolver-core';

export const COLLECTIONS = {
  references: 'resolver_references',
  revisions: 'resolver_revisions',
  grants: 'resolver_grants',
  reveals: 'resolver_reveals',
  meta: 'resolver_meta',
  authority: 'resolver_authority',
  sessions: 'resolver_sessions',
} as const;

const SEQUENCE_ID = 'sequence';
const COMMIT_ATTEMPTS = 16;

export interface ReferenceRecord {
  id: string;
  tenantId: string;
  ref: RefName;
  kind: Kind;
  /** `value` references: the JSON Schema fixed at creation. */
  schema: Json | null;
  revision: number;
  state: ReferenceState;
  binding: Binding;
  ttlSeconds: number;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
  __version?: number;
}

export interface RevisionRecord {
  id: string;
  referenceId: string;
  tenantId: string;
  ref: RefName;
  revision: number;
  action: HistoryEntry['action'];
  binding: Binding | null;
  actor: string;
  reason?: string;
  at: string;
  restoredFrom?: number;
  /** Position in the change sequence. Absent on revisions written before the sequence existed. */
  seq?: number;
  kind?: Kind;
  state?: ReferenceState;
}

/** A change of authority, numbered in the same sequence as revisions. */
export interface AuthorityRecord {
  id: string;
  type: 'authority';
  seq: number;
  tenantId: string;
  /** The principal whose access shrank: its watch streams are ended so its clients revalidate. */
  subject: string;
  change: 'grant-removed';
  at: string;
}

/** What the change sequence numbers: a reference revision or an authority change. */
export type ChangeRow = (RevisionRecord & { type?: undefined }) | AuthorityRecord;

export interface SessionRecord {
  /** SHA-256 of the session token: the token itself is never stored. */
  id: string;
  tenantId: string;
  /** The API key the operator signed in with. Every request re-checks that it is still live. */
  keyId: string;
  created: number;
  lastUsed: number;
}

export interface GrantRecord {
  id: string;
  tenantId: string;
  subject: string;
  actions: Action[];
  pattern: string;
  createdBy: string;
  createdAt: string;
}

export interface RevealRecord {
  id: string;
  tenantId: string;
  ref: RefName;
  revision: number;
  custodyVersion: number;
  principalId: string;
  decisionId: string;
  at: string;
}

/** FeltDB server ids allow `[A-Za-z0-9_-]` (128 at most); references are hashed with their tenant into one. */
export function referenceId(tenantId: string, ref: string): string {
  return createHash('sha256').update(`${tenantId}\u0000${ref}`).digest('hex').slice(0, 40);
}

/** A revision row's id. The reference id is hex, so `-` cannot be ambiguous. */
export function revisionId(referenceIdValue: string, revision: number): string {
  return `${referenceIdValue}-${revision}`;
}

export type CommitResult = { ok: true; seq: number } | { ok: false; currentRevision: number };

export class ResolverStore {
  readonly #references;
  readonly #revisions;
  readonly #grants;
  readonly #reveals;
  readonly #meta;
  readonly #sessions;

  constructor(readonly db: StateFirstDB) {
    this.#meta = db.collection<{ id: string; seq: number; __version?: number }>(COLLECTIONS.meta);
    this.#sessions = db.collection<SessionRecord>(COLLECTIONS.sessions);
    this.#references = db.collection<ReferenceRecord>(COLLECTIONS.references);
    this.#revisions = db.collection<RevisionRecord>(COLLECTIONS.revisions);
    this.#grants = db.collection<GrantRecord>(COLLECTIONS.grants);
    this.#reveals = db.collection<RevealRecord>(COLLECTIONS.reveals);
  }

  async reference(tenantId: string, ref: string): Promise<ReferenceRecord | null> {
    return this.#references.get(referenceId(tenantId, ref));
  }

  async revision(tenantId: string, ref: string, revision: number): Promise<RevisionRecord | null> {
    const id = referenceId(tenantId, ref);
    // `-` since the FeltDB server accepts only [A-Za-z0-9_-] in ids; `.` in revisions written before that.
    return (await this.#revisions.get(revisionId(id, revision))) ?? (await this.#revisions.get(`${id}.${revision}`));
  }

  async history(tenantId: string, ref: string): Promise<RevisionRecord[]> {
    const rows = await this.#revisions.find({ referenceId: referenceId(tenantId, ref) });
    return rows.filter((r) => r.tenantId === tenantId).sort((a, b) => a.revision - b.revision);
  }

  async references(tenantId: string): Promise<ReferenceRecord[]> {
    const rows = await this.#references.find({ tenantId });
    return rows.sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  }

  /**
   * Writes `next`, its revision row and the next sequence number atomically, only if the stored reference
   * is still at `expectedRevision` (0: it must not exist yet). A conflict on the sequence alone (another
   * reference changed at the same moment) is retried; a conflict on the reference is a stale write.
   */
  async commit(next: Omit<ReferenceRecord, 'id' | '__version'>, entry: Omit<RevisionRecord, 'id' | 'referenceId' | 'tenantId' | 'ref' | 'revision' | 'seq' | 'kind' | 'state'>, expectedRevision: number): Promise<CommitResult> {
    const id = referenceId(next.tenantId, next.ref);
    for (let attempt = 0; attempt < COMMIT_ATTEMPTS; attempt++) {
      const current = await this.#references.get(id);
      if ((current?.revision ?? 0) !== expectedRevision) return { ok: false, currentRevision: current?.revision ?? 0 };
      const sequence = await this.#meta.get(SEQUENCE_ID);
      const seq = (sequence?.seq ?? 0) + 1;
      const revision: RevisionRecord = {
        ...entry,
        id: revisionId(id, next.revision),
        referenceId: id,
        tenantId: next.tenantId,
        ref: next.ref,
        revision: next.revision,
        seq,
        kind: next.kind,
        state: next.state,
      };
      const record = { ...next, id };
      const value = (v: unknown) => v as Record<string, unknown>;
      try {
        await this.db.transaction({
          operations: [
            { collection: COLLECTIONS.revisions, id: revision.id, value: value(revision), requireAbsent: true },
            current
              ? { collection: COLLECTIONS.references, id, value: value(record), ifVersion: current.__version! }
              : { collection: COLLECTIONS.references, id, value: value(record), requireAbsent: true },
            sequence
              ? { collection: COLLECTIONS.meta, id: SEQUENCE_ID, value: { id: SEQUENCE_ID, seq }, ifVersion: sequence.__version! }
              : { collection: COLLECTIONS.meta, id: SEQUENCE_ID, value: { id: SEQUENCE_ID, seq }, requireAbsent: true },
          ],
        });
        return { ok: true, seq };
      } catch (error) {
        if (!(error instanceof ConditionalConflictError || (error as { name?: string }).name === 'ConditionalConflictError')) throw error;
        const latest = await this.#references.get(id);
        if ((latest?.revision ?? 0) !== expectedRevision) return { ok: false, currentRevision: latest?.revision ?? 0 };
        // Only the sequence moved: another reference committed first. Try again with the new number.
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 5 * (attempt + 1)));
      }
    }
    throw new Error('the change sequence stayed contended; the write was not committed');
  }

  /** The last committed sequence number (0 before the first change). */
  async sequence(): Promise<number> {
    return (await this.#meta.get(SEQUENCE_ID))?.seq ?? 0;
  }

  /** Changes (revisions and authority changes) numbered above `after`, in sequence order, at most `limit`. */
  async changesAfter(after: number, limit: number): Promise<ChangeRow[]> {
    const page = <T>(collection: string) =>
      this.db.query<T>({ collection, where: [{ field: 'seq', gt: after }], orderBy: [{ field: 'seq', direction: 'asc' }], limit });
    const [revisions, authority] = await Promise.all([page<RevisionRecord>(COLLECTIONS.revisions), page<AuthorityRecord>(COLLECTIONS.authority)]);
    const rows: ChangeRow[] = [...revisions.records, ...authority.records].filter((r) => typeof r.seq === 'number') as ChangeRow[];
    // Each query returned the lowest `limit` of its kind; merged, only the lowest `limit` overall are complete.
    return rows.sort((a, b) => a.seq! - b.seq!).slice(0, limit);
  }

  /** Every reference in every tenant (integrity checks and backups only). */
  async allReferences(): Promise<ReferenceRecord[]> {
    return this.#references.find({});
  }

  /** Every revision of every reference in every tenant (integrity checks only). */
  async allRevisions(): Promise<RevisionRecord[]> {
    return this.#revisions.find({});
  }

  // ---- management sessions -------------------------------------------------------------------------

  async session(id: string): Promise<SessionRecord | null> {
    return this.#sessions.get(id);
  }

  async saveSession(session: SessionRecord): Promise<void> {
    await this.#sessions.insert(session, session.id);
  }

  async dropSession(id: string): Promise<void> {
    await this.#sessions.delete(id).catch(() => undefined);
  }

  /** Deletes sessions last used before `before` (at most `limit` per call). */
  async dropSessionsIdleSince(before: number, limit = 100): Promise<void> {
    const page = await this.db.query<SessionRecord>({ collection: COLLECTIONS.sessions, where: [{ field: 'lastUsed', lt: before }], orderBy: [{ field: 'lastUsed', direction: 'asc' }], limit });
    for (const session of page.records) await this.dropSession(session.id);
  }

  async grants(tenantId: string): Promise<GrantRecord[]> {
    return (await this.#grants.find({ tenantId })).sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1));
  }

  async grantsFor(tenantId: string, subject: string): Promise<GrantRecord[]> {
    return (await this.#grants.find({ tenantId, subject })).filter((g) => g.tenantId === tenantId && g.subject === subject);
  }

  async addGrant(grant: Omit<GrantRecord, 'id'>): Promise<GrantRecord> {
    const record = { ...grant, id: randomUUID() };
    await this.#grants.insert(record, record.id, { requireAbsent: true });
    return record;
  }

  /**
   * Removes a grant and records the authority change in the change sequence, in one transaction, so every
   * instance ends the subject's watch streams and its clients revalidate what they hold.
   */
  async removeGrant(tenantId: string, id: string): Promise<{ removed: false } | { removed: true; seq: number }> {
    for (let attempt = 0; attempt < COMMIT_ATTEMPTS; attempt++) {
      const grant = (await this.#grants.get(id)) as (GrantRecord & { __version?: number }) | null;
      if (!grant || grant.tenantId !== tenantId) return { removed: false };
      const sequence = await this.#meta.get(SEQUENCE_ID);
      const seq = (sequence?.seq ?? 0) + 1;
      const change: AuthorityRecord = { id: `authority-${seq}`, type: 'authority', seq, tenantId, subject: grant.subject, change: 'grant-removed', at: new Date().toISOString() };
      try {
        await this.db.transaction({
          operations: [
            { collection: COLLECTIONS.grants, id, ifVersion: grant.__version! },
            { collection: COLLECTIONS.authority, id: change.id, value: change as unknown as Record<string, unknown>, requireAbsent: true },
            sequence
              ? { collection: COLLECTIONS.meta, id: SEQUENCE_ID, value: { id: SEQUENCE_ID, seq }, ifVersion: sequence.__version! }
              : { collection: COLLECTIONS.meta, id: SEQUENCE_ID, value: { id: SEQUENCE_ID, seq }, requireAbsent: true },
          ],
        });
        return { removed: true, seq };
      } catch (error) {
        if (!(error instanceof ConditionalConflictError || (error as { name?: string }).name === 'ConditionalConflictError')) throw error;
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 5 * (attempt + 1)));
      }
    }
    throw new Error('the change sequence stayed contended; the grant was not removed');
  }

  async recordReveal(reveal: Omit<RevealRecord, 'id'>): Promise<void> {
    const id = randomUUID();
    await this.#reveals.insert({ ...reveal, id }, id, { requireAbsent: true });
  }

  async reveals(tenantId: string, ref: string): Promise<RevealRecord[]> {
    return (await this.#reveals.find({ tenantId, ref: ref as RefName })).sort((a, b) => (a.at < b.at ? -1 : 1));
  }
}
