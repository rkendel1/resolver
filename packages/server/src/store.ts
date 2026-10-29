/**
 * Durable state on FeltDB.
 *
 * - `resolver_references`: one row per reference, its current binding and revision.
 * - `resolver_revisions`: one row per revision, written once (`requireAbsent`) and never updated.
 * - `resolver_grants`: who may do what on which references.
 * - `resolver_reveals`: every reveal of secret material (who, which version, when), never the material.
 *
 * Every change to a reference is one FeltDB transaction: the new revision row and the updated reference
 * row, conditional on the reference's version. Two writers basing a change on the same revision cannot
 * both commit, and the history can never miss a change that the current state shows.
 */

import { createHash, randomUUID } from 'node:crypto';
import { ConditionalConflictError, type StateFirstDB } from '@feltdb/core';
import type { Action, Binding, HistoryEntry, Json, Kind, ReferenceState, RefName } from '@appport/resolver-core';

export const COLLECTIONS = {
  references: 'resolver_references',
  revisions: 'resolver_revisions',
  grants: 'resolver_grants',
  reveals: 'resolver_reveals',
} as const;

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

/** FeltDB ids allow `[A-Za-z0-9._-]`; references are hashed with their tenant into one. */
export function referenceId(tenantId: string, ref: string): string {
  return createHash('sha256').update(`${tenantId}\u0000${ref}`).digest('hex').slice(0, 40);
}

export type CommitResult = { ok: true } | { ok: false; currentRevision: number };

export class ResolverStore {
  readonly #references;
  readonly #revisions;
  readonly #grants;
  readonly #reveals;

  constructor(readonly db: StateFirstDB) {
    this.#references = db.collection<ReferenceRecord>(COLLECTIONS.references);
    this.#revisions = db.collection<RevisionRecord>(COLLECTIONS.revisions);
    this.#grants = db.collection<GrantRecord>(COLLECTIONS.grants);
    this.#reveals = db.collection<RevealRecord>(COLLECTIONS.reveals);
  }

  async reference(tenantId: string, ref: string): Promise<ReferenceRecord | null> {
    return this.#references.get(referenceId(tenantId, ref));
  }

  async revision(tenantId: string, ref: string, revision: number): Promise<RevisionRecord | null> {
    return this.#revisions.get(`${referenceId(tenantId, ref)}.${revision}`);
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
   * Writes `next` and its revision row atomically, only if the stored reference is still at
   * `expectedRevision` (0: it must not exist yet).
   */
  async commit(next: Omit<ReferenceRecord, 'id' | '__version'>, entry: Omit<RevisionRecord, 'id' | 'referenceId' | 'tenantId' | 'ref' | 'revision'>, expectedRevision: number): Promise<CommitResult> {
    const id = referenceId(next.tenantId, next.ref);
    const current = await this.#references.get(id);
    if ((current?.revision ?? 0) !== expectedRevision) return { ok: false, currentRevision: current?.revision ?? 0 };
    const revision: RevisionRecord = {
      ...entry,
      id: `${id}.${next.revision}`,
      referenceId: id,
      tenantId: next.tenantId,
      ref: next.ref,
      revision: next.revision,
    };
    const record = { ...next, id };
    try {
      await this.db.transaction({
        operations: [
          { collection: COLLECTIONS.revisions, id: revision.id, value: revision as unknown as Record<string, unknown>, requireAbsent: true },
          current
            ? { collection: COLLECTIONS.references, id, value: record as unknown as Record<string, unknown>, ifVersion: current.__version! }
            : { collection: COLLECTIONS.references, id, value: record as unknown as Record<string, unknown>, requireAbsent: true },
        ],
      });
      return { ok: true };
    } catch (error) {
      if (error instanceof ConditionalConflictError || (error as { name?: string }).name === 'ConditionalConflictError') {
        const latest = await this.#references.get(id);
        return { ok: false, currentRevision: latest?.revision ?? 0 };
      }
      throw error;
    }
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

  async removeGrant(tenantId: string, id: string): Promise<boolean> {
    const grant = await this.#grants.get(id);
    if (!grant || grant.tenantId !== tenantId) return false;
    await this.#grants.delete(id);
    return true;
  }

  async recordReveal(reveal: Omit<RevealRecord, 'id'>): Promise<void> {
    const id = randomUUID();
    await this.#reveals.insert({ ...reveal, id }, id, { requireAbsent: true });
  }

  async reveals(tenantId: string, ref: string): Promise<RevealRecord[]> {
    return (await this.#reveals.find({ tenantId, ref: ref as RefName })).sort((a, b) => (a.at < b.at ? -1 : 1));
  }
}
