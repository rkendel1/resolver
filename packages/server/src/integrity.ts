/**
 * Checks that the state and the secret custody agree: every revision of an active secret points at a
 * version the custody holds, that opens with a configured key and carries the seal the revision recorded;
 * every revoked secret's material is gone. Reads no material out of the process and returns none.
 *
 * Run after a restore (`backup.ts`), after a vault key rotation, and at startup when asked to.
 */

import type { SecretCustody } from '@appport/services';
import type { SecretTarget } from '@appport/resolver-core';
import { referenceId, type ResolverStore } from './store.js';
import { isVersionedCustody, type Vault, type VersionCheck } from './vault.js';

export interface IntegrityProblem {
  tenantId: string;
  ref: string;
  revision?: number;
  version?: number;
  /** What is wrong: a `VersionCheck` other than ok, or `material-survived-revocation`, or `custody-error`. */
  problem: Exclude<VersionCheck, 'ok'> | 'material-survived-revocation' | 'custody-error';
  /** Whether the reference's current revision is affected (resolution fails now), or only an older pin. */
  current: boolean;
}

export interface IntegrityWarning {
  tenantId: string;
  ref?: string;
  warning: 'orphan-version' | 'dangling-credential' | 'old-vault-key' | 'unverified-seal';
  version?: number;
  detail?: string;
}

export interface IntegrityReport {
  ok: boolean;
  checked: { references: number; secretVersions: number };
  problems: IntegrityProblem[];
  warnings: IntegrityWarning[];
}

export async function verifyIntegrity(store: ResolverStore, custody: SecretCustody<string>, vault?: Vault): Promise<IntegrityReport> {
  const references = await store.allReferences();
  const revisions = await store.allRevisions();
  const byReference = new Map<string, typeof revisions>();
  for (const row of revisions) byReference.set(row.referenceId, [...(byReference.get(row.referenceId) ?? []), row]);
  const report: IntegrityReport = { ok: true, checked: { references: references.length, secretVersions: 0 }, problems: [], warnings: [] };
  const referenced = new Set<string>();
  const active = new Map(references.map((r) => [`${r.tenantId}\u0000${r.ref}`, r]));

  for (const record of references) {
    if (record.kind === 'model' && record.state === 'active') {
      for (const target of record.binding.targets) {
        const credential = (target.value as { credential?: string }).credential;
        const found = credential ? active.get(`${record.tenantId}\u0000${credential}`) : undefined;
        if (credential && (!found || found.state !== 'active' || found.kind !== 'secret')) {
          report.warnings.push({ tenantId: record.tenantId, ref: record.ref, warning: 'dangling-credential', detail: credential });
        }
      }
    }
    if (record.kind !== 'secret') continue;
    const secretId = referenceId(record.tenantId, record.ref);
    const reference = { secretId, tenantId: record.tenantId };
    const rows = (byReference.get(record.id) ?? []).filter((r) => r.binding);
    for (const row of rows) {
      const target = row.binding!.targets[0]?.value as SecretTarget | undefined;
      if (!target) continue;
      referenced.add(`${secretId}#${target.version}`);
      report.checked.secretVersions += 1;
      const current = row.revision === record.revision || (record.state === 'revoked' && row.revision === record.revision - 1);
      let check: VersionCheck | 'custody-error';
      try {
        if (isVersionedCustody(custody) && custody.verifyVersion) {
          check = await custody.verifyVersion({ reference, version: target.version, ...(target.seal ? { seal: target.seal } : {}) });
        } else {
          // A custody without version checks: only its status for the current version can be compared.
          const status = await custody.status!({ reference, context: { tenantId: record.tenantId, principalId: 'integrity', purpose: 'resolver.verify' } } as never);
          check = status.state === 'revoked' ? 'removed' : status.state !== 'set' ? 'missing' : !current || status.version === target.version ? 'ok' : 'missing';
        }
      } catch {
        check = 'custody-error';
      }
      if (record.state === 'revoked') {
        if (check === 'ok' || check === 'mismatch' || check === 'undecryptable') {
          report.problems.push({ tenantId: record.tenantId, ref: record.ref, revision: row.revision, version: target.version, problem: 'material-survived-revocation', current: true });
        }
        continue;
      }
      if (check !== 'ok') report.problems.push({ tenantId: record.tenantId, ref: record.ref, revision: row.revision, version: target.version, problem: check, current });
      else if (!target.seal) report.warnings.push({ tenantId: record.tenantId, ref: record.ref, warning: 'unverified-seal', version: target.version, detail: 'written before seals were recorded: presence and key checked, identity not' });
    }
  }

  if (vault) {
    for (const entry of await vault.list()) {
      for (const version of entry.versions) {
        if (!referenced.has(`${entry.secretId}#${version.version}`)) {
          report.warnings.push({ tenantId: entry.tenantId, warning: 'orphan-version', version: version.version, detail: `secret ${entry.secretId.slice(0, 12)}…: stored but no revision points at it` });
        }
        if (version.kid !== vault.keys.current) {
          report.warnings.push({ tenantId: entry.tenantId, warning: 'old-vault-key', version: version.version, detail: `sealed with ${version.kid ?? 'a format-1 key'}; run vault rotate` });
        }
      }
    }
  }
  report.ok = report.problems.length === 0;
  return report;
}
