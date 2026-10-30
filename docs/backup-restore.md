# Backup and restore runbook

Every procedure here is exercised by automated tests, so the claims are test-backed:
- `packages/server/test/backup.test.ts` (in-process, disposable state and vaults);
- the acceptance test in `packages/server/test/multi-process.test.ts`, which runs the CLI against live
  instances, both on local shared state and on a real FeltDB server.

Anything not covered by those tests is marked as such.

## What must be backed up

| Data | Where | In the backup? |
|---|---|---|
| References, revisions (history), grants, reveal records, the change sequence, authority changes | FeltDB: `resolver_references`, `resolver_revisions`, `resolver_grants`, `resolver_reveals`, `resolver_meta`, `resolver_authority` | yes |
| API keys and their audit trail | FeltDB: `api_keys`, `api_key_prefixes`, `api_key_audit_events`, `service_effect_evidence` (AppPort Services) | yes |
| Secret material | the vault directory: sealed versions `v<N>.json` and tombstones `removed.json` | yes, as ciphertext only |
| Management sessions | FeltDB: `resolver_sessions` | **no**: a restore must not bring old sign-ins back |
| Vault keys (`RESOLVER_VAULT_KEY`, `RESOLVER_VAULT_PREVIOUS_KEYS`) and the verifier key (`RESOLVER_VERIFIER_KEY`) | your secret manager | **never**. The manifest lists the key ids it needs, so a restore can refuse early. |

The link between the two halves: every secret revision records `{ credentialRef, version, seal }`, where
`seal` is a random id the vault stored with that exact version. A restore checks every revision against
the vault: the version must be present, open with a configured key, and carry the recorded seal. No
material and nothing derived from it is ever stored in FeltDB.

## Consistency boundary

`resolver backup` takes the backup in this order:

1. It exports the state through FeltDB, one JSON line per row, sorted. If the change sequence moved during
   the export, the export is retried (5 times; otherwise `backup.busy`).
2. It copies the vault, **after** the state. A vault version is written before the revision that points
   at it, and it is never edited. So every version the exported state points at is in the copy, unless a
   revocation destroyed it in between. That revocation is newer than the export, and the restore's check
   reports it.
3. It writes `manifest.json`: the sequence number, a SHA-256 for every file, the row counts, and the
   required vault key ids.

The backup can run against live instances. It needs only read access to FeltDB and the vault. **[test]**
With local state and no `RESOLVER_STATE_SHARED=1`, the running resolver holds an exclusive lock; stop it
or use shared state.

## Taking a backup

```bash
RESOLVER_FELTDB_URL=https://feltdb.internal RESOLVER_VAULT_DIR=/mnt/resolver-vault \
RESOLVER_VAULT_KEY=… RESOLVER_VERIFIER_KEY=… \
  resolver backup /backups/resolver-$(date -u +%Y%m%dT%H%M%SZ)
```

Store the backup directory like any other encrypted-at-rest artifact: it contains ciphertext, API key
verifiers and audit data. Keep the keys separately.

## Restoring

Restore into **empty** state and an **empty** vault directory, with every instance stopped.

```bash
# 1. Check the backup: every file against the manifest, nothing changed.
#    (`restore` does this first anyway.)
# 2. Restore: vault first, then state (the sequence row last), then verify.
RESOLVER_FELTDB_URL=https://feltdb-new.internal RESOLVER_VAULT_DIR=/mnt/resolver-vault-new \
RESOLVER_VAULT_KEY=… RESOLVER_VERIFIER_KEY=… \
  resolver restore /backups/resolver-20261030T013000Z
# exit 0: integrity.ok. exit 1: problems are listed; do not start the resolver.

# 3. Verify again at any time:
resolver verify
# 4. Start the instances with the integrity check on:
RESOLVER_VERIFY_ON_START=1 resolver serve …
```

What `restore` refuses, changing nothing **[test]**:
- a missing manifest;
- a missing or edited state file;
- a missing, edited or unlisted vault file;
- a vault key id it needs that is not configured (`restore.key-missing`);
- a target that is not empty (`restore.target-not-empty`).

What it reports after restoring (exit 1) **[test]**:
- a revision whose version is **missing**;
- a version that is a **mismatch** (another backup's vault: same names, different material);
- a version that is **undecryptable** (wrong key);
- material that survived a revocation.

It also gives warnings: orphan versions, versions sealed under an old key, and revisions written before
seals existed (their presence and key are checked; their identity cannot be).

After a restore:
- the same API keys work, provided the same verifier key is configured;
- revision pins reveal what they did before;
- revoked references stay revoked;
- the change sequence continues from where it was. **[test]**

## Recovery scenarios

| Situation | What to do | Tested |
|---|---|---|
| **Lost vault, state intact** | `resolver verify` lists every secret revision as `missing`. Reveals fail with `resolver.custody-unavailable`; nothing is served silently, and readiness is 503 with `RESOLVER_VERIFY_ON_START=1`. Non-secret references keep working. Restore the vault from the latest backup into an empty directory and run `verify`. With no backup, set each secret again (`resolver set <ref> --secret-stdin`); this creates a new revision, and old pins to lost versions keep failing. | **[test]** |
| **Lost database, vault intact** | The vault alone cannot be mapped back to references: the files are named by a hash of tenant and reference. Restore the latest backup (state and vault together) into an empty state and vault. `verify` against a fresh state reports the surviving vault's versions as orphans. | **[test]** |
| **Both lost** | Restore the latest backup. Changes after it are lost: re-apply them from your change records, because the history in the backup ends at the manifest's `sequence`. | **[test]** (restore); re-applying is operational |
| **Incomplete or tampered backup** | `restore` refuses it with the file that failed. Use an earlier backup. | **[test]** |
| **Vault and state from different backups** | `restore` reports `missing` or `mismatch` per revision. Restore both halves from one backup. | **[test]** |
| **Vault key lost** | Material sealed under that key is unrecoverable by design. Every revision sealed with it reports `undecryptable`, or `restore.key-missing` before anything is written. Set the affected secrets again. | **[test]** (detection) |
| **Verifier key lost** | Every existing API key stops authenticating. Mint an operator key with `resolver init` on the restored state and issue new application keys. | **[code]** only, not tested |

## Not covered

- **The FeltDB server's own backups.** If you also back up FeltDB at the storage level, that copy contains
  the resolver's rows too. A resolver restore from it is still checked by `resolver verify`.
- **Point-in-time recovery between backups.**
- **Moving state written before this release (revision ids with `.`) to a FeltDB server.** The server
  refuses `.` in ids, and backup and restore copy ids unchanged. Such state can be restored into local
  state only; moving it to a FeltDB server needs an id-rewriting migration that does not exist yet.
