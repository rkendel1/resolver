# Vault key rotation

## Three operations that are not the same

| Operation | What changes | Revision pins | Command |
|---|---|---|---|
| **Credential rotation** | The secret's *value*. A new revision points at a new vault version. | Older revisions still reveal the old value; that is what a pin means. | `resolver set <ref> --secret-stdin` |
| **Reference revocation** | The reference ends: every resolution fails, and every version's material is destroyed (tombstone, then deletion). | Every pin fails. | `resolver revoke <ref>` |
| **Vault key rotation** | The *key* that seals stored versions. The material, version numbers and seals stay the same. | Unchanged: the same revision reveals the same value before, during and after. | `resolver vault rotate` |
| Revision retirement (destroying only superseded versions) | Not implemented (open item O2). | — | After a leak, revoke the reference rather than only rotating the credential. |

## How the vault knows which key

- Every sealed version records `kid`, an id derived from the key that sealed it:
  `sha256("resolver.vault.kid\0" ‖ key)`, first 16 hex characters. It reveals nothing usable about the key,
  and nothing has to be configured to keep ids in sync.
- New versions are always sealed with `RESOLVER_VAULT_KEY`.
- A version opens with the key its `kid` names, which must be the current key or one of
  `RESOLVER_VAULT_PREVIOUS_KEYS`. With no such key, the vault fails with `KEY_MISSING`, never with a
  wrong value.
- Format-1 files (written before key ids existed) are tried with every configured key.

## Procedure

1. **Add the new key everywhere.** On every instance, set `RESOLVER_VAULT_KEY=<new>` and
   `RESOLVER_VAULT_PREVIOUS_KEYS=<old>` (comma-separated if several), then roll the instances. From now on:
   - new versions are sealed with the new key;
   - old ones still open.
2. **Re-seal.** Run `resolver vault rotate` once, from any one host with the same configuration. Each
   version is decrypted in memory and re-sealed under the new key, one file at a time:
   - the new file is written to a temporary name and renamed over the old one, so readers see one whole
     file or the other, and both open;
   - plaintext never touches disk;
   - format-1 files are migrated to format 2 on the way.

   The output counts what it did: `resealed`, `migrated`, `alreadyCurrent`, and `skippedRemoved` (revoked
   secrets whose removal it finishes rather than carrying material forward).
3. **Check.** `resolver verify` should exit 0 with no `old-vault-key` warnings.
4. **Remove the old key.** Drop it from `RESOLVER_VAULT_PREVIOUS_KEYS` and roll the instances. Destroy it
   in the secret manager only after you have a backup taken after step 2: older backups still need it.

**Interrupted?** Run `resolver vault rotate` again. It is idempotent: versions already under the current
key are skipped. While a rotation is incomplete, instances configured with both keys serve every secret.
**[test]**

**Concurrent with traffic?** Yes. Reveals during the rotation return the right value and writes during it
seal with the new key. **[test]**

**A revocation during the rotation?** A tombstone written mid-rotation wins: the rotation never writes a
version back once the tombstone exists, and it deletes anything it raced with. **[test]** for the
sequential case. The concurrent case is **[code]** only.

## Tests

`packages/server/test/rotation.test.ts`:
- **Full rotation:** with existing references, pins unchanged, then the old key removed. A vault holding
  only the old key fails with `KEY_MISSING`.
- **Interrupted rotation:** half re-sealed, readable with both keys, and finished by a second run.
- **Rotation under traffic:** 4 concurrent readers and a writer, with no errors and no wrong values.
- **Format-1 migration:** versions and pins kept.
- **Revoked secrets:** rotation does not bring their material back.

`packages/server/test/backup.test.ts` covers restoring with the old key configured as a previous key, and
refusing to restore without it.

## KMS-backed custody

Resolver accepts any AppPort Services `SecretCustody` (`custody` option). A KMS-backed custody rotates keys
the way its KMS does, and this procedure does not apply to it. For several instances it must also keep
versions: implement `withSecretVersion` and `discardVersion` (see `VersionedCustody` in `vault.ts`), or
`RESOLVER_MULTI_INSTANCE=1` refuses it. No KMS custody is shipped or tested in this repository.
