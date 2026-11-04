# Resolver as a native AppPort Services capability: architecture and plan

Status: **plan only.** Nothing here is implemented, published or migrated. Code references:
- Resolver `7720560` (this repository);
- AppPort Services `393f5c2` (rkendel1/appport-services, 0.14.0);
- FeltKit `main` `2909d05`.

## 1. What exists today

| Concern | Resolver | AppPort Services | FeltKit |
|---|---|---|---|
| Reference management | `Resolver.put/set/revoke/rollback/list` (`resolver.ts`); pages *References*, *Models* (`ui/contribution.ts:27-46`) | none (no `ref://` anywhere) | shows a model reference and its revision only (`Models.tsx:65`) |
| Revision history | `history` capability; `resolver_revisions` | none | none |
| Revision comparison | **none** (history lists revisions; no diff view) | none | none |
| Secret creation and rotation | write-only material, sealed versioned vault (`vault.ts`); page *Secrets* | `SecretCustody` interface only, **no implementation shipped**; page `/secrets` stores through the host's custody (`runtime/ui.ts:60`) | `HostCredentials` (env var or AES-GCM vault), **not versioned** (no `withSecretVersion`) |
| Grants and authority | `GrantAuthorizer`, `resolver_grants`; page *Access* | `ServiceGateway` over a **closed** capability manifest (`authority/manifest.ts:23`); unknown capabilities rejected (`gateway.ts:99`) | roles/permissions; Studio actions run as a declared identity, authorized by the gateway |
| Resolution activity and evidence | `resolver_reveals` (every secret reveal: who, revision, custody version). **Plain resolutions are not recorded.** | `service_effect_evidence` | decision and call records carry the resolution receipt |
| Configuration and lifecycle | `createResolverRuntime` (`runtime.ts`): state, custody, management, sync, readiness, integrity; CLI `init`/`serve`/`backup`/`restore`/`verify`/`vault rotate` | `createServices` (fixed service set, `unified-services.ts:180-227`); `startManagementHost` | hosts Services on the app's FeltDB instance (`services.ts:333-343`) |
| Embedded vs remote | **embedding already designed in**: `state: { db }`, `custody`, `management.authenticate`, `operator(tenantId)` (`runtime.ts:33`, `:57-62`, `:100`) | embedded (`createManagementRouter` + host `authenticate`) or standalone (`docs/management.md:5-12`) | Resolver used **remotely only**, through `@appport/resolver-client` |
| Management UI | its own management host: packaged pages + `/_resolver/*` JSON API, host identity adapter first (`ui/router.ts:1-17`); an `AppPort/ui/1` contribution validated with the protocol's validator | one shell (`renderManagementPage`, Stack UI `S.dom.Shell`); **closed** surface list, page list and router (`runtime/ui.ts:48-61`, `ui/management.js` `PAGES`) | packaged Services pages only on a development loopback console that cannot be framed (`management.ts:113`, `index.ts:141`); Studio reimplements service screens in React, from a hard-coded map (`ServicePages.tsx:39`) |
| Backup | state + vault + manifest, integrity-checked restore (`backup.ts`) | configuration export/import only, no HTTP route | local storage only; the credential vault is not included |

**Blocking facts for embedding:**
1. **Version skew.** Resolver pins `@feltdb/core` 0.18.0, `@appport/services` 0.9.1 and Stack UI 0.3.0. AppPort Services is at 0.14.0 with Stack UI 0.6.1. FeltKit runs one `@feltdb/core` 0.21.0, enforced by its release check. An embedded Resolver shares the host's process and FeltDB handle, so the versions must converge first.
2. **Two Services instances on one database.** Resolver calls `createServices({ db, application: 'resolver' })` for its API keys and principals (`runtime.ts:164`). Services' collections are flat and unprefixed (`api_keys`, `api_key_prefixes`, …; `storage/api-keys.ts:14-16`). Embedded in a host that already runs Services on that FeltDB instance, both would write the same `api_keys` collection under different applications.
3. **No extension point in Services.** Surfaces, pages, routes and the capability manifest are all closed. Another package's management pages cannot appear in the Services navigation today.
4. **Custody versioning.** Resolver reveals a pinned or superseded revision only from a versioned custody (`isVersionedCustody`, `vault.ts:101`), and multi-instance requires it. FeltKit's custody isn't versioned.

## 2. Ownership

| Owner | Owns | Does not |
|---|---|---|
| **Resolver** | references, kinds, bindings, revisions, grants, the vault (secret material and versions), resolution, watch, reveal records, backup and restore of its own state | the management shell, the host's identity, AppPort invocation authority |
| **AppPort Services** | the management experience (shell, navigation, layout, identity adapter), configuration workflows, host integration | `resolver.*` authorization (Resolver's grants decide), any copy of references, revisions or grants |
| **FeltDB** | durable state for Resolver (`resolver_*` collections), alongside the host's | |
| **AppPort** | capability discovery and invocation authority for application capabilities | resolution |
| **FeltKit** | composing the host: which Resolver mode, where its pages appear, deploy settings | a second registry, vault or permission system |

`resolver.*` capabilities are not added to Services' gateway manifest. Resolver authorizes them with its own grants; that is its responsibility.

> **Revised in [services-extension-integration.md](./services-extension-integration.md), Decision A (proposed):** with the generic extension mechanism (appport-services#43), `resolver.*` capabilities join the host gateway as `invocable: false` declarations, so pages are gated and effects recorded by the host. Resolver's grants (`resolver_grants`, `GrantAuthorizer`) remain the only policy that decides them. Services hosts the *experience*, and the identity adapter supplies *who* is calling.

## 3. Tenancy

A Resolver database is **not** one per application.
- **A tenant is an operator domain** (an organization or workspace). Every `resolver_*` row carries `tenantId`. Grants, keys and the watch stream are per tenant (`resolver.ts:163-190`).
- **Applications are principals inside a tenant.** Each deployment holds its own key, granted only its references (`read` on `ref://prod/payments/*`, `reveal` on its credentials).
- **Environments are reference namespaces** (`ref://prod/…`, `ref://staging/…`), with one key per environment's deployment. A staging key granted `ref://staging/*` cannot read production.
- **Shared mode:** many hosts and applications resolve against one Resolver, in one or more tenants.
- **Embedded mode:** the tenant is the host's tenant (FeltKit: the app), and its references serve that host's environments.

## 4. Deployment modes

### Shared Resolver (separately operated)
This is what runs today:
- `resolver serve`, its own FeltDB (`namespace: 'resolver'`; a FeltDB server for several instances; `docs/multi-instance.md`) and its own vault;
- applications use `@appport/resolver-client` (`RESOLVER_URL`, a per-deployment key);
- backup and restore are Resolver's own (`docs/backup-restore.md`).

No change is needed to run it. The management experience is the gap (section 6).

### Embedded Resolver (inside a Services host or host application)
`createResolverRuntime({ state: { db: hostDb }, … })` on the host's FeltDB instance. It requires:
- **E1. Version convergence:** `@feltdb/core` ≥ 0.21, `@appport/services` 0.14 and Stack UI 0.6.1 in Resolver. This is a Resolver release, tested on its full and multi-instance suites.
- **E2. One Services instance.** Add a Resolver runtime option to **use the host's `AppPortServices`** (its API keys and `identify`) instead of creating its own: `identity: { services }`. Resolver keeps its own `GrantAuthorizer`, because grants stay Resolver's. Without E2, embedding is refused when the host already runs Services on that database (detect `api_keys` in use by another application).
- **E3. One vault.** The embedded Resolver's vault becomes the host's custody. FeltKit passes Resolver's versioned vault as `SecretCustody` to `createServices({ credentials })`, so Services' `credential.store` writes Resolver secrets. It does not give Resolver FeltKit's unversioned custody. The `credential-ref:<id>` naming maps to `ref://<env>/credentials/<id>`. Until E3 lands, embedded mode is not offered, because two vaults would exist.
- **E4. The same contract.** The embedded Resolver serves the same AppPort application (`resolver.*` capabilities). The host mounts it at a path (`/resolver/appport`), and applications keep using `ResolverClient` against it. Caching, watch, revocation and `revealSecret` then behave exactly as in shared mode, so there is no second code path. (An in-process transport, `@appport/transport-inprocess`, is a later optimization; it must pass the same client test suite.)
- **E5. Lifecycle.**
  - Initialization: the host calls `createResolverRuntime` at startup and `close()` at shutdown.
  - Upgrades: they ride the host's dependency upgrade. This requires a Resolver schema version in `resolver_meta`, checked at start: refuse an older Resolver on newer state, and migrate forward explicitly. It does not exist yet.
- **E6. Backup and restore.** The host's backup must include `resolver_*`, the Services collections Resolver uses, and the vault directory. FeltKit's backup today excludes its vault and supports local storage only. Resolver's own `createBackup` has the right content and manifest, so the host calls it rather than copying files.

## 5. API changes

| Package | Change | Why |
|---|---|---|
| Resolver | dependency convergence (E1) | embedding |
| Resolver | `createResolverRuntime({ identity: { services } })` (E2) | one Services instance per database |
| Resolver | `resolver_meta.schemaVersion` + startup check (E5) | embedded upgrades |
| Resolver | record resolutions per principal (last resolved revision and time) in a bounded `resolver_consumers` collection, written at most once per principal, reference and revision | "which applications consume each reference" has no source today. It is additive; plain resolutions are not recorded now |
| Resolver | `history` returns enough to diff two revisions (it does, as `targets`); a compare view in the UI | revision comparison |
| AppPort Services | **management extensions**: `createManagementRouter({ extensions })`, with each extension `{ surface: { id, title, route, order, capabilities }, script, routes(router) }`. The shell adds the surface to the navigation and `/v1/ui` merges its `AppPort/ui/1` contribution (validated). Pages render inside the same Stack UI shell | the only way to add pages to the Services experience without forking its closed lists |
| FeltKit | mount extensions in its Services console; Studio lists them | native experience in FeltKit |

No change to `@appport/resolver-core` or the protocol.

## 6. Management experience (inside Services)

Resolver ships `@appport/resolver/management-extension`, built from its existing pages and `/_resolver/*` JSON API, ported to Stack UI 0.6.1. Its pages, in the Services navigation:
- **References.** Catalog with search by prefix, kind and namespace (`list`). Create and edit (`put`, with kind-specific forms: model, endpoint, value with schema, agent). Revoke, and roll back.
- **Revision history.** Each revision with who, why and when, plus a **compare** view between two revisions (new).
- **Environments.** References grouped by namespace (`prod`, `staging`, …), with one row per environment for the same path.
- **Secrets.** Create and rotate, write-only; the UI never receives material. Shows the reveal log (`reveals`).
- **Access.** Keys per deployment, with their grants (`read` / `reveal` / `write` / `admin` on patterns), create, revoke and ungrant.
- **Status and activity.** Readiness (`/_resolver/ready`), sync, integrity. Who resolved and revealed what, at which revision (new `resolver_consumers` plus `resolver_reveals`).
- **Consumers.** For each reference, the principals that resolve it and the revision each last used (new).

**Identity:**
- The host's `authenticate` adapter supplies the caller, the same adapter Services uses.
- Resolver decides what that caller may do through its grants. A human principal without grants sees nothing.
- `principalType: 'resolver-operator'` (full access) is asserted only by a host that has authorized that operator for it. In FeltKit that means operators holding a new `resolver.admin` permission.

**Modes:**
- **Embedded:** the extension calls the in-process Resolver.
- **Shared:** a Services host shows no Resolver pages, because it holds no authority there. The shared Resolver deployment runs its own Services management host with the same extension, which is the one console for that Resolver. Applications' Studio shows each reference they use, with its revision, read through their own key (as Models does today).

## 7. FeltDB schema and lifecycle

- **Collections.** `resolver_references`, `resolver_revisions`, `resolver_grants`, `resolver_reveals`, `resolver_meta`, `resolver_authority` and `resolver_sessions` exist today. `resolver_consumers` is new. All are tenant-keyed, and all are in Resolver's backup set except sessions.
- **Writes.** They are conditional on the revision read, with one change sequence in `resolver_meta` (`store.ts`).
- **Schema version (new).** `resolver_meta/schema` `{ version }`. A Resolver refuses state newer than it knows; migrations are explicit steps, recorded in the change sequence.
- **Embedded.** The same collections live on the host's instance, under its own handle (`instance.handle("appport-resolver")` in FeltKit, for attribution), with no namespace change.

## 8. Security boundaries

- Secret material exists in the vault (sealed) and in the memory of a principal that revealed it. It is never in FeltDB, logs, the UI, backups (ciphertext only) or receipts.
- `reveal` is separate from `read`. Removing it stops cached material (client 0.2.0), and `revealSecret` returns material together with its revision.
- Resolver grants are the only authority over references. AppPort decides invocation of application capabilities. Services' gateway is not asked about `resolver.*`, and Resolver is not asked about application capabilities.
- Tenants never see each other: names, values, lists and change notifications (an existing test, `security.test.ts`).
- Embedded mode keeps the host's single FeltDB instance (FeltKit refuses a second) and a single vault (E3).

## 9. Tests and acceptance

- **Resolver:** the full suite, plus multi-instance on a FeltDB server, after E1. New tests for E2 (`identity: { services }`: keys and identities from the host, grants from Resolver; refusal when another application owns `api_keys`), E5 (schema version refusal and forward migration), and `resolver_consumers`.
- **AppPort Services:** extension surfaces in the navigation and in `/v1/ui` (validated); an extension's routes authenticated by the host adapter; built-in pages unchanged; a browser test in light and dark at 1280 and 640 px, as Resolver's suite already does.
- **FeltKit:**
  - embedded Resolver on the app's instance: one `@feltdb/core`, one vault (`credential.store` lands in Resolver), backup and restore round-trip including `resolver_*` and the vault;
  - the model-reference tests and `resolver-switch` e2e unchanged, run against embedded and shared Resolver alike (same client, same contract).
- **Acceptance:**
  - an operator creates a model reference and a credential in the Services console;
  - a deployed app uses it;
  - the operator rotates the credential and sees the new revision in use (consumers view);
  - a removed `reveal` grant stops the app within seconds;
  - backup and restore preserve all of it.

## 10. Exact changes, in order

> Superseded by the PR-by-PR plan in [services-extension-integration.md](./services-extension-integration.md). Step 2 below is appport-services#43.

1. **Resolver: converge dependencies (E1).** `package.json`, the lockfile, `packages/server/vendor/stack-ui` → 0.6.1, the UI pages. Nothing else; full plus multi-instance suites.
2. **AppPort Services: management extensions.**
   - `src/runtime/ui.ts`: `SURFACES` plus extension surfaces.
   - `src/runtime/management.ts`: extension routes.
   - `src/configuration/ui.ts`: navigation and script assets.
   - `ui/management.js`: delegate unknown page ids to an extension script.
   - docs.
3. **Resolver: `management-extension` export.** It reuses `ui/router.ts` and `ui/pages.ts`, and adds the compare and consumers views and `resolver_consumers`.
4. **Resolver: `identity: { services }` (E2), schema version (E5).**
5. **FeltKit: embedded mode** behind `feltkit({ resolver: { embedded: true } })`:
   - Resolver's vault as Services custody (E3);
   - mount the AppPort application (E4) and the management extension;
   - backup integration (E6);
   - Studio navigation.

**Recommendation.** Do steps 1–3 first. With them, **shared mode gets a native console** (the Resolver deployment's own Services host) with no change to applications or FeltKit. Embedded mode (steps 4–5) follows only once E2 and E3 remove the second Services instance and the second vault. Until then, offering embedded mode would duplicate a control plane and a vault, which the constraints forbid.

## 11. Not decided here

- Whether the shared Resolver's console should also be reachable from each application's Studio. A link is fine. Proxying operations would need a delegation model that doesn't exist (the host would act with a Resolver admin key on a person's behalf), so it is not proposed.
- Whether FeltKit's own `FELTKIT_CREDENTIAL_<ID>` custody should eventually move entirely to Resolver. E3 does that for embedded mode only.
