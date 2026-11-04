# Resolver on AppPort Services extensions: decisions and plan

Status: **decisions A and B accepted** (after resolver#5). P0 is done: `@appport/services` 0.15.0 is published. Nothing else here is implemented yet. It refines
[appport-services-integration.md](./appport-services-integration.md) (resolver#5) now that the generic
extension mechanism exists (rkendel1/appport-services#43, `a3fabd5`).

Inspected:
- Resolver default branch at `695b918` (includes #4, `revealSecret`).
- AppPort Services `claude/services-extensions` at `a3fabd5`.
- FeltKit `packages/sdk/src/runtime/credentials.ts` (`HostCredentials`).

Statements about behavior cite the source or test that shows it. Anything not reproduced is marked
as read from source.

## The extension API this plan builds on (#43)

- `defineServicesExtension({ id, capabilities, pages, routes })`.
  - Capabilities are `{ name: '<id>.<…>', operation, effect, resource }`. They join the host gateway's
    manifest as `invocable: false`.
  - Pages are `{ id: '<id>' | '<id>-<x>', title, route: '/<id>[/…]', order, description, capabilities (≥1),
    script }`. A page is served only if the gateway allows **every** declared capability for the
    caller's tenant.
  - `routes(router, { db, gateway, application })` is mounted at `/v1/extensions/<id>`, behind the
    host's `authenticate` adapter. A request without a host identity is `401` before any extension
    handler runs.
  - Ids may not take built-in capability namespaces, and capabilities may not use built-in resource
    types. `resolver` and resource types such as `reference` or `grant` are fine. API keys are a
    built-in resource (`api_key`), so Resolver's key routes call the host's `apikeys.*` capabilities
    and do not declare their own.
- `createServices({ extensions })` binds each extension to that instance's FeltDB and gateway.
  `createManagementRouter({ extensions: services.extensions })` mounts only those registrations,
  and refuses hand-built ones and those bound to another instance.
- The renderer registers `window.AppPortServicesPages[pageId] = (ui) => node`. `ui` is
  `{ S, el, request, at, failureOf, config }`, with Stack UI 0.6.1 from the host shell.
- `authenticate` may return `PrincipalClaims` (minted as `verifiedBy: 'host'`) or an already verified
  principal (for example from `services.apiKeys.authenticateApiKey`), which is used as is
  (`src/runtime/management.ts`).

There is no lifecycle hook, no custody field in the context, and no side-effect-free "may this caller?"
query on the gateway. `authorize` throws on denial and records refusal evidence
(`docs/management.md`, "UI discovery").

## Decision A: who owns `resolver.*` authorization

### What Resolver does today

- **Grants.** Grants are `{ subject, actions ⊆ {read, reveal, write, admin}, pattern }`, per tenant, in
  `resolver_grants`. `pattern` is `*`, an exact `ref://…`, or a `ref://…/*` prefix
  (`core/src/names.ts` `matches`). `admin` is granted on `*` only (`checkGrant`).
- **Decision point.** `GrantAuthorizer.decide(principal, action, ref)` (`server/src/authorizer.ts`) is
  the only decision point for Resolver operations. A host principal with
  `principalType: 'resolver-operator'` and `verifiedBy: 'host'` is allowed everything. Decisions are
  not cached.
- **Actions per operation** (`server/src/resolver.ts`):

  | Operation | Action required |
  |---|---|
  | resolve, history | `read` on the ref |
  | resolve with `reveal` | `read` and then `reveal` on the ref |
  | put, rollback, revoke | `write` on the ref |
  | grant, ungrant, grants, keys.*, reveals | `admin` on `*` |
  | list, watch, dependents | **no call-level check**: rows and events are filtered by `decide(read)` per ref. A caller with no grants gets an empty list, not a refusal. |

- **Services gateway.** Resolver uses its own `createServices` instance, whose authorizer is the same
  `GrantAuthorizer`. Its `authorize()` answers only `apikeys.*` (admin grant or operator) and refuses
  every other capability ("is not used by the resolver").
- **Grant removal.** Removing a grant writes an `authority` record into the shared change sequence in
  the same transaction (`store.ts` `removeGrant`). Every instance then ends the subject's watch
  streams, and clients drop cached material before its TTL. Tests: `secret-revision.test.ts` 4, 5, 6.

### Can the host gateway carry these semantics?

| Question | Finding |
|---|---|
| Principal | The gateway passes `subject: { kind: principalType, id: principalId }`, `context.verified_by`, `tenant_id` and `credential_id`. These are the fields `decide` and `isOperator` use. Expressible. |
| Resource | `ServiceResource` has `id` and `attributes`. The request carries `resource.uri = appport://<app>/tenants/<t>/<type>/<encodeURIComponent(id)>` plus the attributes. A ref can travel as `{ type: 'reference', id: ref, attributes: { ref } }`. Expressible. |
| Action | One capability per action-bearing operation. `resolve`, `history`, `put`, `rollback`, `revoke`, `grant`, `ungrant` and `grants` map one-to-one. `resolver.keys.*` are not declared: key management is the host's `apikeys.*` on `api_key`, which `GrantAuthorizer.authorize` already answers (admin grant or operator). **Reveal has no capability today**: it is a flag on `resolver.resolve`. It needs its own declared capability (`resolver.reveal`), authorized as a second step for the same ref, as `#reveal` does now. |
| Tenancy | The gateway refuses a principal whose tenant differs from the resource's (`assertOwnership`), which matches "a grant never crosses tenants". |
| List, watch, dependents | **Not expressible as gateway calls.** Filtering rows through `gateway.authorize` would throw on each hidden row and write a refusal record for it, which turns visibility filtering into recorded denied effects. These must keep calling the same policy's `decide(read)` directly. The call-level capability (`resolver.list`, `resolver.watch`) must then be **allowed for any principal of the tenant**, or a caller with no grants would get `403` where it gets `[]` today. |
| Revocation | Unchanged if the policy store stays `resolver_grants`: grant removal still writes the authority record. If the grants lived in a host policy, Resolver could not see their removal, and tests 4–5 would degrade to the TTL bound of test 6. |
| Broadening | The gateway adds only denials: tenant and application checks, and API-key restrictions (`enforceCredential`, "can only deny"). Two things could broaden access: an unknown `resolver.*` capability that the authorizer allows by default, or a ref in `attributes` that differs from the one in the URI. Both must be denied explicitly (acceptance tests below). |
| Duplicated policy | Translating grants into a host AuthBoundry policy would create two policy stores for one decision. Keeping `resolver_grants` as the only store, and having the gateway's authorizer *be* `GrantAuthorizer` for `resolver.*`, does not. |
| Standalone | A standalone Resolver already is a Services host whose authorizer is `GrantAuthorizer`. Extending `authorize()` to answer `resolver.*` with the same `decide` keeps its behavior identical. |

### Recommendation

**Resolver owns the policy; the host gateway is the enforcement point.**

- `resolver_grants` and `GrantAuthorizer.decide` remain the only authorization policy for `resolver.*`.
- `GrantAuthorizer.authorize(request)` answers `resolver.*` by mapping the capability to its action.
  It reads the ref from `attributes.ref` and requires it to match the URI's id segment. Any
  capability it does not map is denied.
- Every Resolver operation reached through the extension runs inside
  `gateway.execute(capability, principal, { type: 'reference', tenantId, id: ref, attributes: { ref } }, …)`.
  Grant operations use `{ type: 'grant', tenantId }`. Key operations go through the host's own `apikeys.*` capabilities on `api_key`, which `GrantAuthorizer` already answers. This gives page gating, a single
  enforcement path, and `service_effect_evidence` for every Resolver effect.
- List, watch and dependents keep filtering with `decide(read)` on the same object. Their
  call-level capabilities are allowed for any principal of the tenant.

This **revises one sentence of resolver#5 §2**: "`resolver.*` capabilities are not added to Services'
gateway manifest". With the extension mechanism they are added, as `invocable: false` declarations.
Resolver's grants still make every decision.

**Scope.** This applies to the **shared Resolver deployment**, where the Resolver server is the host
and its gateway's authorizer is `GrantAuthorizer`. Embedding Resolver in another application's host
would require that host to route `resolver.*` to `GrantAuthorizer`, which means composing two
authorizers. That is not designed here and is not proposed now.

Rejected alternatives:
- **Keep authorization entirely outside the gateway** (resolver#5 as written). The page gate would
  need capabilities the gateway cannot decide. That means either a second check beside the gateway or
  pages that are not gated.
- **Host AuthBoundry owns the grants.** It duplicates policy, loses the authority-change signal, and
  cannot express the list and watch semantics.

## Decision B: versioned secret custody

### Contracts today

- **AppPort Services `SecretCustody`** (`src/secrets/protocol.ts`): `withSecret` (current material),
  `store → { version }`, `status`, and optional `remove`. `ResolvedSecret.version` exists, but nothing
  opens a specific version. No Services code needs one: there is no `withSecretVersion` in
  `appport-services/src`.
- **Resolver `VersionedCustody`** (`server/src/vault.ts`, exported from `@appport/resolver`):
  `SecretCustody` plus `withSecretVersion`. It also has optional `discardVersion` (delete a version
  whose commit lost) and optional `verifyVersion` (presence, key and `seal`, without the material).
  The vault implements all of them: immutable `v<N>.json` files published with `link`, a tombstone
  first on removal, key rotation by re-sealing, and a `seal` id recorded in the revision.
- **Resolver requirements:**
  - A revision's `SecretTarget` names `{ credentialRef, version, seal }`, and `revealSecret` returns
    exactly that version's material with that revision. Tests: `secret-revision.test.ts` 1–3.
  - `multiInstance` refuses custody without `withSecretVersion` and `discardVersion`
    (`runtime.ts` `checkMultiInstance`).
  - Revoke commits `state: 'revoked'`, so resolve refuses before custody is touched. It then
    removes the material, tombstone first.
- **Resolver fallback without versions** (`resolver.ts` `#reveal`): it calls `withSecret` and refuses
  unless `s.version === target.version`. That fails closed when the version moved. It assumes,
  though, that a version number identifies material.
- **FeltKit `HostCredentials`** (read from source, not reproduced) is latest-only. An
  environment-variable value is always reported as `version: 1`, whatever its content. Under the
  fallback, a secret stored at v1 and later shadowed by `FELTKIT_CREDENTIAL_<ID>` would reveal the
  environment value under the old revision. The version cannot detect that substitution.

### Recommendation

**Versioned custody stays a Resolver-owned contract (`VersionedCustody`, already exported). It is not
added to the shared Services contract now.** Resolver should **require** it wherever secrets are
enabled.

- **No shared contract yet.** It has one consumer. Putting it in the shared contract would ask every
  host custody to provide immutable, material-bound versions. FeltKit's cannot today, and an
  implementation that reports versions it does not keep would silently break revision consistency.
- **Require it, drop the fallback.** This strengthens the guarantee: the fallback is correct only when
  versions identify material, which a generic custody does not promise. It changes behavior only for a
  standalone Resolver configured with a non-versioned `custody` option. The default vault is
  versioned, and `multiInstance` already requires it.
- **No second vault in the shared deployment.** `runtime.ts` already passes the vault to its Services
  instance as `credentials`. The host's configuration secrets and Resolver's secrets are one vault. The
  extension takes the same object as its own `custody` option; the extension context gains nothing.
- **Compatibility:**
  - Services and its consumers: no change.
  - Standalone Resolver with the vault: no change.
  - Standalone Resolver with a custom non-versioned custody: refused at startup, with a message
    naming `withSecretVersion`.
  - If a second consumer appears, `VersionedCustody` can move to Services as an *optional* interface
    with `isVersionedCustody`. That would be additive.
- **Rotation and history.** Vault key rotation re-seals versions in place, the old and new keys both
  open during rotation, and `seal` lets `verifyIntegrity` check a restored state against a restored
  vault. Pinned revisions stay revealable until the reference is revoked. None of this changes.
- **Revocation and caches across instances.** Reference revocation travels through the shared
  sequence (`sync.ts`) and the vault tombstone. Grant revocation travels through the authority record
  (Decision A). Client caches are dropped on the authority notification, or else bounded by the TTL.
  None of this changes.

## Integration plan

The first target is the **shared Resolver deployment**: the Resolver server becomes an AppPort Services
management host whose only extension is Resolver. Applications keep using `@appport/resolver-client`.
No application embeds a Resolver.

Every PR below is a separate PR in `rkendel1/resolver` (owner: Resolver), except P0. None publishes
or deploys. Each keeps the existing suites green: `npm test`, the multi-instance and FeltDB-server
suites, `secret-revision.test.ts`, and the browser pages.

### P0 — AppPort Services: extension API

`rkendel1/appport-services#43`, owned by AppPort Services. Review and merge, then the owner publishes
it.

**Dependency for P1.** P1 onward need a Services version that contains #43. Until it is published,
they can be developed against a local link, but they cannot merge with a lockfile that points at an
unpublished version.

### P1 — Dependency convergence

- **Scope:**
  - `@appport/services` 0.9.1 → the release containing #43, as a regular dependency, because the
    standalone server is a host;
  - vendored Stack UI 0.3.0 → 0.6.1;
  - `@feltdb/core` aligned with that Services release;
  - `express`, which `createManagementRouter` needs and Resolver does not declare today.
- **No behavior change.** Remove the `as never` casts around `createServices` where the types now
  line up.
- **Acceptance:** the full suites pass unchanged, and the lockfile is regenerated from the published
  versions only.
- **Risk:** Services 0.9 → 0.14 option renames (`credentials`, `verifierKey`), and the Stack UI 0.6
  component changes in the current pages.

### P2 — Versioned custody required (Decision B)

- **Scope:**
  - `#reveal` and `createResolverRuntime` refuse a custody without `withSecretVersion` whenever
    secrets can be stored;
  - remove the latest-only fallback;
  - document `VersionedCustody` as Resolver's custody contract.
- **Acceptance:**
  - a runtime given a non-versioned custody fails at startup with a message naming the missing
    method;
  - `secret-revision.test.ts` 1–7 pass;
  - a new test: material of a non-current pinned revision is revealed exactly, after two later stores.
- **Risk:** a deployment configured with a custom latest-only custody stops starting. That is
  intended, and the changelog says so.

### P3 — Authorization through the gateway (Decision A)

> **Implemented** (`RESOLVER_GATEWAY_CAPABILITIES`, `GrantAuthorizer.authorize`; test `gateway-authorization.test.ts`).

- **Scope:**
  - `GrantAuthorizer.authorize` answers `resolver.*` through the capability→action map;
  - `resolver.reveal` declared;
  - `resolver.list` and `resolver.watch` allowed for any principal of the tenant;
  - unmapped capabilities denied;
  - `attributes.ref` must equal the URI id.
- The standalone server's operations still call `Resolver` methods, which still call `decide`.
  Only the gateway now answers for `resolver.*` too.
- **Acceptance:**
  - for each action, gateway and `decide` agree on the same principal, ref and pattern matrix
    (exact, prefix, `*`, other tenant, operator, no grant);
  - an unknown `resolver.x` capability is denied;
  - a mismatched `attributes.ref` is denied;
  - after `ungrant`, the next gateway call is denied (no caching);
  - list with no grants still returns `[]`.
- **Risk:** a policy mismatch between the map and `resolver.ts`. The agreement matrix is the guard.

### P4 — Resolver extension and route migration (items 1 and 3)

- **Scope:**
  - `resolverExtension({ custody })` built with `defineServicesExtension`: id `resolver`, the
    `resolver.*` capabilities except `resolver.keys.*`, plus `resolver.reveal`;
  - `routes(router, { db, gateway })` serving today's `/_resolver/*` JSON API at
    `/v1/extensions/resolver/*`;
  - each handler runs `gateway.execute(...)` around the existing `Resolver` method;
  - `ResolverStore` is built on `context.db`. There is no `createServices` and no vault inside the
    extension.
- **Acceptance:** against a Services host with the extension, these properties hold (cf.
  `appport-services/tests/extensions.test.ts`):
  - same FeltDB instance;
  - identity from the host adapter;
  - every effect has `service_effect_evidence`;
  - a refusal is a `403` with evidence;
  - tenants are isolated;
  - no route works without the extension.
- **Risk:** the `Resolver` constructor currently takes `services`, and uses it for API keys. Key
  routes must use the host's `services.apiKeys`, which is the same instance in the shared deployment.

### P5 — UI port (item 2)

- **Pages:**

  | Page id | Route | Declared capabilities |
  |---|---|---|
  | `resolver` | `/resolver` | `resolver.list` |
  | `resolver-references` | `/resolver/references` | today's references capabilities |
  | `resolver-models` | `/resolver/models` | today's models capabilities |
  | `resolver-secrets` | `/resolver/secrets` | today's secrets capabilities |

  The renderers register on `window.AppPortServicesPages`, use `ui.request` and `ui.S` (Stack UI
  0.6.1), and call `/v1/extensions/resolver/*`.
- **Access page.** It is not ported. API keys use the host's `/api-keys` page. Grants get a
  `resolver-grants` page (`resolver.grants`, `resolver.grant`, `resolver.ungrant`), which is the same
  policy store.
- **Acceptance:**
  - a browser test per page in the host shell: navigation, `aria-current`, axe light and dark, no
    script errors;
  - setting a secret never returns or renders the value;
  - `/secrets` stays the Services page, and `/resolver/secrets` is Resolver's.
- **Risk:** dropping the Access page removes the key-plus-grant flow on one screen. Operators use two
  pages instead.

### P6 — Standalone compatibility (item 6)

- **Scope.** The standalone server builds its own Services host with
  `createServices({ db, credentials: vault, authorizer: GrantAuthorizer, extensions: [resolverExtension({ custody: vault })] })`
  and mounts `createManagementRouter` (an Express app) in its `fallback`.
- **One `authenticate` adapter keeps today's three paths:**
  - the host adapter;
  - `Bearer` keys, returning the principal from `authenticateApiKey`;
  - the cookie session (still checking key liveness, idle and absolute TTL);
  - the CSRF origin check moves into that adapter, so a cookie-authenticated unsafe request from
    another origin is refused.
- **Sign-in.** It stays a route of the Resolver server, not of the extension.
- **What is removed.** The old `/_resolver/*` handler, after one release that serves both.
- **Unchanged.** The AppPort application endpoints and `@appport/resolver-client`: the client uses
  `@appport/sdk`, not `/_resolver/*`.
- **Acceptance:**
  - all existing client tests, the multi-instance and FeltDB-server suites, and backup and restore
    pass unchanged;
  - a session for a revoked key is refused on the next request;
  - a cross-origin cookie POST is refused.
- **Risk:** this changes the URLs of the management API. Anything scripting `/_resolver/*` breaks
  after the dual-serve release. Only the packaged UI is known to use it.

### Order and gates

P0 → P1 → (P2 ∥ P3) → P4 → P5 → P6. Nothing starts until Decisions A and B are reviewed. Embedding
Resolver in each application's host is out of scope: it would need host-side authorizer composition
and a versioned host custody, and neither exists.
