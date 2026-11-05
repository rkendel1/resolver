# Changelog

## Unreleased

_Next release: `@appport/resolver` 0.3.0, `@appport/resolver-client` 0.2.1. `@appport/resolver-core` is unchanged (0.1.0)._

### Resolver's grants answer the host gateway for `resolver.*` (P3)

`GrantAuthorizer.authorize`, the AuthBoundry contract a host gateway calls, now answers Resolver's own
capabilities. Before, it refused everything but `apikeys.*`. Each capability maps to the grant action it
needs (`RESOLVER_GATEWAY_CAPABILITIES`, exported), and the answer comes from the same `decide` the
resolver's operations use: one policy, one store (`resolver_grants`), no caching. A removed grant still
writes the authority record instances and clients react to.

- `resolver.resolve` / `history` need `read`. `resolver.reveal` (new, a gateway-only capability) needs
  `reveal`. `put` / `rollback` / `revoke` need `write`. `grant` / `ungrant` / `grants` need `admin` on `*`.
- `resolver.list` and `resolver.watch` are allowed to any principal of the tenant. They filter every row
  and event by `read` themselves, so a caller with no grants still gets `[]`.
- The resource must name the reference twice, as the resource id and the `ref` attribute, and both
  must agree. Unmapped `resolver.*` capabilities are denied.
- Key management stays on the host's `apikeys.*`. `resolver.keys.*` is not declared to the gateway.
- Nothing calls the gateway for `resolver.*` yet. The standalone server's operations still call
  `Resolver` methods directly. P4 (the management extension) declares these capabilities and routes
  through the gateway.
- Test: `packages/server/test/gateway-authorization.test.ts` runs a real @appport/services 0.15 gateway
  with the capabilities declared through `defineServicesExtension`. It checks agreement with `decide`
  across six principals (none, exact, prefix, `*`, another tenant's grant, operator) × two refs × every
  reference capability. It also checks a mismatched or missing `ref`, admin scope, list/watch semantics,
  denial on the next call after `ungrant`, and allow and deny evidence through `gateway.execute`.
### Versioned custody is required

`createResolverRuntime` and `new Resolver()` refuse a custody without `withSecretVersion` (Resolver's
`VersionedCustody`), with an error naming it. The latest-only fallback is removed: before, a custody
without versions revealed whatever it held now, if its version number matched the revision's. A version
number from a generic custody need not identify material (an environment-variable custody reports
every value as version 1), so that check could pair a revision with another revision's material.

- The vault, the default, is versioned; nothing changes for it. `multiInstance` still also requires
  `discardVersion`.
- A deployment configured with a custom latest-only `custody` no longer starts. Give it versions, or
  use the vault.
- `requireVersionedCustody()` is exported. `ResolverRuntimeOptions.custody` and
  `ResolverOptions.custody` are typed `VersionedCustody`.
- Tests: `packages/server/test/custody-versions.test.ts`. Refusal at startup and in the constructor (both
  fail on the old code); revisions 1, 2 and 3 of one secret each reveal exactly their own value after
  two later stores. The concurrent-writes test in `audit.test.ts` now runs on the versioned vault; it
  used to exercise the latest-only path this removes.
### Stack UI 0.6.1 (was 0.3.0)

The management pages' vendored design system is the release AppPort Services 0.15 uses:
`packages/server/vendor/stack-ui` is replaced with `rkendel1/stack-ui` 0.6.1, copied unmodified from
AppPort Services' vendored copy (every file matches `SHA256SUMS`). The pages keep the same three
inlined files (`tokens.css`, `core.css`, `stack-ui-core-stateless.js`) and need no code change. The
release adds `tokens-light.css`, `brand/`, `esm/` and `conformance.mjs`, which the pages don't load.
They ship with the package so the directory stays identical to the release. The UI test also checks
`VERSION`.

## 0.2.0 — `@appport/resolver-client`, `@appport/resolver`

Adds one client API, and moves the server onto the current AppPort Services and FeltDB. No change
to the protocol or to `@appport/resolver-core` (0.1.0, already published and unchanged). It includes
everything in 0.1.1 below. 0.1.1 was prepared and never published; 0.2.0 is the first release with
the reveal-revocation fix.

### Dependencies: AppPort Services 0.15.0 and FeltDB 0.21.0

`@appport/resolver` now pins `@appport/services` 0.15.0 (was 0.9.1) and `@feltdb/core` 0.21.0 (was
0.18.0), the versions the rest of the AppPort / FeltKit train uses. There is one copy of each in the
install. There is no code change: the whole suite passes unchanged, including the multi-instance
suites against a FeltDB server 0.6.1. Nothing in Resolver uses the Services management-extension API
yet.

### `revealSecret(ref)`: a secret's material with the revision it belongs to

`secret(ref)` returns the material only. A caller that must record which credential it used
(an integration receipt) had to ask for the revision separately. A rotation between the two
answers then pairs revision 1 with revision 2's material.

`revealSecret(ref)` returns `{ ref, revision, value }` as one result:

- **One answer.** The resolver reads the reference once, reveals the custody version that
  revision binds, and returns both in the same response. A custody without versions refuses
  rather than reveal a different version. The client caches and invalidates the pair together.
- **Same authority and cache as `secret()`.** It needs `reveal`, and it is dropped when the
  key's authority shrinks. A client that does not watch, or that missed the notification, may
  answer from cache until the reference's TTL, and never after it.
- **Record `ref` and `revision`, never `value`.**
- `secret(ref)` is unchanged: same return type, same behavior.

Tests:
- `packages/server/test/secret-revision.test.ts`:
  - exact revision; rotation;
  - concurrent rotations: 40 rotations while three readers loop, and every pair read is a
    revision with its own material. A naive two-call implementation fails this test;
  - reveal removed;
  - notification invalidation;
  - the TTL bound with no notification;
  - no material in logs or stored files.
- `packages/server/test/sync.test.ts` case 10: rotations through one instance while another
  reveals, on a shared handle and on a real FeltDB server.

Upgrade: `npm install @appport/resolver-client@0.2.0`.

### The API-key verifier key is applied (`RESOLVER_VERIFIER_KEY`)

`createResolverRuntime` passed `verifierKey` to AppPort Services under a name Services does not read
(it reads `apiKeyVerifierKey`), and an `as never` cast hid the mismatch. So the configured verifier
key never took effect: every API key was stored as a plain `scrypt$…` verifier, not the
`hmac-scrypt$…` verifier keyed by the server-held secret that the docs describe.

- New keys are stored as `hmac-scrypt$…` under the configured key. They verify only with that key,
  which makes the docs' statement true: losing `RESOLVER_VERIFIER_KEY` invalidates them.
- Keys created before this release (`scrypt$…`) keep working unchanged. Services verifies both
  forms, so no key has to be reissued. To move an existing key to the keyed form, rotate it.
- The cast is gone, so the options object is type-checked again.
- Test: `packages/server/test/verifier-key.test.ts`. It fails on the old code.

## 0.1.1 — `@appport/resolver-client`, `@appport/resolver` (prepared, not published; released as part of 0.2.0)

Security fix in the client. No API change. `@appport/resolver-core` is unchanged (0.1.0).

### A removed `reveal` grant now stops cached secret material

In 0.1.0, the client kept revealed secret material in its cache after the key lost `reveal`
on that secret, if it kept `read`. It handed out the old material until the reference's TTL
ran out: 30 s by default, longer with a larger `--ttl`.

- **Why.** When a key's authority shrinks, the resolver ends that key's watch stream. The client
  then revalidates what it holds, but in 0.1.0 it revalidated cached resolutions only. A cached
  secret was re-checked through `resolve`, which needs `read`, never through a new reveal.
- **Now.** Every revalidation also drops the cached secret material: a reconnect, or the resolver
  ending the stream because the key's authority shrank. The next use reveals again, with the
  key's current authority, and is refused if `reveal` was removed.
- **Unchanged.** The other revocation paths already stopped cached use within seconds:
  - removing `read` on the reference;
  - revoking the key;
  - revoking the secret reference;
  - rotating the secret, after which the new material arrives.
- **Still bounded by delivery, not instant.** Between removing the grant and the client receiving
  the end of its stream, cached material is still usable. On one resolver instance that gap is
  effectively immediate. Across instances it is bounded by the sync interval (default 1 s). If
  the notification is missed, the TTL bounds it.

Test: `packages/server/test/security.test.ts`, "stops handing out cached secret material once
reveal is removed, while read remains". It fails against 0.1.0.

`@appport/resolver` 0.1.1 depends on `@appport/resolver-client` 0.1.1, so the CLI and anything
installed with the server get the fixed client.

Upgrade: `npm install @appport/resolver-client@0.1.1`.

## 0.1.0

First release.
