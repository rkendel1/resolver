# Changelog

## 0.3.3 / client 0.2.4 / core 0.1.1

_Prepared; publish with Actions → Publish packages (needs the `NPM_TOKEN` repository secret)._

### CI: the consumer check follows the client's declared SDK range

`scripts/consumer-check.mjs` asserted that `@appport/sdk` resolves to exactly the 1.7 line. The client
declares `^1.7.0`, and `@appport/sdk` 1.8.0 is published, so every install now resolves 1.8.0 and `main`
failed CI although nothing was wrong. The check now asserts the declared range (1.x from 1.7, never 1.6 or 2.x)
and installs the current `@feltdb/feltkit` (0.3.22), whose pins are aligned, so the whole-graph assertions
(one copy of every `@appport/*` package, one protocol module) are required rather than only reported.

### Model options named like sizes are no longer refused as credentials

`checkTarget` refused any `model.options` key or `endpoint.headers` name containing `token`, so
`{ max_tokens: 1024 }` (which `ModelTarget.options` documents as an example) failed with "looks like a credential".
Keys are now judged by whole words: `access_token`, `apiKey`, `X-Api-Key`, `client_secret`, `Authorization`,
`password`, `bearer` and `credential` are still refused; `max_tokens`, `maxOutputTokens` and other size settings are
accepted. Found while auditing the FeltKit M1 generation path. Test: `packages/core/test/core.test.ts`.

## 0.3.2 / client 0.2.3 (published)

### `@appport/resolver-client` follows the AppPort 1.7 release line

`@appport/resolver-client` 0.2.2 pinned `@appport/sdk` 1.6.0. FeltKit, and this workspace's own server, had moved to
`@appport/sdk` 1.7.0 (protocol 1.5.0, core 1.7.1, schema 1.1.6, authorization 1.1.1, server 1.3.1), so an application
installing `@feltdb/feltkit` received two AppPort dependency graphs: two protocol modules, two sets of SDK types,
feedback receipts digested by one copy that the other could not verify. FeltKit's exhaustive composition consumer gate
(`scripts/matrix-consumer.mjs verify` in rkendel1/feltkit) found it; FeltKit's root npm override had hidden it inside
that monorepo and cannot protect downstream consumers.

- `@appport/resolver-client` depends on `@appport/sdk` `^1.7.0` (a caret range, so a 1.7.x or later 1.x SDK is one
  copy with whatever installs beside it). It uses only `AppPort.discover` and the `AppPortClient` type, both unchanged
  in 1.7 (verified: typecheck, the suite, and `packages/client/test/dependencies.test.ts`).
- `@appport/resolver` moves to the same release set (`@appport/sdk` 1.7.0, `@appport/server` 1.3.1, `@appport/core`
  1.7.1, `@appport/protocol` 1.5.0, `@appport/schema` 1.1.6, `@appport/authorization` 1.1.1, `@appport/services`
  0.16.0, which requires protocol 1.5.0) and on `@appport/resolver-client` 0.2.3, so the server's own install is one
  graph too. No server code changed.
- Regression test `packages/client/test/dependencies.test.ts`: the range admits 1.7 and not 1.6; the resolved SDK is
  1.7.0 or later with every package at the version it pins; the client, the SDK, core and the server resolve one
  `@appport/protocol` module; the client imports only what the SDK exports.
- `scripts/consumer-check.mjs` (run by CI): the packed client installed beside `@feltdb/feltkit` from the registry in an
  empty project resolves one copy of every `@appport/*` package, the 1.7 line, no SDK nested under the client, and one
  protocol module for FeltKit, the SDK and the client, through which an `appport.feedback/1` report validates with the
  same digest.

Nothing in the AppPort protocol or SDK changed; no overrides were added; the lockfile was regenerated.

FeltKit: once 0.2.3 is published, FeltKit drops its root `overrides` for `@appport/resolver-client` and pins 0.2.3;
until then its consumer gate stays red by design.

### Current AppPort releases

Both packages move to the current AppPort releases: `@appport/sdk` 1.6.0, `@appport/server` 1.3.0
(per-connection event subscriptions), `@appport/core` 1.7.0 (no static Node imports on the
server-internal path), `@appport/protocol` 1.4.1, `@appport/authorization` 1.1.0 (`NOT_FOUND` denials),
`@appport/schema` 1.1.5. Applications that use `@appport/resolver-client` (FeltKit among them) no
longer install a second, older copy of the AppPort server.

## `@appport/resolver` 0.3.0, `@appport/resolver-client` 0.2.1

_`@appport/resolver-core` is unchanged (0.1.0)._

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
