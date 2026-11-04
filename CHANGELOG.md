# Changelog

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
