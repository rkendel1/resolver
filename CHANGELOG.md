# Changelog

## 0.1.1 — `@appport/resolver-client`, `@appport/resolver`

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
