# Governance and observability: guarantees, evidence, limitations

What `@appport/resolver` 0.4.0 (with `@appport/resolver-core` 0.2.0 and `@appport/resolver-client` 0.3.0)
guarantees about mutation authority and resolution observability, and what it does not. Each guarantee names the
test that shows it. The design is [governance-and-observability.md](governance-and-observability.md).

## Mutation authority

### Guaranteed

| # | Guarantee | Evidence |
|---|---|---|
| G1 | **Unchanged without a policy.** A reference no policy covers is written exactly as in 0.3.3: no authorization needed, none recorded. | The 177 pre-existing tests pass unchanged. `governance.test.ts` "leaves ungoverned references exactly as before". Resolver Control's and FeltKit's Resolver suites pass against 0.4.0. |
| G2 | **Grants are not enough on a governed reference.** Under a policy, `put`, secret `put` (`put-secret`), `rollback`, `revoke` and creation all need a change authorization, whatever grants the caller holds (`write`, `admin`, `*`). | "refuses every governed operation without an authorization" |
| G3 | **One enforcement point.** The check is in the `Resolver` class (`#governance`), called by every write path after the revision check. Every transport calls those methods: the CLI, the SDK over AppPort/HTTP, the management pages, embedding. | Tested over AppPort (`governance.test.ts`), the CLI (`governance-cli.test.ts`), embedding (operator calls) and two served processes (`multi-process-governance.test.ts`). The management pages and MCP clients reach the same methods, but were not exercised against a policy. |
| G4 | **An authorization admits exactly the change it was issued for.** Tenant, reference, operation, expected revision and the SHA-256 of the canonical request (kind, schema, normalized binding, ttl; for a rollback, the restored revision) are signed claims, compared with the request. Writing the same binding in another key order or form is the same change. | "binds the reference, tenant, operation, revision and exact change" (another ref, tenant, operation, revision, binding, ttl: each refused) |
| G5 | **Signatures are verified locally (Ed25519).** No network call; Resolver Control can be down. Forged, tampered, `alg: none`, malformed, unknown-key, untrusted-issuer, and issuer-impersonating tokens are refused. | "refuses forged, tampered, unsigned, wrongly-typed and untrusted authorizations" |
| G6 | **Time-bound.** `nbf`, `exp` and `iat` are checked with 30 s skew; validity (`exp - nbf`) may not exceed the policy's `maxValiditySeconds`. | "refuses expired, not-yet-valid, over-long and future-issued authorizations" |
| G7 | **Single use, atomically.** A consumed-authorization row keyed by (tenant, issuer, jti) is written with `requireAbsent` **in the same FeltDB transaction** as the revision. It exists if and only if the revision committed. One token presented concurrently to many writers, or to two resolver instances (in process or as separate processes), commits once. A jti reused in a re-signed token is refused (`resolver.authorization-consumed`). | "a consumed authorization admits nothing more…"; "one authorization presented concurrently…"; "two resolver instances over one state…"; multi-process test |
| G8 | **A failed commit consumes nothing.** If the transaction fails, the token remains usable for its exact change. | "a commit that fails leaves the authorization unconsumed" (fault injection) |
| G9 | **Stale writes stay stale.** A valid authorization for revision N cannot be applied once the reference has moved past N. | "a stale revision is refused as stale" |
| G10 | **Key lifecycle.** Keys are identified by `kid`. `active` verifies. `retired` (rotation) verifies only tokens issued before its retirement, so approvals in flight survive a rotation. `revoked` (compromise) verifies nothing from then on, including outstanding tokens. Key ids are never reused. | "rotation: … revocation: …" |
| G11 | **Secrets.** A secret write needs a `put-secret` authorization bound to kind and ttl, never to the material. The decision is made **before** the material reaches custody, so a refused write stores nothing. A write that loses on consumption discards its stored version. Material appears in no token, consumed row, revision evidence, governance event or record. | "secrets: authorized without the material…" (integrity reports no problems and no orphans) |
| G12 | **No silent operator bypass.** The host operator is refused under a policy like any key. `breakGlass: { reason }` is the operator's alone (an API key's is refused), needs a non-empty reason, and is refused where no policy governs (so the trail holds only meaningful entries). A break-glass write records `governance: { mode: "break-glass", actor, reason }` on the revision. It writes a `break-glass` governance event in the **same transaction**, and every watcher's change event carries `governance: "break-glass"`. | "the operator: refused like anyone without break-glass…"; CLI and multi-process tests |
| G13 | **Trust roots are host-level and audited.** Policies and signing keys are changed only by the host operator (CLI on the state host), with a reason. Each change is committed with its governance event. An API key, `admin` included, can read them but never change them. | "policies and signing keys are the host operator's…" |
| G14 | **A narrower policy never un-governs.** The governing policy is the most specific matching one *among those that list the operation*. | "…a narrower policy for one reference never un-governs…" |
| G15 | **Authoritative evidence.** Each governed revision records its authority (`issuer`, `kid`, `jti`, `decision`, `approvers`, or break-glass), returned by `history`. The consumed-authorization row links the issuer's decision to the revision. | "admits the write…, records it on the revision, and tells watchers" |
| G16 | **Checked before side effects.** Governance runs before outbound target checks (an unauthorized writer cannot make the resolver contact an agent origin) and before custody. | Code order in `#put` / `#rollback` / `#revoke`; G11 |

### Limitations

* **Trust is rooted in the host.** Whoever can run the operator CLI against the state (the host, or a holder of the
  FeltDB credentials) can change policies and keys and break glass. Every such act is recorded, but in the same
  state they control.
* **History is not tamper-evident.** A FeltDB administrator can edit rows directly, bypassing Resolver entirely:
  revisions, consumed authorizations, governance events. (Unchanged from 0.3.3; gap R5.)
* **An authorization is a bearer token for its exact change**, until it expires or is used. Anyone holding it *and*
  a `write` grant can apply that one approved change, once. They cannot alter it. Keep validity short (the policy
  caps it).
* **Revoking a key does not undo** revisions committed with it. It stops future use only.
* **Revision binding already prevents re-use.** Revisions only increase, so a committed token's expected revision
  can never match again. Consumption adds the authoritative token→revision record, and closes the window where
  two writers present one token at the same moment.
* **The management pages cannot write governed references.** They have no field for an authorization, so the
  resolver refuses those writes. How the pages present that refusal was not tested. They do not yet show
  governance or adoption.
* **Evidence copied from the token is the issuer's claim.** `decision` and `approvers` are recorded but not checked
  by Resolver.

## Resolution observability

### Guaranteed

| # | Guarantee | Evidence |
|---|---|---|
| O1 | **On by default.** Every resolution's outcome (`ok`, `revoked`, `not_found`, `forbidden`) is recorded per principal, registration, reference and revision. `observeResolutions: false` turns it off. | `observability.test.ts` "records what a consumer resolves by default…" |
| O2 | **The facts stay apart.** Declared (registration), registered (liveness), resolved (observed by Resolver), used (reported by the consumer) and verified (none yet) are separate fields and separate collections, never one status. | "…keeps declared, resolved and used apart"; `resolver.consumers.list` |
| O3 | **Recording never blocks or fails a resolution.** Writes run in the background. A state store that refuses them leaves resolutions served; the loss is counted (`observations.status().failures`). | "a state store that refuses observation writes never fails a resolution" (fault injection) |
| O4 | **Bounded cost.** 200 resolutions of one key cost at most 2 writes (first sighting, then the coalesced count), and the count is kept exactly after flush. | "many resolutions cost a bounded number of writes" |
| O5 | **No secret material, no steering key.** Records hold references and revisions only. | "records no secret material…"; the steering key `user-123` is absent from records |
| O6 | **Identity.** A registration id is honoured only for its own principal. A borrowed id is ignored, and the resolution is recorded under the verified caller. A consumer cannot declare dependencies it may not read. | "a consumer cannot declare what it may not read, nor borrow…" (fails if the check is removed) |
| O7 | **Refusals are visible to admins only**, so readers cannot learn which principals probe a reference. | "refused resolutions are recorded, and shown to admins only" |
| O8 | **Liveness from the watch stream.** An open stream keeps a registration `live`. Without one it becomes `stale` after the grace period (default 120 s). `close()` deregisters it. Rows are kept for history. | "registration liveness follows the watch stream" |
| O9 | **Adoption is a lifecycle, not a notification.** `resolver.adoption` reports, per revision: **authorized** (authorization with its consumption time, break-glass, or ungoverned), **committed**, **available** (current, or until when), **fetched** (observed), **not yet fetched** (live declared consumers), **adopted** (asserted) and **functionally verified** (`null`). A consumer that *received* the change notification but did not resolve is not counted as having fetched it. | "distinguishes authorized, committed, available, fetched and adopted, and never counts a notification as adoption"; read across processes in the multi-process test |
| O10 | **Old clients work, and are observed.** A 0.2.x client is recorded under its principal, without a registration. | Resolver Control's suites pass against 0.4.0 with client 0.2.4 |

### Limitations

* **Counts are lower bounds.** Increments within the coalescing window (default 60 s) are held in memory per
  instance. A crash loses at most one window of increments, never a first sighting already written. A clean
  shutdown flushes everything.
* **"Fetched" has TTL granularity.** A consumer serves its cache until a notification or its TTL, so Resolver sees
  a fetch when the consumer actually asks, not when the revision became current.
* **Weighted steering runs in the client.** Resolver observes the revision served, not the target selected. Only a
  usage report carries the label.
* **Declared and used are asserted.** A consumer can misreport its application name, instance, dependencies or use.
  The principal is the only verified identity.
* **"Available" is the committed timeline.** It does not include another instance's sync lag (at most its sync
  interval) or client caches.
* **No retention policy.** Observation rows grow with consumers × references × revisions × outcomes. Stale
  registrations are kept, never pruned.
* **Functional verification is not produced.** The `functionallyVerified` stage is always `null` in this milestone.

## Test inventory (this branch)

| Suite | Command | Result |
|---|---|---|
| Unit, integration, CLI, multi-process (local state shared) | `npm test` | 25 files, **202 passed**, 9 skipped |
| Management pages in Chromium (flows, CSP, axe, light/dark, 1280/640 px) | `npm run test:browser` | **11 passed** |
| New: `governance.test.ts` | adversarial authority, concurrency, failure injection | 15 passed |
| New: `governance-cli.test.ts` | operator and writer through the CLI | 1 passed |
| New: `observability.test.ts` | registration, recording, cost, failure, adoption | 8 passed |
| New: `multi-process-governance.test.ts` | two served processes, CLI operator, restart | 1 passed |
| Resolver Control (published client 0.2.4) against 0.4.0 | `RESOLVER_SERVICE_FROM=<packs> npm test`, `test:e2e`, `test:artifact` | 13/13, 1/1, 1/1 |
| FeltKit's Resolver tests (`resolver-model`, `resolver-revocation`) against 0.4.0 | fixture pointed at the packs | 12/12 (12/12 on 0.2.0 before) |

**Mutation checks.**
- With enforcement disabled, 12 of 15 governance tests fail. The other 3 hold on the revision check alone, correctly.
- With transactional consumption removed, exactly the 4 consumption tests fail.
- With registration ownership unchecked, the borrowing test fails.

**Not run, and why.** The 9 skipped tests are the FeltDB-server variants of the sync and multi-process suites. With
`feltdb-server` built from rkendel1/flow_db (HEAD 0.6.1, and the commit before "Enforce application and environment
boundaries"), they fail on **unmodified** 0.3.3 too: the server asks for an application id the harness does not
send. That incompatibility predates this work. Multi-host behaviour over a FeltDB server is therefore not verified
here. The shared-local-state variants (two processes, one host) run and pass.

**CI consumer check** (`node scripts/consumer-check.mjs`): passes (exit 0). Every assertion about what these
packages control holds: client 0.3.0 installed from its tarball, the SDK within `^1.7.0`, one `@appport/protocol`
module. It reports one ✗, duplicated `@appport/*` copies in the whole graph. That comes from the published FeltKit
0.3.22's own pins, and the identical ✗ appears on unmodified 0.3.3. The script reports it without failing, by design.

## Versions

`@appport/resolver-core` 0.2.0, `@appport/resolver-client` 0.3.0, `@appport/resolver` 0.4.0. Not published. The server
now links the workspace client: 0.3.3 pinned the published client 0.2.3, so the CLI could not use client features
of this workspace.
