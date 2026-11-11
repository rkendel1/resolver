# Resolver: the next milestone

_Design as approved; the implemented guarantees and remaining limitations are in [governance-guarantees.md](governance-guarantees.md) once implementation lands._

**Consumer registration, resolution observability, and enforced mutation authority.**

Status: **approved design; implementation in progress** (rkendel1/resolver, branch `claude/youthful-thompson-bhqeox`). Grounded in `@appport/resolver` at `c674d14` (0.3.3). File and line
references are to `packages/server/src` there. Motivated by Resolver Control's gap register
(`docs/PLATFORM-GAPS.md`, R1 and R4).

## The problem in one paragraph

Resolver resolves references, and Resolver Control governs changes to them. Neither knows which running
applications depend on a reference: impact analysis relies on declarations a person typed. Neither can
guarantee that a governed change is the only way a reference changes: any key with `write` changes it
directly, and Resolver Control can only *detect* that afterwards (an out-of-band revision without its tag).
Both gaps belong to Resolver. They concern what Resolver itself observes and what it accepts at its own
mutation boundary, so no application can close them from outside.

## What already exists, and what does not

Read from the code, not the README.

| Need | Today | Where |
|---|---|---|
| Who is calling | Every call has a verified principal (an AppPort Services API key) | `app.ts:84-106` |
| A record of resolutions | **Logs only**: every call writes a JSON log line with principal, ref, revision | `app.ts:108` |
| A durable record of use | **Secrets only**: every reveal is a row (principal, revision, custody version, decision id) | `store.ts:110` `RevealRecord`; `resolver.ts:517-540` |
| Connected consumers | The `resolver.watch` stream is per verified principal, held open with heartbeats | `app.ts:136-146` |
| Change notifications to running consumers | **Exist and work.** Watch stream plus client cache invalidation. Proven by Resolver Control's e2e: a consumer process switched models within seconds under the same pid | `client.ts` `#watchLoop`, `#apply` |
| One write boundary | `put`, `rollback` and `revoke` each run `#require(write)`, then the stale-revision check, then `#commit`, under a per-reference serial lock | `resolver.ts:246-350, 542` |
| Atomic multi-row commit | `store.commit` writes the revision (`requireAbsent`), the reference (`ifVersion`) and the sequence in one FeltDB transaction | `store.ts:175-210` |
| Contracts | **Partial**: `agent` targets pin capability digests (checked at write); `value` references fix a JSON Schema at creation | `kinds.ts` `AgentTarget`; `resolver.ts` `#put` schema |
| A principal above grants | The host **operator** bypasses every grant | `authorizer.ts` `isOperator` |

Two consequences shape the design:

1. **Resolver cannot see which target a consumer selected.** Weighted steering runs in the client from the
   cached binding (`client.ts` `#steer`), so the server learns the *binding revision* a consumer resolved,
   not whether it landed on `stable` or `canary`. Selection can only be reported by the client.
2. **The server sees resolutions at TTL granularity.** A client serves its cache until a notification or the
   TTL (`client.ts` `#current`). "Last resolved" is accurate to the reference's TTL, not to the request.

## The five facts

These are different facts, recorded separately, never collapsed into one status:

| Fact | Meaning | Who establishes it | Trust |
|---|---|---|---|
| **Declared** | The consumer says it depends on the reference | the consumer, at registration | asserted |
| **Registered** | Resolver knows the consumer exists and is alive | Resolver, from a registration plus liveness | principal verified; application and instance names asserted |
| **Resolved** | The consumer obtained a resolution of a given revision | **Resolver observes it** in `resolve` | verified (the only fact Resolver sees itself) |
| **Used** | The consumer used the resolved target, with an outcome | the consumer reports it | asserted |
| **Verified** | A check confirmed the target works at some level | a verifier (milestone after this) | as strong as the verifier |

Every record states which fact it is and whether it is observed or asserted. A declared dependency that is
never resolved is itself a finding (stale declaration). A resolution with no declaration is another
(undeclared consumer).

---

## P0-1 Consumer registration

**Identity.** A consumer is a verified principal (its API key), which Resolver already authenticates on
every call, plus an asserted application, environment and instance. One key may run many instances.

**Capabilities** (new, `resolver.consumers.*`, same AppPort host and gateway mapping as today's):

| Capability | Input | Authorization |
|---|---|---|
| `resolver.consumers.register` | `{ application, environment, instance, dependencies: [{ ref, contract? }] }` → `{ registrationId, expiresAt }` | any principal of the tenant. Each declared `ref` must be readable by the caller (`decide(read)`), or it is refused per ref: a key cannot claim dependencies it cannot resolve. |
| `resolver.consumers.update` | `{ registrationId, dependencies }` | the registering principal |
| `resolver.consumers.deregister` | `{ registrationId }` | the registering principal |
| `resolver.consumers.list` | `{ ref? , application? }` | `read` on each listed reference (rows filtered, as `list` does today) |

**Liveness without a new heartbeat.** A registered client already holds the `resolver.watch` stream with
heartbeats. Passing `registrationId` on `watch` makes the open stream the liveness signal. A registration
whose stream has been closed longer than its grace period (default 2 × the longest TTL among its
dependencies) expires to `stale`, then `expired`. Expired rows are kept for history, not deleted.

**Storage.** `resolver_consumers`: one row per registration, with principal, application, environment,
instance, declared dependencies, `registeredAt`, `lastSeenAt` and state. It is written in its own small
transaction, never in a reference commit.

**Client.** `ResolverClient.connect({ …, consumer: { application, environment, instance?, dependencies? } })`
registers on connect (and again after a reconnect), passes the id on `watch` and `resolve`, and deregisters on
`close()`. `dependencies` defaults to the references the client resolves; an explicit list is the declared set.
Old clients keep working with no registration: their resolutions are still recorded under their principal.

## P0-2 Resolution observability

**Where.** In `Resolver.resolve` (`resolver.ts:~95`), after authorization, for every outcome:
`ok`, `revoked`, `not_found`, `forbidden`. A refused resolution matters: it is how an undeclared or
misconfigured consumer shows up. A `forbidden` outcome reveals nothing about the reference (it is recorded
for the tenant, visible to admins only, as today's denials are).

**What is recorded.** Not one row per request: that would multiply writes by request rate. Instead, an
aggregate keyed by `(tenant, principal, registrationId?, ref, revision, outcome)`:
`{ firstAt, lastAt, count, lastCorrelationId }`. One row per consumer per revision per outcome is exactly
what impact analysis and adoption tracking need. A write happens when the key is new, or when `lastAt` is
older than a coalescing window (default 60 s) in this instance's memory, so write volume is bounded by
(consumers × references × revisions), not by traffic. Counts are therefore lower bounds and say so.

**Never recorded:** secret material, selected target values, endpoint headers, the `key` steering input
(it may be a user id), or request payloads.

**The reveal log stays** as the record of material access. A resolution with reveal writes both.

**Used.** `resolver.consumers.report { ref, revision, label?, outcome: succeeded|failed, at }`, sent by the
client when it is told. `withFailover` reports per target tried; `model()` exposes a `report()` callback. It
is asserted, rate-limited like resolutions, and carries the selected `label`, which is the only way the
selected target becomes known.

**Read side.** `resolver.consumers.of { ref }` returns, per consumer, the five facts side by side:
declared?, registration state and last seen, resolved revisions with last time and outcome, last reported
use. This is the read Resolver Control's impact analysis switches to. From the same rows:

* **Adoption** of a change: the share of live consumers whose latest resolution is at or after revision N.
  That is the missing half of "change notifications": delivery already works, and *adoption* becomes
  observable.
* **Unused** references: no resolution within a window.
* **Undeclared** consumers: resolutions without a declaration.
* **Stale** declarations: declared, never resolved.

## P0-3 Enforced mutation authority

**Principle.** Resolver Control decides (proposals, impact, approvals). Resolver enforces the decision at its
own mutation boundary, for every client: CLI, SDK, MCP, HTTP, management pages and the operator. Resolver
does not run approvals and does not call Resolver Control at write time, so it keeps working, and keeps
refusing, when Resolver Control is down.

**Mutation policy**, per tenant and reference pattern (stored in `resolver_policies`, managed with `admin`):

```text
pattern: ref://prod/*
require: change-authorization
issuers: [ { id: "resolver-control", publicKey: "ed25519:…" } ]
operations: [ put, rollback, revoke ]        # secrets: see Decisions
maxValidity: 3600                            # seconds an authorization may live
```

A reference with no matching policy behaves exactly as today. Direct writes stay possible wherever policy
permits them.

**Change authorization.** A compact signed document (JWS, EdDSA) that the issuer creates when a change is
approved:

```json
{
  "iss": "resolver-control", "jti": "chg_mwcmus1x225811a9d949-a1",
  "tenant": "acme", "ref": "ref://prod/ai/default",
  "op": "put", "expectedRevision": 1,
  "bindingDigest": "sha256:…",
  "approvals": [ "linus" ], "decision": "CHG-1",
  "nbf": 1794430836, "exp": 1794434436
}
```

* `bindingDigest` is the SHA-256 of the **normalized** binding: `checkBinding`'s output in a canonical JSON
  form defined in `@appport/resolver-core`, so the issuer and Resolver compute the same digest from the same
  code. A rollback binds `toRevision` instead. A revoke binds neither.
* It is bound to the reference, operation, expected revision and exact binding. It cannot authorize
  anything else.

**Enforcement point.** One private method, called by `#put`, `#rollback` and `#revoke` after `#require(write)`
and the stale check, before `#commit`. It does five things:

1. Finds the policy for the ref. If there is none, it returns.
2. Requires `PutInput.authorization` (a new optional field on put, rollback and revoke).
3. Verifies the signature against the policy's issuers, `nbf`/`exp` within `maxValidity`, and that tenant, ref, op and expected revision match the request.
4. Recomputes the digest of the binding *Resolver is about to commit* and compares it.
5. On any mismatch, throws `FORBIDDEN` with reason `resolver.authorization-required` or `resolver.authorization-invalid` (new `REASONS`), and records the denial.

**Single use, atomically.** `store.commit` gains one more write in the same FeltDB transaction:
`resolver_authorizations/<tenant>:<jti>` with `requireAbsent: true`. A replayed authorization fails the
transaction like a stale revision. No nonce service, no window between check and use.

**Evidence.** The revision row gains `authorization: { issuer, jti, decision }`. `history` returns it. This
is the authoritative link between Resolver's revision and Resolver Control's change record, replacing today's
convention of a tag in `reason`. Resolver Control keeps the business record and points at the revision.

**The operator.** Today `isOperator` bypasses every grant. Under a policy, the operator is refused like
anyone else, unless it passes `breakGlass: { reason }`. Break-glass writes commit with
`authorization: { breakGlass: true, reason }`, write an authority record (`resolver_authority`) so every
instance and client sees it, and are what Resolver Control reports as the most severe finding.

**Key management.** Issuer public keys live in the policy row. Rotation means adding the new key, then
removing the old one: both are accepted in between. The private key stays with the issuer: Resolver
Control's component credential, next to its Resolver API key, never in state.

---

## How Resolver Control changes when this ships

| Today | After |
|---|---|
| `consumers` collection, declared by people | Kept for annotation, while impact reads `resolver.consumers.of`: declared, registered, resolved and used, each labelled by Resolver |
| Verification checks a `[resolver-control CHG-n …]` tag in `reason` | Checks `authorization.jti` on the revision |
| Out-of-band writes detected after the fact | On governed patterns they are refused. What remains to report: writes on ungoverned patterns, and break-glass |
| "Propagation: within TTL" stated as a guarantee | Adoption measured: N of M live consumers on the new revision |
| The executor key needs `write` on prod | Still needs it. Without a valid authorization, `write` is not enough on a governed pattern. A leaked executor key alone can no longer change prod |

## Deliberately not in this milestone

* An approval workflow, UI or policy engine in Resolver (Resolver Control's, or AuthBoundry's).
* Delivery acknowledgements for notifications: adoption from resolution records answers the same question
  without a second protocol.
* Dependency contracts beyond today's agent pins and value schemas (P1, next milestone). Registration already
  carries an optional `contract` per dependency so the data has a place.
* The verification framework (P1). The "Verified" fact has its column but no producer yet.
* Resolution intelligence (P2): it reads these records. Nothing new in Resolver.
* The AppBoundry companion-process gap (Resolver Control's A1). It is a separate execution-platform item,
  tracked separately.

## Approved decisions, and what they mean in the code

1. **Secrets under policy.** A secret write needs an authorization bound to the reference, op `put-secret`, the
   expected revision and its constraints (`kind`, `ttlSeconds`). It is never bound to the material. Secret values
   never enter an authorization, the consumed-authorization row, a revision's evidence, a governance event or a
   log line.
2. **Operator break-glass, explicit only.** Under a policy the operator is refused like any key unless it passes
   `breakGlass: { reason }` (non-empty). The revision records `governance: { breakGlass: true, reason, actor }`.
   A row is written to `resolver_governance_events` in the **same transaction**. The change event every watcher
   receives carries `governance: "break-glass"`. An API key passing `breakGlass` is refused: only the host
   operator holds it. There is no silent bypass: `isOperator` no longer short-circuits a governed mutation.
3. **Offline Ed25519 change authorizations.**
   - **Format:** compact JWS (`header.payload.signature`, base64url), header `{ alg: "EdDSA", typ: "resolver-change+jws", kid }`.
   - **Claims:** `v`, `iss`, `jti`, `tenant`, `ref`, `op` (`put` | `put-secret` | `rollback` | `revoke`), `expectedRevision`, `digest`, `iat`, `nbf`, `exp`, and optionally `decision` and `approvers`.
   - **Digest:** the SHA-256 of a canonical JSON of the normalized request. For `put` that is kind, schema, `checkBinding`'s output and ttlSeconds. For `put-secret`, kind and ttlSeconds. For `rollback`, toRevision. For `revoke`, nothing. It comes from one function in `@appport/resolver-core`, so issuer and verifier cannot disagree.
   - **Signing keys:** `resolver_signing_keys`, each with a key id (`kid`), issuer, Ed25519 public key and state. `active` verifies. `retired` verifies only tokens issued (`iat`) before its retirement: rotation without breaking in-flight approvals. `revoked` verifies nothing, including tokens issued before.
   - **Verification:** local, with no network call.
   - **Consumption:** a `resolver_authorizations` row keyed by (tenant, issuer, jti) is written with `requireAbsent` in the same FeltDB transaction as the revision.
   - **Replay resistance:** a token cannot be replayed against another reference, revision, tenant, operation, binding or ttl, because each is a signed claim compared with the request. It cannot be used twice because of consumption.
   - **Revision binding alone already prevents re-use:** revisions only increase, so a committed token's `expectedRevision` can never match again. Consumption adds the authoritative token→revision record, and closes the window where two writers present one token concurrently.
4. **Resolution recording on by default.** Observed resolution facts (`resolver_resolutions`, written by Resolver)
   and asserted usage (`resolver_usage`, reported by consumers) are separate collections. They are never merged
   into one status.
5. **Adoption as a lifecycle.** `resolver.adoption { ref, revision? }` reports, for one revision:

   | Stage | Meaning | Source |
   |---|---|---|
   | **authorized** | the authorization that admitted it, or break-glass, or ungoverned | the revision's `governance` + `resolver_authorizations` |
   | **committed** | the revision exists: actor, time, sequence number | `resolver_revisions` |
   | **available** | served as current from its commit until superseded or revoked | the revision rows |
   | **fetched** | consumers Resolver *observed* resolving this revision or a later one | `resolver_resolutions` (observed) |
   | **adopted** | consumers that *reported* using it | `resolver_usage` (asserted) |
   | **functionally verified** | not produced in this milestone: `null`, with the reason | (verification framework, next milestone) |

   Notification delivery is not a stage. A watch event says a change exists; only a resolution says a consumer
   fetched it, and only a report says it used it.

### Further rules the code requires

* **Trust roots are host-level.** Policies and signing keys are managed by the operator only: CLI on the state
  host (`resolver policy …`, `resolver signing-key …`, like `resolver vault rotate`), with a required reason,
  each change a governance event. An API key with `admin` can neither weaken a policy nor add a key: otherwise
  it could disable governance and write.
* **One policy decides.** For a reference and operation, the most specific matching policy applies: exact name,
  then longest prefix, then `*`. Its issuers are the keys trusted.
* **The commit loop distinguishes consumption from contention.** `store.commit` retries when only the sequence
  moved. A conflict on the authorization row is reported as a consumed authorization, never retried as
  contention.
* **Recording never blocks resolution.** A failure to record a resolution is logged and counted. The resolution
  is still served: observability does not reduce availability.

## Acceptance tests (against a real Resolver, as today's suites are)

* A put on a governed pattern without an authorization is refused (`FORBIDDEN`). It is refused for an API key
  with `write`, for the CLI, over MCP, from the management pages, and for the operator without break-glass.
* A valid authorization succeeds once. Replaying it fails atomically, including two concurrent writers on two
  instances sharing state.
* An authorization for binding A does not admit binding B. A wrong ref, op, revision or expired authorization
  is refused. Each is a distinct reason.
* The revision carries the authorization, and `history` returns it. Break-glass is recorded and announced to
  watchers.
* No policy means today's behaviour, byte-for-byte. All existing suites pass unchanged.
* A registered client's resolutions appear as rows under its registration. An unregistered client's appear
  under its principal. Outcomes ok, revoked, not found and forbidden are each recorded.
* Write volume stays bounded: N resolves within the coalescing window cost at most one write per key per
  instance.
* Nothing recorded contains secret material, a selected value, a steering key or a header value
  (scan, as Resolver's security suite does today).
* A closed watch stream makes a registration stale, then expired. Reconnecting revives it.
* `consumers.of` shows the five facts separately: declared-not-resolved, resolved-not-declared, used with a
  label.
