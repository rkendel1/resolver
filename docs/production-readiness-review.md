# Resolver: production readiness, integration and architecture review

Date: 2026-10-30. Scope: `rkendel1/resolver` at `48c115b` (branch `claude/laughing-cray-ry8nnj`), plus the fixes
in this change. I read every source file in `packages/*/src` and checked each claim against code or a test.
The reference implementations were AppPort Services (`rkendel1/appport-services` `29f438b`), FeltKit
(`rkendel1/feltkit` main), FeltDB (`@feltdb/core` 0.16.1 and `rkendel1/flow_db`), and Stack-Agent PR #77.
Where a statement rests only on reading code, not on a test I ran, it says so.

**Verdict.** The core model is sound: references, revisions, conditional commits, grants, custody and tenant
isolation. The review found eight reproducible defects, all fixed and covered by tests in this change. Four
of them were in the client cache and revocation paths and could keep serving revoked or changed values
indefinitely. Resolver is ready for a **single-instance** production deployment once the P0 items in section
4 are done: health checks and logs, vault key rotation or KMS custody, a backup procedure, and an agent
origin allowlist. It is **not** ready for several instances behind a load balancer; section 3.3 gives the
plan.

## Update 2: multi-instance operation and hardening (starting from `e39fe19`)

**Question: is Resolver now safe to deploy as several instances behind a load balancer?**

**Yes, with these conditions:**
- a FeltDB server for state;
- the vault on a directory every instance mounts (or a custody that keeps versions);
- the same keys on every instance;
- `RESOLVER_MULTI_INSTANCE=1`;
- the load balancer health-checking `/_resolver/ready`.

The evidence is two-instance tests that pass, not documentation:

1. **Real processes, real FeltDB server.**
   - **What runs:** two `resolver serve` processes over one `feltdb-server` (the Rust server from
     rkendel1/flow_db, built at `e505fc3`) and one vault directory.
   - **Scenario:** your full acceptance scenario, steps 1–13.
   - **Interruption:** step 12 freezes the FeltDB server with SIGSTOP, and B returns 503 and serves nothing
     stale. Then FeltDB resumes and B catches up.
   - **Restore:** into a fresh FeltDB server and vault, followed by an integrity check.
   - **SSRF:** a check that internal destinations are unreachable through either instance.
   - **Where:** `multi-process.test.ts`, "FeltDB server". **Manual integration:** run here with
     `FELTDB_SERVER_BIN`. CI cannot fetch the private flow_db repository.
2. **The same scenario in CI.** It runs on every push with local state opened shared by two processes
   (`multi-process.test.ts`, "local state"). **Automated.**
3. **Sync scenarios 1–9, fault injection and restarts.**
   - 12 tests against two runtimes on one FeltDB handle; **automated**.
   - 7 of those again against the real FeltDB server; **manual integration**.
   - Including 48 concurrent writes through both instances, delivered to every watcher in per-reference
     order, exactly once (`sync.test.ts`).
4. **Flakiness check.** Every multi-instance test passed three repeated runs (100/100 each) with the
   FeltDB server enabled. Full suite with the FeltDB server: 157/157. Browser suite: 11/11.

**What remains true and must be accepted, or addressed, before relying on it:**
- **Notification delay.** Instances learn of each other's changes by polling: watchers are notified
  within one sync interval (measured p50 487 ms, max 994 ms at 1 s). Reads are never behind.
- **KMS custody is not shipped or tested.** The supported shared custody is the vault on a shared POSIX
  mount. That mount's own durability and locking semantics (NFS or EFS) are outside what was tested here;
  the tests used one local filesystem.
- **O2 is still open.** Superseded secret versions stay revealable through pins until the reference is
  revoked.
- **The verifier key must never be lost.** Losing it invalidates every API key; that recovery path is not
  tested.
- **Open items unchanged:** licence, publishing and the PR into `main` (P0.6).

### What changed

| Item | Status | Evidence |
|---|---|---|
| **O1 multi-instance**, P0 | **Done.** | [docs/multi-instance.md](multi-instance.md) |
| ↳ Change sequence | A change sequence numbered inside the existing FeltDB transactions (no second source of truth). | `store.ts` |
| ↳ Sync loop | A per-instance loop that never advances past unprocessed changes (`sync.ts`), with `db.revision()` as the change detector on the FeltDB server. | `sync.ts` |
| ↳ Shared sessions | Management sessions in FeltDB. | `ui/router.ts` |
| ↳ Removed grants | Grant removals numbered in the sequence; every instance ends the subject's watch streams. | `store.ts` |
| ↳ Shared vault | A vault safe for several processes. | `vault.ts` |
| ↳ Startup checks | Topology checks at startup. | `runtime.ts` |
| ↳ Tests | Two-instance tests for every scenario. | test (CI); manual (FeltDB server) |
| **O3 SSRF**, P0 | **Done.** [docs/outbound-ssrf.md](outbound-ssrf.md) | test: 49 cases, plus the cross-process case |
| ↳ Policy | Explicit allowlist, with production failing closed. | `outbound.ts` |
| ↳ Address checks | Every resolved address checked at connect time (rebinding-safe), every redirect hop checked, WebSocket disabled for verification. | `outbound.ts` |
| ↳ Trust boundary | Rollbacks re-checked against today's policy. | test |
| **Backup and recovery**, P0 (plan P0.5) | **Done.** [docs/backup-restore.md](backup-restore.md) | test: 8 cases, plus the cross-process restore |
| ↳ Commands | `resolver backup`, `restore` and `verify`: state, then vault, with a manifest. | `backup.ts`, `cli.ts` |
| ↳ Revision-to-version link | Seal ids link revisions to exact vault versions. | `vault.ts` |
| ↳ Restore safety | Restore refuses incomplete, tampered or mismatched input and reports integrity problems. | test |
| **O5 health, readiness, logs**, P1 | **Done.** | test |
| ↳ Endpoints | `/_resolver/health`, plus `/_resolver/ready` with state, sync, custody, config and integrity checks. | `runtime.ts` |
| ↳ Logs | JSON-line logs with request id, operation, code, reason, instance, revision and duration; nothing sensitive. | `log.ts` |
| **O4 vault key rotation**, P1 | **Done.** [docs/vault-key-rotation.md](vault-key-rotation.md) | test: 5 cases |
| ↳ Rotation | Key ids in sealed versions, previous keys accepted, `resolver vault rotate` (resumable, safe under traffic), format-1 migration. | `vault.ts` |
| O9 grant changes reach clients | **Done:** removed grants end the subject's streams, and a broken stream invalidates the client cache. | test |
| O2, O6, O7, O8, O10, O11 | Open, unchanged. O6's sign-in throttle is now per instance. | — |

### New defects found and fixed in this work

| ID | Severity | Defect | How found | Status |
|---|---|---|---|---|
| D9 | **Critical (pre-existing)** | **Resolver could not use a FeltDB server at all.** Revision ids had the form `<hash>.<n>`, and the FeltDB server accepts only `[A-Za-z0-9_-]` in ids, so every write failed with `VALIDATION_ERROR`. The README documented `RESOLVER_FELTDB_URL`, but it had never been run against a real server. | The first run of the sync tests against `feltdb-server` | Fixed: ids are now `<hash>-<n>`, and reads fall back to the old form for existing local state. **test** (FeltDB server) |
| D10 | High (pre-existing) | **A client could hang indefinitely.** When the resolver's state store hung, `ResolverClient` never returned. `timeoutMs` bounded discovery's HTTP request, but not the WebSocket handshake after it. | Acceptance step 12 | Fixed: the client enforces its own deadline on connecting and on every call, and closes a late connection. **test** + **manual** |
| D11 | High (introduced here, before commit) | **Out-of-order notifications.** An instance announced its own commits before earlier commits by other instances reached it, so a watcher could see revision 10 before revisions 2–9. | The concurrent two-instance test | Fixed: all notifications flow through the sequence; a commit triggers an immediate pass. **test** |
| D12 | Medium (pre-existing; O9) | **Removed access did not reach clients.** A removed grant, or a live stream ended by key revocation, left clients serving cached values until the TTL. | Acceptance step 7 | Fixed. **test** + **manual** |

### Ecosystem boundaries (reviewed, nothing new built)

- **FeltKit: Resolver stays optional.** Resolver accepts any AppPort Services `SecretCustody` (`custody`
  option), so a FeltKit host can supply its own custody instead of Resolver owning it. **code**
  - FeltKit's credential custody is hard-wired today (`feltkit/packages/sdk/src/runtime/runtime.ts:153`,
    `credentials.ts:460`, verified by inspection). An integration needs FeltKit to accept an injected
    custody, as section 3.5 says; nothing in Resolver changes for that.
  - Fail-closed production with declared references, and development without Resolver, remain FeltKit-side
    work (section 3.5). Not built; nothing here blocks it.
- **API-key management stays with AppPort Services.**
  - Resolver uses AppPort Services' `ApiKeyService`; it does not reimplement keys.
  - The Access page still creates, lists and revokes keys alongside grants (O11).
  - **Recommendation, as a separate PR:** reduce the Access page to Resolver grants, and link key lifecycle
    to the AppPort Services keys page. Not done here, to avoid unrelated product changes.
- **Security headers for AppPort Services.**
  - Resolver's pages send a hash-based CSP, `frame-ancestors 'none'`, `no-store`, `nosniff` and
    `no-referrer`; AppPort Services' pages send no CSP (side-by-side review, code inspection).
  - **Recommendation, as a separate PR in rkendel1/appport-services:** adopt the same `renderPage` header
    set. Not done here.

### Evidence summary

```bash
npm run build && npx tsc -p tsconfig.base.json --noEmit          # clean
npm test                                                          # 16 files: 149 passed, 8 skipped (the FeltDB-server variants)
FELTDB_SERVER_BIN=…/feltdb-server npm test                        # 157 passed (manual integration: the real server)
npm run test:browser                                              # 11 passed
```

| Test file | Covers |
|---|---|
| `sync.test.ts` | multi-instance scenarios 1–9, fault injection, gaps, duplicates |
| `multi-process.test.ts` | the acceptance scenario with real processes |
| `outbound.test.ts` | SSRF |
| `backup.test.ts` | recovery |
| `rotation.test.ts` | key rotation |
| `vault.test.ts` | the vault shared by several processes |
| `ops.test.ts` | health, readiness, logs, shared sessions, client deadline, startup checks |

The original review follows, unchanged except where marked.

---

## 1. Current-state assessment

| Area | Status | Evidence |
|---|---|---|
| Reference identity; kind and schema fixed at creation | Works | `resolver.ts` `#put` refuses a kind change or a later schema. Test: `security.test.ts` "fixes kind and schema at creation". |
| Atomic revision and current-binding promotion | Works | `store.ts` `commit`: one FeltDB transaction holding the revision row (`requireAbsent`) and the reference row (`ifVersion` or `requireAbsent`). |
| Optimistic concurrency | Works | `expectedRevision` is checked before the commit and enforced by `ifVersion` inside it. Test: "lets exactly one of concurrent writers win". Concurrent **secret** writes were broken (D4, fixed). |
| Pinning and rollback | Server works. Client was broken (D1, fixed). | A rollback is a new revision, and its restored binding is re-validated (`#rollback` calls `#checkTargets`). |
| Revocation | Server is total and immediate. Client pins and live cache were broken (D1, D2, fixed). Failed destruction could not be retried (D5, fixed). | `resolve` refuses a revoked reference before applying any pin. Tests: `security.test.ts`, `audit.test.ts`. |
| Grant enforcement | Works on every operation | `#require` runs on every method. `list` and `watch` filter per reference and per event. Grants are never cached (`authorizer.ts`). |
| Tenant isolation | Works | Ids hash `tenant\0ref`. Grants, reveals and history filter by tenant. AppPort Services scopes API keys by the caller's tenant (`api-keys/service.js` `revokeApiKey` → `resolveTenant`). The vault's AAD binds the tenant. New test: "cross-tenant attempts". |
| Secret custody | Works with the caveats below | AES-256-GCM per version with AAD (tenant, secret, version). Material never reaches FeltDB (tested). Superseded versions are kept (O2). There is no key rotation (O4). |
| API keys and sessions | Works | `isLive` re-checks the key on every call and every watch chunk. UI sessions do the same, plus idle and absolute timeouts. Test: "a revoked key stops working at once". |
| Weighted selection | Works and is deterministic | FNV-1a with pinned vectors (`core.test.ts` "hashes identically everywhere"). Steering is the same on client and server. |
| Failover | Works | `withFailover` tries the selection first, then the rest by weight (`live.test.ts`). Errors are classified as authoritative (`NOT_FOUND`, `FORBIDDEN`, `UNAUTHORIZED`, `INVALID_INPUT`, `CONFLICT`: they evict the cache) or transport (served from last-known-good, bounded by `maxStaleSeconds`). |
| Client cache and staleness | **Was broken, now fixed** (D1–D3) | See the defect register. |
| Watch reconnection | Works by revalidating, not resuming | On every reconnect the client invalidates everything it holds. There is no event cursor (O8). Test: "recovery after a resolver restart". |
| AppPort discovery and contracts | Works | Every operation is an AppPort capability with a JSON Schema input. Discovery grants nothing: every capability requires a key and then a grant (`security.test.ts`). |
| Management UI | Works; minor findings | Strict CSP, cookie and session rules, CSRF checks. 11 API tests and 11 browser tests (axe at 1280 and 640 px, light and dark). See 3.4. |
| Performance (measured, memory state) | Adequate | Network resolve 0.59 ms average; cache hit 1.7 µs; `list` of 1,000 references 17 ms (one grant lookup per reference). |

---

## 2. Defect register

Every **fixed** defect has a test in `packages/server/test/audit.test.ts` that failed before the fix and
passes after it, except D3, which was found by reading the code; its fix is described below.

| ID | Severity | Defect | Reproduction | Status |
|---|---|---|---|---|
| D1 | High | **Pinned resolutions survived revocation and grant removal on the client, indefinitely.** `resolve(ref, { revision })` was cached under `ref#N` with no expiry, and `#apply` cleared only `ref`. Revoking a leaked credential did not stop clients that pinned it. | `client: revocation reaches pinned resolutions` (live and TTL variants). Both failed: the pinned value kept resolving. | Fixed: pins are cached like current results, invalidated by change events, and deleted on revocation. |
| D2 | High | **A live client ignored the TTL.** While the stream was up, a cached result was served forever. A missed notification therefore meant indefinite staleness, revocation included, and with two resolver instances a client never saw a change made through the other one. This contradicted the README ("until a change notification arrives or the TTL passes"). | `a change made through another resolver instance is seen within the TTL` returned `'old'`. `a revocation made through another instance…` kept resolving. | Fixed: the TTL always bounds a cached result, and live notifications only make changes arrive sooner. Cost: one revalidation per reference per TTL (30 s by default). |
| D3 | Medium | **Two races in the client could lose a notification.** (a) A fetch in flight when an event arrived was cached as valid when it finished, carrying the old binding. (b) The client marked its cache invalid as soon as it opened the stream, before the server had subscribed, so a change in between was missed. With D2 these were unbounded; after D2 they are bounded by the TTL. | Found by reading the code. A deterministic test needs control over response timing that the AppPort SDK does not expose. | Fixed: a per-reference generation and a reconnect epoch, so a result fetched across an event is stored as invalid. The server now sends a heartbeat as soon as `watch` subscribes, and the client revalidates again on that first chunk. |
| D4 | High | **Concurrent secret writes broke the committed secret.** Both writers stored material in custody before committing; the loser's version stayed in the vault, referenced by nothing. With a custody that holds one version (typical of KMS-backed custody), the winner's committed revision could no longer be revealed at all. | `concurrent secret writes leave the committed revision revealable…` failed with "the secret could not be opened". | Fixed: writes to one reference are serialized in process, so the loser fails its revision check before touching custody. This holds per process only (see O1). |
| D5 | Medium | **A failed destruction on revoke could never be retried.** `revoke` committed the revoked state and then called `custody.remove`. If removal failed, the material stayed, and every later revoke returned "already revoked" without retrying. | `a revocation whose destruction failed can be retried…`: custody status stayed `set`. | Fixed: revoking an already-revoked secret retries the destruction, then still answers CONFLICT `resolver.revoked`. A failed removal now says what happened and how to retry. |
| D6 | Low | **UI key creation was not atomic.** `POST /_resolver/keys` created the key and then added its grants. An invalid grant left a key whose secret was never shown, and a non-array `grants` returned 500. | `an invalid grant creates no key`: the key count went up. | Fixed: every grant is validated (`checkGrant`, shared with `resolver.grant`) before the key is created. |
| D7 | Medium | **In-memory runtimes shared state within a process.** FeltDB memory instances with the same namespace share data, and every `{ memory: true }` runtime used `namespace: 'resolver'`. The test suite's isolation depended on test order, and two embedded resolvers in one process saw each other's references. This was found when a new test failed because an earlier test had revoked the same name. | `two memory runtimes in one process do not share state`. A standalone script also confirmed the FeltDB behaviour. | Fixed: each memory runtime gets its own namespace. |
| D8 | Low | Management API hygiene: (a) `...error.details` was spread after `code` and `message` and could overwrite them; (b) the `sessions` and sign-in `attempts` maps were never swept; (c) the sign-out cookie lacked `Secure`. | Found by reading the code (the UI review reported (b) as well). | Fixed. |

### Open findings (not fixed in this change)

| ID | Severity | Finding | Why it is not fixed here |
|---|---|---|---|
| O1 | **Blocks multi-instance** (**fixed in Update 2**) | Change notifications (`EventEmitter`), the vault's write queue and the D4 serialization are all in process. FeltDB local mode defaults to `access: 'exclusive'` (`owner.lock` with `O_EXCL`), so a second process on the same directory fails fast with `STATE_LOCKED` (read from `db.d.ts`/`db.js`; not run). That protects state, but a shared vault directory has no such guard. | Needs an architecture decision (3.3). |
| O2 | Medium | Rotating a secret keeps the old version, and anyone with `reveal` can still read it through a pinned revision. A rotated leaked key stays readable until the whole reference is revoked. | Needs a contract decision: a `retire` operation, or not keeping superseded versions. See plan P1.2. |
| O3 | Medium (**fixed in Update 2**) | **SSRF.** Writing an `agent` binding makes the resolver discover any origin the writer names (`targets.ts` `checkAgent`), including internal addresses. Only principals with `write` can trigger it. | Needs a configuration contract: `targets.agentOrigins` allowlist (P0.4). |
| O4 | Medium (**fixed in Update 2**) | There is no vault key rotation. The vault file format carries no key id, and there is no re-seal tool. | P0.3. |
| O5 | Medium (**fixed in Update 2**) | There are no health or readiness endpoints and no structured logs or metrics. The server logs nothing. | P0.1. |
| O6 | Low | The sign-in throttle keys on the socket address, so behind a proxy everyone shares one bucket. There is no general rate limit on `/_resolver/*` (AppPort Services applies 120/min). The Origin check compares against the raw `Host`. The cookie is not `__Host-`. | Proxy trust needs a configuration contract (P1.5). |
| O7 | Low | `/v1/ui` shows authenticated callers only the overview, because AppPort filters by the session's `permissions` (`resolver.call`), not by the capabilities each page declares. AppPort Services behaves the same way. | It is a platform-level contract; fix it in both places together (P1.6). |
| O8 | Low | `watch` has no resume cursor. Recovery is "revalidate everything on reconnect", which is correct but costs O(cached references). | FeltDB's TS client has no resumable feed (3.3). |
| O9 | Low (**fixed in Update 2**) | Grant changes emit no change events, so a removed grant reaches clients after at most the TTL. | Acceptable now that the TTL is enforced (D2). |
| O10 | Low | History and reveal records grow without bound, with no retention policy. History is append-only in use but not tamper-evident (already documented). | P1.4 and P2. |
| O11 | Low | The Access page duplicates AppPort Services' API-key lifecycle: create, list and revoke the same keys. | P1.6. |

---

## 3. Architecture assessment

### 3.1 Boundaries (confirmed, keep)

- **AppPort** carries discovery and invocation. All 13 operations are capabilities. The management UI's JSON
  API (`/_resolver/*`) calls the same `Resolver` methods with the same grants; it is not a second authority.
- **AppPort Services** owns API keys, verified principals and the custody contract. Resolver only re-checks
  liveness and adds per-reference grants, which AppPort Services does not model.
- **FeltDB** is the only durable state. Secret material is never a FeltDB field.
- **Resolver** owns logical identity, bindings, selection and resolution. It never proxies traffic and never
  grants anything at the target.

### 3.2 Reference-to-reference dependencies

**What exists.** The only edge in the model is `model.credential → secret`. Endpoints carry no secret
references (credential-looking headers are refused), and agents and values carry none. At write time, a
model's credential must exist, be a `secret` and be active, and the same check runs again on rollback.

**Cycles cannot occur.** The only edge points at a `secret`, and secrets have no outgoing edges. A cycle
detector would guard nothing.

**What could go wrong when dependencies change independently:**

| Change | Behaviour |
|---|---|
| Credential rotated | Correct. `client.model()` reveals the credential's *current* revision, which is what a rotation intends. |
| Credential revoked while models still name it | Models keep resolving, and `client.model()` fails with `resolver.revoked` when it reveals the credential (tested). Before this change, nothing told the operator which models were affected. |
| Model pinned to an old revision whose credential was revoked | Fails on reveal, as above. |
| Model retargeted while a credential reveal is in flight | The pair stays consistent, because the credential is resolved by name and not by the model's revision. |

**Smallest contract, implemented here.** No graph storage and no new capability:

1. **Impact on revoke.** `revoke` returns `dependents`: the active models whose current binding names the
   revoked reference, limited to those the caller may read (tested both ways). It is derived from bindings
   when needed, so it can never drift out of sync.
2. **Receipts for consumed versions.** `client.model()` now returns `credentialRevision` alongside `ref` and
   `revision`. An application can log exactly which model revision and credential revision a call used.
   Server-side, every reveal is already recorded with principal, revision and custody version.

**Not recommended now:** stored dependency edges, a multi-reference snapshot API, or server-side
consumption logs for non-secret resolutions. None of them has a use case the single edge does not already
cover. Revisit when a second edge kind appears, for example an endpoint credential: then add
`resolver.dependents(ref)` as a read capability, computed the same way.

### 3.3 Several resolver instances

**What FeltDB provides.** This comes from a code read of `@feltdb/core` 0.16.1 and the FeltDB server; it is
not exercised by tests.

| Mode | Cross-process change signal | Resume cursor |
|---|---|---|
| memory | none (single process) | — |
| local file | `exportOperations(sinceSequence)` sees other processes' commits through the shared journal (a replication transport, unbounded) | yes, `sequence` |
| remote (FeltDB server) | `GET /revision` (cheap staleness check). SSE `/v1/events` with `Last-Event-ID` and `/v1/public/events/replay`, server side. | Server: yes. **The TS client sends no cursor** and only reports `resource`. |

Rows carry only a per-record `__version`; there is no global sequence. Inferred and not run: `/transactions`
writes may carry no `resource`, in which case TS `subscribe()` callbacks would never fire for Resolver's
transactions.

**Recommendation.** No sidecars and no new infrastructure.

1. **Supported topology now: one resolver process per state.** Use a FeltDB server, or local state with
   backups. The local file runtime's exclusive lock already refuses a second process.
2. **Several instances, step 1, using existing primitives only:**
   - **State:** a shared FeltDB server (remote mode).
   - **Custody:** a shared KMS-backed `SecretCustody`, not the local vault directory.
   - **Propagation:** each instance polls `db.revision()`, for example every second, and when it changes
     reads `resolver_revisions` newer than its high-water mark. Use an overlap window of a few seconds on
     `at` and de-duplicate by row id, because wall clocks are not a sequence. It then emits locally to its
     own watchers.
   - **Worst cases:** cross-instance propagation takes poll interval plus query time, and the TTL bounds
     everything (D2).
   - **Revocation:** consistent across clients within that bound. For emergency revocation, keep secret
     TTLs short.
   - **D4 serialization:** becomes "the loser fails the conditional commit after storing". With a versioned
     custody that leaves an orphan version, so the custody needs a conditional or idempotent store, or a
     post-failure cleanup.
3. **Step 2, when FeltDB's TS client exposes the server's cursor-resumable SSE:** replace the poller with
   that feed and give `resolver.watch` an optional `after` cursor. Then a reconnecting client resumes
   instead of revalidating everything.
4. **During a state-store outage:**
   - Reads and writes fail with `INTERNAL_ERROR`, which clients treat as transport failure: they serve
     last-known-good for up to `maxStaleSeconds`.
   - Authoritative answers are never replaced by cached ones.
   - Writes fail closed.

### 3.4 Management UI consistency with AppPort Services

This compares the two side by side. The items marked *reported* come from that comparison and were not
re-checked individually.

- **Same:**
  - Stack UI 0.3.0, with identical `SHA256SUMS` and a test that checks them.
  - The same inline-document renderer and the same components: Shell, PageHeader, DataTable with loading,
    empty and error-with-Retry states, ErrorPanel, Form, Select, StatusIndicator.
  - The same `AppPort/ui/1` contribution shape, validated with the protocol's own validator.
  - The same `{error:{code,message}}` envelope; Resolver adds `reason`.
- **Resolver is stricter, and AppPort Services should adopt this:**
  - a per-page CSP with hashes, `frame-ancestors 'none'`, `no-store`, `nosniff` and `no-referrer`
    (*reported*: AppPort Services pages send no CSP);
  - a test that the page can see no storage or cookies.
- **Fixed here:** D6, D8.
- **Align next (P1.6):**
  - Fold Resolver's API-key sign-in and session into one platform convention, with AppPort Services owning
    identity.
  - Add `basePath` support so a shell can mount the pages under a prefix (*reported*).
  - Build navigation from what is mounted (*reported*).
  - Add a busy state on the sign-in form (*reported*).
  - Adopt AppPort Services' horizontal-overflow and dialog axe browser checks (*reported*).
  - Link the Access page's key lifecycle to AppPort Services' API-key page instead of duplicating it. Keep
    grants, which are Resolver's domain.

### 3.5 FeltKit

Facts from `rkendel1/feltkit`:

- `npm create feltkit` copies a starter (`tasks` or `managed`) and asks no questions.
- Configuration comes from environment variables only.
- Credentials go through `HostCredentials`, which is an AppPort Services `SecretCustody`. A
  `credential-ref:<id>` is resolved from `FELTKIT_CREDENTIAL_<ID>`, then a dev vault.
- Models are stored data in AppPort Services Intelligence.
- `feltkit deploy` collects the credential refs into `.env.example`, `DEPLOY.md` and `target.json`.
- FeltKit pins the same `@appport/*`, `@appport/services` 0.9.1 and `@feltdb/core` 0.16.1 as Resolver, so
  there is no version conflict.
- Nothing in FeltKit mentions Resolver.

Recommendation: **Resolver is an optional integration that uses FeltKit's existing seams, with no new handler
API.**

1. **Credentials (standard seam, optional use):**
   - A `ResolverCredentials` custody that answers `credential-ref:ref://…` through `client.secret()`, with an
     environment variable still taking precedence so an operator can always override.
   - Needs one FeltKit change: `credentialsFor()` (`runtime/runtime.ts:153`) must accept an injected custody,
     and the credential id pattern must admit `ref://`.
   - Webhooks, Intelligence and integrations then work unchanged.
2. **Models:**
   - An `agent.decisions` factory that calls `client.model(ref, { key: principal })` and hands the result to
     the existing provider runtime. The receipt (`revision`, `credentialRevision`) goes into FeltKit's
     activity log.
3. **Endpoints and values:**
   - `baseUrl: { ref }` with `withFailover`.
   - An optional, read-only `ctx.services.resolver.get(ref)`.
4. **Environments:**
   - Development and test need no Resolver; refs resolve from literals or the local vault, so `npm run dev`
     is unchanged.
   - Production with declared refs requires `RESOLVER_URL` and `RESOLVER_API_KEY`, fails closed at startup,
     and reports through readiness.
   - Refs are written per environment (`ref://<env>/<app>/…`), matching FeltKit's one-instance-per-environment
     model.
5. **Least privilege at deploy time:**
   - `feltkit deploy` lists the declared refs.
   - It prints the exact `resolver keys create <app>-<env> --grant read:… --grant read,reveal:<secret refs>`
     command.
   - The key is supplied as a secret variable. FeltKit never sees an admin key.
6. **When Resolver is unavailable:**
   - Applications use the client's `maxStaleSeconds`, with `onWarning` sent to FeltKit's logger and to a
     readiness `warn`.
   - Revoked, forbidden and not-found answers become FeltKit's existing `CREDENTIAL_UNAVAILABLE` or
     `CONFIGURATION` errors.
   - Nothing falls back silently.
7. **Managed versus self-hosted:** the same client either way. Only the URL and key differ.
   - `create` should not provision references automatically.
   - At most, a `--resolver` flag adds the dependency and a commented configuration block.

### 3.6 AppPort and agents

- **Sufficient today:**
  - discover (`resolver.list`, filtered by grants);
  - resolve with steering and pins;
  - history;
  - permitted changes (`put`, `rollback` and `revoke`, all conditional);
  - watch;
  - failure explanation: every error carries a stable `details.reason` (`resolver.revoked`,
    `resolver.stale-revision`, `resolver.credential-missing`, …) and, on a refusal, a `decisionId`.
- **Authority boundaries hold:**
  - Discovery (`/.well-known/appport`) lists capabilities, but every call needs a key and then a grant
    (tested).
  - A caller that may not read a reference cannot tell whether it exists (tested).
  - Resolving an agent returns an origin and pins. The agent authorizes its own callers.
- **Not recommended:** a "request a change for approval" capability inside Resolver. That would overlap a
  platform approval flow. An agent with `write` on a pattern changes references directly; without it, it
  proposes changes through whatever approval system the platform adopts.
- **Pins:**
  - Resolver checks pinned capability digests at write time (`targets.ts`).
  - Stack-Agent re-checks them before every call (rkendel1/stack-agent#77, **merged**).
  - Remaining gap: an agent that changes its contract *after* the write is caught by Stack-Agent at call
    time, not by Resolver. That is acceptable, because the consumer-side check is the authoritative one.
  - The SSRF item O3 applies to this write-time check.

---

## 4. Prioritized plan

**P0: before the first production deployment (single instance)**

| ID | Item | Depends on |
|---|---|---|
| P0.1 | `/healthz` (process) and `/readyz` (FeltDB reachable, custody `status` reachable). Structured JSON logs for writes, reveals, auth failures and grant changes, never with material. Counters for resolve, hit and error. | — |
| P0.2 | Write down and enforce the supported topology: one process, local exclusive state or a FeltDB server, vault directory not shared. | — |
| P0.3 | Vault key rotation: add a `kid` to the sealed version, keep the old key read-only, provide a `resolver vault rotate` re-seal, and document migrating to a KMS-backed `SecretCustody`. | — |
| P0.4 | Agent origin allowlist (`targets.agentOrigins`); refuse private address ranges unless allowed. | — |
| P0.5 | Backup and restore procedure covering state and vault together, with a restore test. | P0.3 |
| P0.6 | Decide the open items: licence, npm publishing, the PR into `main`. | — |

**P1: hardening and integration**

| ID | Item | Depends on |
|---|---|---|
| P1.1 | Several instances via `db.revision()` polling plus revision-row catch-up (3.3, step 2), with a shared KMS custody. | P0.1, P0.3 |
| P1.2 | Secret version retirement: `put` with `retirePrevious`, or a `resolver.secret.retire(ref, upToRevision)` capability. Pins to retired versions fail with `resolver.revoked`. | — |
| P1.3 | FeltKit integration (3.5): the custody injection seam in FeltKit first, then the optional `ResolverCredentials` and decisions factory. | P0.6 (publishing) |
| P1.4 | Retention for reveal records and an export for history. | — |
| P1.5 | Proxy-aware client identity (a configured trusted-proxy list), a general management rate limit, and `__Host-` cookies under HTTPS. | — |
| P1.6 | UI convergence with AppPort Services (3.4), including the shared `/v1/ui` capability filtering fix (O7). | coordinated with AppPort Services |

**P2: when there is demand**

- A cursor-resumable `watch` once FeltDB's TS client exposes resumable events.
- A `resolver.dependents` capability once a second dependency edge exists.
- Tamper-evident history (hash-chained revision rows).
- Per-tenant quotas.

---

## 5. Fixes in this change

| File | Change |
|---|---|
| `packages/client/src/client.ts` | TTL always bounds the cache (D2). Pins share the same cache path and invalidation (D1). Generation and epoch guard against in-flight fetches (D3a). Revalidation on the first stream chunk (D3b). `credentialRevision` added to `ResolvedModel`. |
| `packages/server/src/app.ts` | `watch` sends a heartbeat as soon as it subscribes (D3b). |
| `packages/server/src/resolver.ts` | Per-reference write serialization (D4). Destruction retried on re-revoke, with an explicit error (D5). `checkGrant` exported (D6). `dependents` on revoke (3.2). |
| `packages/core/src/protocol.ts` | `WriteResult.dependents?` (additive). |
| `packages/server/src/runtime.ts` | Unique namespace per memory runtime (D7). |
| `packages/server/src/ui/router.ts` | Atomic key creation with grants (D6). Envelope order, map sweeping, `Secure` on the sign-out cookie (D8). |
| `packages/server/test/audit.test.ts` | 12 tests: the reproductions above plus cross-tenant, dependency, two-instance and restart-recovery evidence. |
| `README.md` | Caching semantics, revocation retry, `dependents`, `credentialRevision`, and new limits. |

**Compatibility.** Every API change is additive. One behaviour changes: live clients now revalidate each
reference once per TTL, which is what the README already promised. Clients from before this change keep
working against this server, because they ignore the extra heartbeat.

---

## 6. Test evidence

```bash
npm run build                          # tsc -b: clean
npx tsc -p tsconfig.base.json --noEmit # 0 errors (sources and tests)
npm test                               # 9 files, 61 tests passed
npm run test:browser                   # 11 tests passed (Chromium, axe light/dark, 1280/640 px)
```

Before the fixes, `npx vitest run packages/server/test/audit.test.ts` failed 7 of 8: the two D1 tests, the
two D2 tests, D4, D5 and D6. The restart-recovery test passed. D7 surfaced as a failure in a later test that
inherited state, and has its own test now.

Failure modes covered, with the file that covers each:

| Failure mode | Test file |
|---|---|
| Concurrent writes, plain and secret | `security`, `audit` |
| Revocation under cache, pins and watch | `security`, `audit` |
| Secret rotation and destruction, including failed destruction | `security`, `audit` |
| Cross-tenant attempts | `security`, `audit` |
| Model and credential consistency, and revoked dependencies | `live`, `audit` |
| Weighted determinism | `core`, `live` |
| Failover | `live` |
| Outage and last-known-good | `resilience` |
| Restart and recovery | `resilience`, `audit` |
| Two instances over one state | `audit` (cross-instance changes bounded by TTL) |
| UI security and browser behaviour | `ui`, `pages.browser` |

Measured on the development container with memory state: resolve over the network 0.59 ms average; cache
hit 1.7 µs; listing 1,000 references 17 ms.

---

## 7. Remaining risks that prevent production use

1. **Several instances are unsafe today (O1).** Run exactly one resolver process per state until P1.1 is
   done.
2. **No observability or readiness probes (O5).** An operator cannot tell a degraded resolver from a healthy
   one (P0.1).
3. **The vault key cannot be rotated (O4),** and the vault directory must be backed up together with state
   (P0.3, P0.5).
4. **SSRF through agent discovery (O3)** for principals with `write` (P0.4).
5. **Rotated secrets stay revealable through pinned revisions (O2).** After a leak, revoke the reference
   instead of rotating it, until P1.2 is done.
6. **Not published, no licence, not merged** (P0.6).
