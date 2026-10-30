# Running several resolver instances

How several resolver instances behind one load balancer share their state and secret custody, what each
instance does on its own, how stale anything can be, and what happens when something fails.

Evidence tags used below: **[test]** verified by an automated test in this repository; **[manual]**
verified by a manual integration run (recorded in `production-readiness-review.md`); **[code]** supported
by code inspection only.

## Topology

```
                         load balancer (health: /_resolver/ready)
                     ┌────────────┴────────────┐
              resolver A                  resolver B          … any number, no affinity required
                     │  reads and conditional writes, per request
                     ▼
              FeltDB server  (the single source of truth: references, revisions, the change sequence,
                     │        grants, reveals, API keys, management sessions)
              shared vault directory (sealed secret versions only; ciphertext)
```

- **State:** one FeltDB server (`RESOLVER_FELTDB_URL`). Every instance uses the same namespace
  (`resolver`). Local state opened with `RESOLVER_STATE_SHARED=1` also works, but only for several
  processes on one host, because it relies on file locks in one directory. **[test]**
- **Custody:** the vault, on a directory every instance mounts (NFS, EFS, or a shared volume with POSIX
  `link` and `rename` semantics). Alternatively, any `SecretCustody` that keeps versions and implements
  `withSecretVersion` and `discardVersion` (for example, a KMS-backed custody). **[test]** for the vault;
  other custodies are not verified.
- **Keys:** every instance gets the same `RESOLVER_VAULT_KEY` (plus `RESOLVER_VAULT_PREVIOUS_KEYS` during a
  rotation) and the same `RESOLVER_VERIFIER_KEY`, from the secret manager.
- **`RESOLVER_MULTI_INSTANCE=1`** makes an instance refuse to start with any of the following **[test]**:
  - memory state;
  - local state that was not opened shared;
  - custody that keeps only one version.

There is no Redis, broker or coordination service. FeltDB already provides what is needed, as the next
section shows.

## What is shared and what is not

| Concern | Where it lives | Cross-instance behaviour |
|---|---|---|
| References, revisions, grants, reveals, API keys | FeltDB | Every request reads FeltDB, so a change through A is visible to B's next request. Measured: B's read 2 ms after A's commit returned the new value. **[test]** **[manual]** |
| Write ordering | FeltDB conditional transactions | `expectedRevision` is enforced by `ifVersion` in the same transaction as the revision row and the sequence number. Two writers on two instances cannot both win. **[test]** |
| Change notifications to watchers | Each instance, fed by the change sequence | See "Synchronization" below. **[test]** **[manual]** |
| Management UI sessions | FeltDB (`resolver_sessions`) | Only a token hash and the key id are stored. Any instance serves a session, and revoking the key or signing out ends it everywhere. **[test]** |
| Secret versions | Shared vault directory | Versions are published with `link` (fails if taken), so concurrent writers get distinct versions. A loser's version is discarded, and removal writes a tombstone first. **[test]** |
| Sign-in throttle (10 per minute per address) | Each instance | The effective limit is 10 × the number of instances. This is documented, not shared. **[code]** |
| AppPort WebSocket sessions | Each instance | Each is bound to its own connection. Nothing needs sharing. **[code]** |

## Synchronization

FeltDB's TypeScript client offers no resumable change feed:
- `db.revision()` says whether anything changed, but not what.
- The FeltDB server's SSE cursor is not exposed to TypeScript.

So the resolver numbers its own changes, inside the transactions it already runs.

- **The change sequence.** `resolver_meta/sequence` holds the last number. Every revision commit and every
  grant removal writes `seq + 1` together with its row, conditional on the sequence row's version. A
  conflict on the sequence alone (another reference changed at the same moment) is retried. A conflict on
  the reference is a stale write. Because the number and the row commit together, no number is ever
  skipped or used twice. **[test]**
- **Per-instance position.** Each instance keeps `applied`, the highest number up to which it has
  notified its watchers of every change. A pass runs every `RESOLVER_SYNC_INTERVAL_MS` (default 1000),
  and immediately after a commit on that instance:
  1. Ask FeltDB whether anything changed: `db.revision()` on the FeltDB server, or a read of the sequence
     row where revision validation is not offered.
  2. Read the rows numbered above `applied`, in order, and notify watchers of each.
  3. Advance `applied` by one after each row is handled.
- **Properties:**
  - **Monotonic:** `applied` only moves forward. **[test]**
  - **Never past unprocessed changes:** a failed pass leaves `applied` where it was, and a pass that fails
    halfway keeps only what it delivered. **[test]**
  - **Idempotent:** numbers at or below `applied` are skipped, so duplicate rows notify once. **[test]**
  - **One order everywhere:** an instance's own commits are delivered through the same pass, not announced
    first. That ordering bug was found and fixed during this work. With 48 concurrent writes through two
    instances, every watcher on both received every revision, per reference in order 1–16, exactly once.
    **[test]** (shared handle and real FeltDB server)
  - **Gaps:** a missing number (which a correct FeltDB never produces) is waited for (10 s). After that,
    the instance ends every watch stream, so clients revalidate everything they hold, and then moves on.
    Nothing is skipped silently. **[test]**
  - **Restarts:** a starting instance begins at the current end of the sequence. Its clients revalidate on
    connect, so nothing before needs replaying, and it serves the current state at once. **[test]**
    **[manual]**
- **Authority changes.** Removing a grant is numbered in the same sequence. Every instance ends that
  principal's watch streams, its clients revalidate, and they get `FORBIDDEN`. A client whose live stream
  ends for any reason also revalidates everything on next use. **[test]** **[manual]**

## Maximum expected staleness

With defaults: sync interval 1 s, reference TTL 30 s, heartbeat 15 s.

| What | Bound | Evidence |
|---|---|---|
| A request to any instance after a commit on another | none: it reads FeltDB | **[test]** **[manual]**: 2 ms |
| A watcher on another instance learning of a change | sync interval + one query. Measured p50 487 ms, max 994 ms at a 1 s interval (FeltDB server, 20 trials). | **[manual]** |
| A live client's cached value | the notification delay above; at most its TTL if the notification is lost | **[test]** |
| A client without a live connection | the reference's TTL (pinned resolutions included) | **[test]** |
| A removed grant, for a live client | the notification delay (its stream is ended) | **[test]** **[manual]** |
| A revoked API key | refused by every instance on the next request; a live stream ends within one heartbeat (≤ 15 s); cached results last at most the TTL | **[test]** |
| A revoked reference | the notification delay for live clients; the TTL otherwise | **[test]** **[manual]** |

For emergency revocation of a secret, keep secret TTLs short (`--ttl`). The TTL is the bound that holds
when every notification path has failed.

## Failure behaviour

| Failure | What happens | Evidence |
|---|---|---|
| FeltDB server unreachable or hung | Requests fail: reads cannot be served stale, and writes fail closed. `/_resolver/ready` returns 503 within 2 s. Health stays 200. Sync stops advancing. Clients serve their last known good result for at most `maxStaleSeconds`, then fail. When FeltDB returns, sync resumes from `applied` and delivers everything, in order. | **[manual]** (SIGSTOP on a real FeltDB server); **[test]** with fault injection |
| Sync failing while reads still work | `applied` is held; after 10 s without a successful pass, readiness is 503 (`checks.sync`) so the load balancer drains the instance. | **[test]** |
| An instance crashes mid-write | The FeltDB transaction either committed (revision, reference and sequence number together) or did not. A secret version stored for an uncommitted write remains as an orphan; `resolver verify` reports it. | **[code]**; orphan reporting **[test]** |
| Two instances write the same secret at once | One commit wins and the other gets `CONFLICT`. The loser's vault version is discarded, and both instances reveal the winner. | **[test]** **[manual]** |
| The vault directory is unusable | Readiness returns 503 (`checks.custody`). Reveals fail with `resolver.custody-unavailable`. | **[test]** |
| A client cannot reach a hung resolver | Every call, including connecting, fails within the client's `timeoutMs` (default 5 s) as a transport error. This bug was found and fixed: the WebSocket handshake after discovery had no deadline. | **[test]** **[manual]** |

## Load balancer and deployment

- **Health check:** `GET /_resolver/ready` (200 or 503, with a JSON report). Use `GET /_resolver/health`
  for liveness. No session affinity is needed.
- **Rolling upgrade:** start new instances (they become ready after their first sync), then drain old
  ones. Change notifications from an instance draining mid-stream end the stream, and clients reconnect to
  another instance and revalidate. **[code]**
- **Logs:** JSON lines on stdout (`RESOLVER_LOG_LEVEL`).
  - Each line carries `instance`, `requestId`, `operation`, `code`, `reason`, `durationMs`, `tenant`,
    `principal`, `ref` and `revision`.
  - Sync logs `sync.started`, `sync.failed`, `sync.recovered` and `sync.gap-resynced`.
  - Never logged: inputs, bindings, secrets, keys, cookies or error messages. **[test]**

## Configuration

| Variable | Meaning |
|---|---|
| `RESOLVER_FELTDB_URL`, `RESOLVER_FELTDB_TOKEN` | the FeltDB server |
| `RESOLVER_MULTI_INSTANCE=1` | check the topology at startup |
| `RESOLVER_VAULT_DIR` | the shared vault directory |
| `RESOLVER_VAULT_KEY`, `RESOLVER_VAULT_PREVIOUS_KEYS`, `RESOLVER_VERIFIER_KEY` | from the secret manager; the same on every instance |
| `RESOLVER_SYNC_INTERVAL_MS` | default 1000 |
| `RESOLVER_INSTANCE_ID` | name in logs and readiness |
| `RESOLVER_ENV`, `RESOLVER_OUTBOUND_*` | see [outbound-ssrf.md](outbound-ssrf.md) |
| `RESOLVER_VERIFY_ON_START=1` | integrity check at startup (after a restore) |
