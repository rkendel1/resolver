# Resolver

**DNS for everything that changes.** An application names what it needs, `ref://prod/chat/model`, and
resolves it at run time. Change which model, provider, key, endpoint or agent that name points to, and every
running application follows: **no redeploy, no restart.**

```ts
const resolver = await ResolverClient.connect({ url: process.env.RESOLVER_URL, apiKey: process.env.RESOLVER_API_KEY });

const model = await resolver.model('ref://prod/chat/model', { key: user.id });
// { provider: 'anthropic', model: 'claude-sonnet-5-5', apiKey: '…', options: { temperature: 0.2 }, revision: 7 }
```

Operations retarget the alias; the next call gets the new target:

```bash
resolver set ref://prod/chat/model --value '{"provider":"anthropic","model":"claude-sonnet-5-5","credential":"ref://prod/llm/anthropic-key"}' --reason "cost review"
```

It solves the problems an alias solves for models (teams stuck on old versions, cost changes needing a
deploy, nobody sure which model to use) for every value an application depends on, with traffic steering,
revisions, rollback and an audit trail.

## What it resolves

| Kind | A reference points to | Checked when it changes |
|---|---|---|
| `model` | `{ provider, model, endpoint?, credential?, options? }` | provider and model against the AppPort Services intelligence catalog; credential must be an active `secret` reference; no credential in `options` |
| `secret` | an API key, token or password | write-only; material goes to the vault, never into state, history, logs or errors |
| `endpoint` | `{ url, headers? }` | http(s), no embedded credentials, no credential-looking headers |
| `agent` | `{ origin, application?, capabilities? }` | the origin is discovered over AppPort; every pinned `name@version → sha256:…` capability digest is recomputed from the served manifest and must match |
| `value` | any JSON (config, feature flags, limits) | against a JSON Schema fixed when the reference is created |

A reference's kind (and schema) never changes; only what it is bound to.

## Traffic steering

A binding is one target, a weighted split, or a failover list:

```bash
# 90/10 canary, sticky per user
resolver set ref://prod/chat/model --binding '{"strategy":"weighted","targets":[
  {"value":{"provider":"openai","model":"gpt-4o","credential":"ref://prod/llm/openai-key"},"weight":90,"label":"stable"},
  {"value":{"provider":"anthropic","model":"claude-sonnet-5-5","credential":"ref://prod/llm/anthropic-key"},"weight":10,"label":"canary"}]}'

# failover: try in order
resolver set ref://prod/payments/endpoint --kind endpoint --binding '{"strategy":"failover","targets":[
  {"value":{"url":"https://primary.payments.example"},"label":"primary"},
  {"value":{"url":"https://secondary.payments.example"},"label":"secondary"}]}'
```

- **Weighted.** With a `key` (user, tenant, session), the same key always gets the same target while the
  weights are unchanged. Promote a canary by changing the weights; set a weight to 0 to drain a target.
  Selection runs in the client from the cached binding, so steering costs no request.
- **Failover.** `resolver.withFailover(ref, use)` calls `use` with each target in order until one succeeds.
- **Pinning.** `resolve(ref, { revision: 4 })` returns the binding exactly as it was at revision 4, for a
  team that must not move. The result says which revision is current, so the team can see it is behind.

## How changes reach running applications

```
 operator / CI ──resolver.put──▶ ┌──────────────────────┐ ◀──resolver.resolve── application
                                 │ resolver (AppPort)   │ ───resolver.watch───▶ (live stream)
                                 │ grants, steering     │
                                 └───┬──────────┬───────┘
                         FeltDB      │          │      vault (AES-256-GCM, outside FeltDB)
            references, revisions,   ▼          ▼      secret material only
            grants, reveals, API keys, evidence
```

1. A write is checked (authorization, kind, schema, catalog, agent contract), then committed: the new
   revision row and the reference's current row in one FeltDB transaction, conditional on the revision the
   writer read. Two writers basing a change on the same revision cannot both win.
2. The resolver streams a change notification (name and revision only) to every connected client allowed to
   read that reference, in that tenant.
3. The client drops its cached result; the next call re-resolves with the client's own authority.

A cached result is used until a notification arrives or its TTL (default 30 s) passes, whichever comes
first: the live stream makes changes arrive sooner, and the TTL bounds how long a missed notification (a
reconnect, another resolver instance) can go unnoticed. Pinned resolutions are cached the same way, so a
revocation or a removed grant reaches them too. On every (re)connect the client revalidates everything it
holds. If the resolver is unreachable, the client serves the last known good result for at most
`maxStaleSeconds` (default 300; 0 fails closed) and reports it through `onWarning`. Authoritative answers
(revoked, forbidden, not found) are never covered by the cache: revocation reaches running applications.

## Security model

- **Authentication.** Every call needs an API key from AppPort Services (`ApiKeyService`: salted scrypt
  verifiers with a server-held key mixed in, rotation, revocation). An unauthenticated caller can do nothing.
- **Authorization: deny by default.** Grants give a principal `read`, `reveal`, `write` or `admin` on a
  pattern (`ref://prod/payments/*`). A caller that may not read a reference cannot tell whether it exists.
  Grants never cross tenants and are checked on every request (a removed grant applies at once).
- **Secrets.** `read` shows a secret's metadata (custody pointer and version); only `reveal` returns
  material, and every reveal is recorded (who, revision, custody version, decision id), never the material.
  Material lives in the vault, sealed per version with the tenant, secret and version as authenticated data.
  The vault implements AppPort Services' `SecretCustody`; plug in a KMS-backed custody the same way.
- **Revocation is total.** A revoked reference fails every resolution, pinned or not; revoking a secret
  destroys its material (if custody fails, revoking again retries the destruction). A revoked name is never
  reused. The response lists the active models that still name a revoked credential (`dependents`).
- **Changes are recorded.** Every revision keeps its binding, actor and reason. History is append-only in use
  (rows are written once and never updated), but it is not tamper-evident: an administrator of the state store
  can edit rows.
- **Resolution grants nothing at the target.** Resolving an agent or endpoint returns where it is; the target
  still enforces its own authorization.

## Quick start

```bash
npm install @appport/resolver @appport/resolver-client

npx resolver init --tenant acme          # prints the first admin API key once
npx resolver serve --port 4300           # keeps state, keys and the vault in ./.resolver

export RESOLVER_URL=http://127.0.0.1:4300 RESOLVER_API_KEY=<admin key>
printf '%s' "$OPENAI_API_KEY" | npx resolver set ref://prod/llm/openai-key --kind secret --secret-stdin
npx resolver set ref://prod/chat/model --kind model \
  --value '{"provider":"openai","model":"gpt-4o","credential":"ref://prod/llm/openai-key"}'

# a key for the application: read its references, reveal its credential
npx resolver keys create chat-app --grant read:ref://prod/chat/* --grant read,reveal:ref://prod/llm/*
```

The `.resolver` directory holds `vault.key` and `verifier.key` (mode 0600). In production, supply them as
`RESOLVER_VAULT_KEY` and `RESOLVER_VERIFIER_KEY` from your secret manager, and use a FeltDB server for state
(`RESOLVER_FELTDB_URL`, `RESOLVER_FELTDB_TOKEN`).

### CLI

| Command | |
|---|---|
| `resolver init [--dir D] [--tenant T]` | create keys and the first admin API key |
| `resolver serve [--dir D] [--port P] [--host H]` | run the resolver (configuration: [Deployment](#deployment)) |
| `resolver backup <dir>` / `restore <dir>` / `verify` | state and vault together; integrity check ([runbook](docs/backup-restore.md)) |
| `resolver vault rotate` | re-seal every version under `RESOLVER_VAULT_KEY` ([procedure](docs/vault-key-rotation.md)) |
| `resolver get <ref> [--key K] [--revision N] [--reveal]` | resolve (reveal: print a secret) |
| `resolver set <ref> [--kind K] (--value JSON \| --binding JSON \| --secret-stdin) [--schema JSON] [--reason R] [--ttl S]` | create or change |
| `resolver history <ref>` / `rollback <ref> <revision>` / `revoke <ref>` | revisions |
| `resolver list [prefix]` / `watch [prefix]` | browse, follow changes |
| `resolver keys create <name> [--grant actions:pattern]...` / `keys list` / `keys revoke <id>` | API keys |
| `resolver grant <principal> <actions> <pattern>` / `grants` / `ungrant <id>` | grants |

### Client

| | |
|---|---|
| `ResolverClient.connect({ url, apiKey, live?, maxStaleSeconds?, timeoutMs?, onWarning? })` | |
| `get(ref, { key? })` | the selected value |
| `resolve(ref, { key?, revision? })` | everything: kind, revision, binding, selection, TTL |
| `model(ref, { key? })` | a model target with its credential revealed as `apiKey`; `revision` and `credentialRevision` say exactly what was used |
| `secret(ref)` | secret material (needs `reveal`), held in memory for the TTL only |
| `withFailover(ref, use, { key? })` | try targets in order |
| `watch(refs, listener)` | change notifications |
| `put`, `set`, `history`, `rollback`, `revoke`, `list`, `grant`, `createKey`, … | management |

Any AppPort client can call the resolver directly: it is an AppPort application
(`/.well-known/appport`) with capabilities `resolver.resolve`, `resolver.put`, `resolver.watch`, …

### Agents with Stack-Agent

An `agent` reference with pinned capability digests gives Stack-Agent both the address and the pins:

```bash
resolver set ref://prod/agents/claims-review --kind agent \
  --value '{"origin":"https://claims.internal","capabilities":{"claims.review@1":"sha256:…"}}'
stack-agent work --appport "$(resolver get ref://prod/agents/claims-review | jq -r .selected.value.origin)" \
  --appport-pin "claims.review@1=sha256:…" ...
```

The resolver refuses a binding whose served contract differs from the pin, and Stack-Agent re-checks the
pin before every call (rkendel1/stack-agent#77).

## Management UI

`resolver serve` also serves management pages on the same port, built the way AppPort Services builds its
own: the vendored Stack design system (`vendor/stack-ui`, checked against `SHA256SUMS`) and one HTML
document per page.

| Page | Route | |
|---|---|---|
| Overview | `/resolver` | counts by kind, recently changed references |
| References | `/references` | browse by prefix and kind; a reference's binding, targets, history, rollback, revoke |
| Models | `/models` | model aliases: retarget, start a canary at N%, promote it |
| Secrets | `/secrets` | metadata and reveal log; set a new value, revoke. Material never reaches the page |
| Access | `/access` | API keys (shown once on creation) and grants |

Every page and the JSON API behind it (`/_resolver/*`) go through the same resolver methods and grants as
the AppPort API, so the UI can do exactly what the signed-in key may do.

- **Sign-in.** An operator signs in with an API key at `/resolver/sign-in` and gets an HttpOnly,
  SameSite=Strict session cookie (8 hours, 30 minutes idle). The page's script never sees the key or the
  session and keeps nothing in browser storage. Sign-in is limited to 10 attempts a minute per address. A
  revoked or expired key ends its sessions on the next request.
- **CSRF.** A cookie-authenticated change must carry a same-origin `Origin` and a JSON body.
- **CSP.** Each page admits only its own inline script and style (by hash), requests to its own origin, and
  no framing. Responses are `no-store`.
- **Host identity.** Embedding applications or an SSO proxy pass `management: { authenticate(request) }`
  (returning AppPort Services principal claims); `signIn: false` turns off API-key sign-in.
  `management: false` serves the AppPort API only.
- **Composition.** The pages are published as an AppPort UI contribution at `/v1/ui`, so an AppPort shell can
  place them in its navigation; anonymous callers see only the overview.

## Deployment

| Topology | State | Custody | Configuration |
|---|---|---|---|
| One instance | local (`.resolver/state`) or a FeltDB server | the vault in `.resolver/vault` | defaults |
| Several processes, one host | local, opened shared | the vault, one directory | `RESOLVER_STATE_SHARED=1 RESOLVER_MULTI_INSTANCE=1` |
| Several hosts behind a load balancer | a FeltDB server | the vault on a shared mount (or a versioned KMS custody) | `RESOLVER_FELTDB_URL=… RESOLVER_VAULT_DIR=… RESOLVER_MULTI_INSTANCE=1` |

Every instance gets the same keys from your secret manager: `RESOLVER_VAULT_KEY`,
`RESOLVER_VAULT_PREVIOUS_KEYS` (during a key rotation) and `RESOLVER_VERIFIER_KEY`. Point the load
balancer's health check at `GET /_resolver/ready` (200 or 503 with a JSON report: state, sync, custody,
config, integrity). `GET /_resolver/health` is liveness only. No session affinity is needed: management
sessions live in the shared state.

| Variable | Default | |
|---|---|---|
| `RESOLVER_ENV` | `production` | `production` fails closed on outbound requests; `development` allows any origin, `http:` and private addresses |
| `RESOLVER_OUTBOUND_ORIGINS` | none | origins agent discovery may contact (production: required for agent bindings) |
| `RESOLVER_OUTBOUND_PRIVATE_NETWORKS` | none | CIDRs allowed although not public |
| `RESOLVER_FELTDB_URL`, `RESOLVER_FELTDB_TOKEN` | local state | the FeltDB server |
| `RESOLVER_STATE_SHARED` | off | local state opened by several processes on one host |
| `RESOLVER_MULTI_INSTANCE` | off | refuse to start unless state and custody can be shared |
| `RESOLVER_VAULT_DIR` | `<dir>/vault` | |
| `RESOLVER_SYNC_INTERVAL_MS` | 1000 | how often an instance looks for changes made elsewhere |
| `RESOLVER_LOG_LEVEL` | `info` | JSON lines on stdout; `off` to silence |
| `RESOLVER_INSTANCE_ID` | host name and pid | |
| `RESOLVER_VERIFY_ON_START` | off | check state against the vault at startup; not ready on problems |

Operations, each with its tests and limits:

- [docs/multi-instance.md](docs/multi-instance.md): architecture, synchronization, maximum staleness,
  failure behaviour.
- [docs/backup-restore.md](docs/backup-restore.md): `resolver backup`, `restore` and `verify`; the
  recovery runbook.
- [docs/vault-key-rotation.md](docs/vault-key-rotation.md): `resolver vault rotate`.
- [docs/outbound-ssrf.md](docs/outbound-ssrf.md): the threat model and outbound configuration.
- [docs/production-readiness-review.md](docs/production-readiness-review.md): findings, evidence and the
  verdict.

## Built from

| Responsibility | Package |
|---|---|
| Transport, discovery, capability contracts, streams | `@appport/core`, `@appport/server`, `@appport/sdk`, `@appport/schema`, `@appport/authorization` |
| Contract digests for agent pins | `@appport/protocol` (`capabilityDigest`) |
| API keys, verified principals, the AuthBoundry decision contract, secret custody contract, model catalog | `@appport/services` |
| References, revisions, grants, reveals, keys: durable state and atomic conditional writes | `@feltdb/core` (local file, memory, or a FeltDB server) |
| References, kinds, bindings, steering (shared by server and client) | `@appport/resolver-core` (this repository) |
| Management pages | Stack design system (`@stack/ui` 0.3.0, vendored as AppPort Services does) |
| The vault, the grant policy, the resolver service, the CLI, the management UI | `@appport/resolver` (this repository) |

`@appport/services` 0.9.1 pins `@feltdb/core` 0.15.0; this workspace overrides it to 0.16.1 so one FeltDB
instance serves both, and the tests exercise the AppPort Services paths the resolver uses on it.

## Limits

- **Change notifications between instances poll.** An instance learns of another's changes within its
  sync interval (1 s by default; measured p50 0.5 s). Every request reads the shared state directly, so
  reads are never behind. See [docs/multi-instance.md](docs/multi-instance.md).
- **Superseded secret versions are kept** (so pinned revisions still reveal). Rotating a leaked secret does
  not destroy the old material; only revoking the reference does.
- **History is not tamper-evident.** Rows are written once, but nothing signs or chains them.
- **Steering is client-side.** A client that ignores the weights can pick any target it may read. Weights
  steer traffic; they do not authorize it.
- **Secrets reach the application.** An application with `reveal` holds the material in memory. For
  providers it never needs to see, keep the call inside a boundary that holds the credential.
- **Grants are per API key.** There is no group or role layer yet.
- **The vault is a directory.** Several instances share it on a mount with POSIX `link` and `rename`. Back
  it up with the state (`resolver backup`). A KMS-backed custody plugs in through `custody`, but none is
  shipped or tested here.
- **The sign-in throttle is per instance.** 10 attempts per minute per address, on each instance.

## Development

```bash
npm install
npm run build
npm test              # everything below except the browser suite (after `npm run build`: the cross-process test runs the built CLI)
npm run test:browser  # the management pages in Chromium: flows, CSP, axe in light and dark at 1280 and 640 px

# With a FeltDB server binary (rkendel1/flow_db `feltdb-server`), the multi-instance tests also run against it:
FELTDB_SERVER_BIN=/path/to/feltdb-server npm test
```
