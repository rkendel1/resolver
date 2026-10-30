# Outbound requests and SSRF

## Threat model

**Asset.** The resolver's network position. It often runs inside a private network, next to metadata
services (`169.254.169.254`), databases and admin endpoints.

**Attacker.** Any principal with a `write` grant on some reference pattern, or anyone who can get a
binding written: a compromised CI key, a malicious agent operator, a confused administrator.

**Vector.** The only request the resolver itself makes on a binding's behalf is **agent verification**.
When an `agent` binding is written or rolled back to, the resolver discovers its origin over AppPort
(`GET /.well-known/appport`, then the manifest) to check its pinned capability digests. A binding naming
`http://169.254.169.254` or `https://internal-admin:8443` would make the resolver send requests there.
The response would also shape the error the writer sees, which leaks a little about it.

| Path | Contacts the destination? | Evidence |
|---|---|---|
| `put` / `rollback` of `agent` bindings | yes: discovery and manifest | **[test]** every case below |
| `model` and `endpoint` bindings | no. The resolver validates them structurally; applications contact them | **[test]** (nothing reached the listener) |
| `resolve`, `watch`, `history`, `list` | no | **[code]** |
| Management UI | the same `put` / `rollback` paths | **[test]** through the cross-process acceptance test |

**Out of scope.** Applications contacting the endpoints and models they resolve: that is the
application's network policy. Resolving an agent grants nothing at the agent, which enforces its own
authorization.

## The control

Everything goes through `createOutboundPolicy` (`packages/server/src/outbound.ts`). Agent discovery has no
other way out:
- AppPort's discovery is given the policy's `fetch`;
- the WebSocket transport is disabled for verification, because a WebSocket would open its own connection
  outside the policy.

Every request and every redirect hop passes three checks, in order:

1. **URL.**
   - It is parsed by the WHATWG URL parser, the same one Node's HTTP stack uses, so there is no second
     interpretation.
   - Only `https:` is allowed, plus `http:` when permitted.
   - No user name or password, and no IPv6 zone ids.
2. **Origin.** The normalized origin must be in `allowedOrigins`, compared exactly: scheme, host and port.
3. **Address, at connect time.** The module resolves the host name itself.
   - Every address in the answer must be allowed. A mixed public-and-private answer is refused.
   - The socket connects to the address that was checked, through the `lookup` hook of `http.request`, with
     a fresh connection per request.
   - So there is no window for DNS to change between check and connect (rebinding).
   - An IP literal is checked as the address the parser normalized it to, so decimal, octal, hex, short
     forms and IPv4-mapped IPv6 are all caught.

**Allowed addresses.** Public unicast only, unless a range is listed in `allowPrivateNetworks`. Refused,
with the kind reported:
- unspecified, loopback, private (RFC 1918), shared address space (RFC 6598), link-local, multicast,
  reserved, documentation and benchmarking ranges;
- IPv4-mapped and IPv4-compatible IPv6, NAT64, 6to4, Teredo, ULA, site-local;
- anything outside `2000::/3`.

**Redirects.** AppPort's discovery client refuses them outright. If a caller asks the policy's `fetch` to
follow them, each hop is checked again, `Authorization` is dropped across origins, and at most
`maxRedirects` (3) are followed.

**The trust boundary.** A reference's own content can never widen the policy. Only the resolver's
configuration can, so rolling back to a historical binding is checked against today's policy. **[test]**

## Configuration

| `RESOLVER_ENV` | Without `RESOLVER_OUTBOUND_ORIGINS` | With it |
|---|---|---|
| `production` (default) | **nothing is contacted**: agent bindings are refused with `resolver.outbound-refused (outbound.not-configured)` | only those origins, `https:` only, public addresses only unless `RESOLVER_OUTBOUND_PRIVATE_NETWORKS` |
| `development` | any origin, `http:` allowed, any address | only those origins; private addresses allowed unless `RESOLVER_OUTBOUND_PRIVATE_NETWORKS` narrows them |

| Variable | Example |
|---|---|
| `RESOLVER_OUTBOUND_ORIGINS` | `https://claims.agents.example.com,https://10.20.0.7:8443` |
| `RESOLVER_OUTBOUND_PRIVATE_NETWORKS` | `10.20.0.0/16,fd00:20::/32` (trusted configuration: internal agents live here) |
| `RESOLVER_OUTBOUND_ALLOW_HTTP=1` | allow `http:` origins (not recommended in production) |

Invalid configuration is a **startup error**, never a silent fallback **[test]**:
- an entry that is not a bare origin;
- `http:` without permission;
- credentials in an entry;
- a malformed CIDR;
- an unknown environment.

`/_resolver/ready` reports `checks.config.outbound` as `disabled`, `restricted` or `open`.

Embedding: `createResolverRuntime({ environment, outbound: { allowedOrigins, allowPrivateNetworks, allowHttp } })`.
`targets.verifyAgents: false` turns verification, and so all outbound requests, off.

## Tests

`packages/server/test/outbound.test.ts` (49 cases):
- address classification across IPv4 and IPv6 special ranges, including mapped forms;
- production with no allowlist;
- invalid configuration;
- an allowed origin, and disallowed origins and schemes;
- loopback, private and metadata addresses written 14 ways;
- DNS answers that are private or mixed;
- rebinding (a second resolution to a disallowed address);
- redirects to private addresses and to other origins;
- redirect chains and their limit;
- malformed and unusual URLs (`user@host`, `#@`, suffix confusion, `file:`, `gopher:`);
- agent bindings at internal addresses refused on create;
- rollback to an internal origin refused;
- model and endpoint bindings never contacted.

In every case the internal listener receives no request. The cross-process acceptance test repeats the
agent case against two running instances.
