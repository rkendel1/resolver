/**
 * Outbound requests the resolver itself makes: today only discovering an `agent` binding's origin to
 * verify its pinned contracts (`targets.ts`). Models and endpoints are never contacted by the resolver.
 *
 * The trust boundary is the resolver's own configuration. A reference's binding names a destination; it
 * can never widen what the resolver may contact.
 *
 * Every request, and every redirect hop, passes three checks:
 *
 * 1. **URL**: parsed with the WHATWG parser (the one Node's HTTP client uses, so there is no second
 *    interpretation). Only `https:` (and `http:` when allowed); no user name or password; no zone ids.
 * 2. **Origin**: the parsed origin must be one of `allowedOrigins`, compared exactly.
 * 3. **Address, at connect time**: the host name is resolved by this module, every address it resolves
 *    to must be public (or inside `allowPrivateNetworks`), and the socket connects to the address that was
 *    checked. There is no window between the check and the connection for DNS to change (rebinding), and an
 *    IP literal in any notation is checked as the address the parser normalized it to.
 *
 * Redirects are refused by AppPort's discovery client; if a caller asks this fetch to follow them, every
 * hop is checked like the first and at most `maxRedirects` are followed.
 *
 * Production (`environment: 'production'`, the default) fails closed: without a valid `allowedOrigins`
 * nothing is contacted, and an invalid entry is a configuration error at startup. Development allows any
 * origin, `http:` and private addresses, unless the configuration says otherwise.
 */

import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { Readable } from 'node:stream';

export type Environment = 'production' | 'development';

export interface OutboundOptions {
  /** Exact origins (`https://agents.example.com`, `https://10.1.2.3:8443`) the resolver may contact. */
  allowedOrigins?: string[];
  /** Non-public address ranges that are allowed anyway, as CIDRs (`10.20.0.0/16`, `fd00:1::/32`) or addresses. */
  allowPrivateNetworks?: string[];
  /** Allow `http:` origins. Default false in production, true in development. */
  allowHttp?: boolean;
  /** Redirect hops followed when a caller asks to follow redirects. Default 3. */
  maxRedirects?: number;
  /** Name resolution (tests). Default: the system resolver, every address. */
  lookup?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
}

export type OutboundReason =
  | 'outbound.not-configured'
  | 'outbound.malformed-url'
  | 'outbound.scheme-not-allowed'
  | 'outbound.credentials-in-url'
  | 'outbound.origin-not-allowed'
  | 'outbound.address-not-allowed'
  | 'outbound.dns-failed'
  | 'outbound.too-many-redirects';

export class OutboundRefusedError extends Error {
  readonly code = 'OUTBOUND_REFUSED';
  constructor(
    readonly reason: OutboundReason,
    message: string,
  ) {
    super(message);
    this.name = 'OutboundRefusedError';
  }
}

export interface OutboundPolicy {
  readonly environment: Environment;
  /** `disabled`: production without an allowlist; `restricted`: an allowlist applies; `open`: development without one. */
  readonly mode: 'disabled' | 'restricted' | 'open';
  /** Checks a URL without contacting anything (scheme, credentials, origin, IP literals). */
  checkUrl(url: string | URL): URL;
  /** A `fetch` that applies every check to every request and redirect hop. */
  readonly fetch: typeof globalThis.fetch;
  describe(): { environment: Environment; mode: string; origins: number; privateNetworks: number; allowHttp: boolean };
}

// ---- addresses ----------------------------------------------------------------------------------------

interface Range {
  v6: boolean;
  base: bigint;
  bits: number;
  label: string;
}

function v4ToBig(address: string): bigint | null {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null;
    value = (value << 8n) | BigInt(Number(part));
  }
  return value;
}

/** Expands any valid IPv6 text (with `::` and an optional dotted IPv4 tail) to 128 bits. */
function v6ToBig(address: string): bigint | null {
  if (isIP(address) !== 6 || address.includes('%')) return null;
  let text = address.toLowerCase();
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (dotted) {
    const v4 = v4ToBig(dotted[1]!);
    if (v4 === null) return null;
    text = text.slice(0, -dotted[1]!.length) + `${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const [head, tail] = text.split('::') as [string, string | undefined];
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(parseInt(group || '0', 16));
  return value;
}

function parseRange(text: string, label: string): Range {
  const [address, bitsText] = text.split('/') as [string, string | undefined];
  const v6 = isIP(address) === 6;
  const base = v6 ? v6ToBig(address) : v4ToBig(address);
  const max = v6 ? 128 : 32;
  const bits = bitsText === undefined ? max : Number(bitsText);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > max || (bitsText !== undefined && !/^\d{1,3}$/.test(bitsText))) {
    throw new Error(`"${text}" is not an IP address or CIDR range`);
  }
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(max - bits);
  return { v6, base: base & mask, bits, label };
}

function inRange(range: Range, v6: boolean, value: bigint): boolean {
  if (range.v6 !== v6) return false;
  const max = v6 ? 128 : 32;
  const mask = range.bits === 0 ? 0n : ((1n << BigInt(range.bits)) - 1n) << BigInt(max - range.bits);
  return (value & mask) === range.base;
}

/** IANA special-purpose IPv4 ranges: none is a public destination. */
const V4_SPECIAL: Range[] = [
  ['0.0.0.0/8', 'unspecified'],
  ['10.0.0.0/8', 'private'],
  ['100.64.0.0/10', 'shared-address-space'],
  ['127.0.0.0/8', 'loopback'],
  ['169.254.0.0/16', 'link-local'],
  ['172.16.0.0/12', 'private'],
  ['192.0.0.0/24', 'reserved'],
  ['192.0.2.0/24', 'documentation'],
  ['192.31.196.0/24', 'reserved'],
  ['192.52.193.0/24', 'reserved'],
  ['192.88.99.0/24', 'reserved'],
  ['192.168.0.0/16', 'private'],
  ['192.175.48.0/24', 'reserved'],
  ['198.18.0.0/15', 'benchmarking'],
  ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'],
].map(([cidr, label]) => parseRange(cidr!, label!));

/** IPv6: only global unicast (2000::/3) can be public, minus its special-purpose blocks. */
const V6_GLOBAL = parseRange('2000::/3', 'global');
const V6_SPECIAL: Range[] = [
  ['2001::/23', 'reserved'], // IETF protocol assignments: Teredo, benchmarking, ORCHID, ...
  ['2001:db8::/32', 'documentation'],
  ['2002::/16', '6to4'],
  ['3fff::/20', 'documentation'],
].map(([cidr, label]) => parseRange(cidr!, label!));
const V6_LABELS: Range[] = [
  ['::/128', 'unspecified'],
  ['::1/128', 'loopback'],
  ['64:ff9b::/96', 'nat64'],
  ['64:ff9b:1::/48', 'nat64'],
  ['100::/64', 'discard'],
  ['fc00::/7', 'private'],
  ['fe80::/10', 'link-local'],
  ['fec0::/10', 'site-local'],
  ['ff00::/8', 'multicast'],
].map(([cidr, label]) => parseRange(cidr!, label!));
const V4_MAPPED = parseRange('::ffff:0:0/96', 'ipv4-mapped');
const V4_COMPATIBLE = parseRange('::/96', 'ipv4-compatible');

/**
 * `public`, or the kind of non-public address. IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:7f00:1`) is
 * classified as the IPv4 address it carries.
 */
export function classifyAddress(address: string): string {
  const family = isIP(address);
  if (family === 4) {
    const value = v4ToBig(address);
    if (value === null) return 'invalid';
    return V4_SPECIAL.find((r) => inRange(r, false, value))?.label ?? 'public';
  }
  if (family === 6) {
    const value = v6ToBig(address);
    if (value === null) return 'invalid';
    if (inRange(V4_MAPPED, true, value)) {
      const v4 = value & 0xffffffffn;
      return classifyAddress([24n, 16n, 8n, 0n].map((s) => String((v4 >> s) & 0xffn)).join('.'));
    }
    const labelled = V6_LABELS.find((r) => inRange(r, true, value));
    if (labelled) return labelled.label;
    if (inRange(V4_COMPATIBLE, true, value)) return 'ipv4-compatible';
    if (!inRange(V6_GLOBAL, true, value)) return 'reserved';
    return V6_SPECIAL.find((r) => inRange(r, true, value))?.label ?? 'public';
  }
  return 'invalid';
}

// ---- policy -------------------------------------------------------------------------------------------

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

export function createOutboundPolicy(environment: Environment, options: OutboundOptions = {}): OutboundPolicy {
  if (environment !== 'production' && environment !== 'development') throw new Error(`unknown environment "${String(environment)}"`);
  const development = environment === 'development';
  const allowHttp = options.allowHttp ?? development;
  const origins = new Set<string>();
  for (const entry of options.allowedOrigins ?? []) {
    let parsed: URL;
    try {
      parsed = new URL(entry);
    } catch {
      throw new Error(`outbound.allowedOrigins: "${entry}" is not a URL`);
    }
    if (parsed.origin === 'null' || parsed.origin !== entry.replace(/\/$/, '') || parsed.username || parsed.password) {
      throw new Error(`outbound.allowedOrigins: "${entry}" must be an origin (scheme://host[:port]) with nothing else`);
    }
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && allowHttp)) {
      throw new Error(`outbound.allowedOrigins: "${entry}" uses ${parsed.protocol}; only https: is allowed${development ? '' : ' in production'}`);
    }
    origins.add(parsed.origin);
  }
  const privateNetworks = (options.allowPrivateNetworks ?? []).map((cidr) => {
    try {
      return parseRange(cidr, 'allowed');
    } catch (error) {
      throw new Error(`outbound.allowPrivateNetworks: ${(error as Error).message}`);
    }
  });
  const mode: OutboundPolicy['mode'] = origins.size > 0 ? 'restricted' : development ? 'open' : 'disabled';
  const maxRedirects = options.maxRedirects ?? 3;
  const resolveName = options.lookup ?? (async (hostname: string) => dnsLookup(hostname, { all: true, verbatim: true }));

  const refuse = (reason: OutboundReason, message: string): never => {
    throw new OutboundRefusedError(reason, message);
  };

  function addressAllowed(address: string): boolean {
    if (development && privateNetworks.length === 0) return classifyAddress(address) !== 'invalid';
    const kind = classifyAddress(address);
    if (kind === 'public') return true;
    if (kind === 'invalid') return false;
    const family = isIP(address);
    const mapped = family === 6 && inRange(V4_MAPPED, true, v6ToBig(address)!);
    const value = mapped ? v6ToBig(address)! & 0xffffffffn : family === 6 ? v6ToBig(address)! : v4ToBig(address)!;
    return privateNetworks.some((r) => inRange(r, family === 6 && !mapped, value));
  }

  /** The host as the connection will see it: brackets removed from IPv6 literals. */
  const bareHost = (url: URL) => url.hostname.replace(/^\[(.*)\]$/, '$1');

  function checkUrl(input: string | URL): URL {
    if (mode === 'disabled') refuse('outbound.not-configured', 'outbound requests are disabled: configure outbound.allowedOrigins');
    let url: URL;
    try {
      url = new URL(String(input));
    } catch {
      return refuse('outbound.malformed-url', 'the URL could not be parsed');
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && allowHttp)) refuse('outbound.scheme-not-allowed', `${url.protocol} is not allowed`);
    if (url.username || url.password) refuse('outbound.credentials-in-url', 'URLs with credentials are not allowed');
    const host = bareHost(url);
    if (!host || host.includes('%')) refuse('outbound.malformed-url', 'the URL has no usable host');
    if (mode === 'restricted' && !origins.has(url.origin)) refuse('outbound.origin-not-allowed', `${url.origin} is not an allowed origin`);
    if (isIP(host) && !addressAllowed(host)) refuse('outbound.address-not-allowed', `${url.origin} is a ${classifyAddress(host)} address`);
    return url;
  }

  /** Resolves the name and checks every address; the connection uses the first, already checked. */
  const lookup: LookupFunction = (hostname, lookupOptions, callback) => {
    void (async () => {
      let addresses: Array<{ address: string; family: number }>;
      try {
        addresses = await resolveName(hostname);
      } catch {
        throw new OutboundRefusedError('outbound.dns-failed', `${hostname} could not be resolved`);
      }
      if (addresses.length === 0) throw new OutboundRefusedError('outbound.dns-failed', `${hostname} has no addresses`);
      // Every answer must be allowed: a mixed answer is how rebinding attacks pick the address later.
      const refused = addresses.find((a) => !addressAllowed(a.address));
      if (refused) throw new OutboundRefusedError('outbound.address-not-allowed', `${hostname} resolves to a ${classifyAddress(refused.address)} address`);
      return addresses;
    })().then(
      (addresses) => {
        const first = addresses[0]!;
        if ((lookupOptions as { all?: boolean }).all) callback(null, [{ address: first.address, family: first.family }] as never);
        else callback(null, first.address, first.family);
      },
      (error) => callback(error as NodeJS.ErrnoException, '' as never),
    );
  };

  function send(url: URL, init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal }): Promise<Response> {
    return new Promise((resolve, reject) => {
      const host = bareHost(url);
      const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
        {
          protocol: url.protocol,
          host,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method: init.method,
          headers: init.headers,
          agent: false, // a fresh connection, and so a fresh checked lookup, for every request
          lookup,
          ...(isIP(host) ? {} : { servername: host }),
          ...(init.signal ? { signal: init.signal } : {}),
        },
        (response: IncomingMessage) => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) for (const v of value) headers.append(name, v);
            else if (value !== undefined) headers.set(name, value);
          }
          const status = response.statusCode ?? 502;
          const empty = status === 204 || status === 304 || init.method === 'HEAD';
          if (empty) response.resume();
          resolve(new Response(empty ? null : (Readable.toWeb(response) as ReadableStream), { status, statusText: response.statusMessage ?? '', headers }));
        },
      );
      request.on('error', (error) => {
        let cause: unknown = error;
        while (cause && !(cause instanceof OutboundRefusedError)) cause = (cause as { cause?: unknown }).cause;
        reject(cause instanceof OutboundRefusedError ? cause : error);
      });
      if (init.body !== undefined) request.write(init.body);
      request.end();
    });
  }

  const guardedFetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    let url = checkUrl(typeof input === 'string' || input instanceof URL ? input : input.url);
    let method = (init.method ?? 'GET').toUpperCase();
    let body = typeof init.body === 'string' ? init.body : init.body == null ? undefined : String(init.body);
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((value, name) => (headers[name] = value));
    for (let hop = 0; ; hop++) {
      const response = await send(url, { method, headers, ...(body !== undefined ? { body } : {}), ...(init.signal ? { signal: init.signal } : {}) });
      const location = response.headers.get('location');
      if (!REDIRECTS.has(response.status) || !location || init.redirect === 'manual') return response;
      await response.body?.cancel().catch(() => undefined);
      if (init.redirect === 'error') throw new TypeError('redirect refused');
      if (hop >= maxRedirects) refuse('outbound.too-many-redirects', `more than ${maxRedirects} redirects`);
      const next = checkUrl(new URL(location, url));
      if (next.origin !== url.origin) delete headers['authorization'];
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
        method = 'GET';
        body = undefined;
      }
      url = next;
    }
  }) as typeof globalThis.fetch;

  return {
    environment,
    mode,
    checkUrl,
    fetch: guardedFetch,
    describe: () => ({ environment, mode, origins: origins.size, privateNetworks: privateNetworks.length, allowHttp }),
  };
}
