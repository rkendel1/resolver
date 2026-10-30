/**
 * What a reference can point at. A reference's kind is fixed when it is created; only its binding changes.
 *
 * - `value`    configuration: any JSON, optionally constrained by a JSON Schema fixed at creation.
 * - `secret`   an API key, token or password. Write-only material held in custody, never in the store.
 * - `model`    an LLM: provider, model, optional endpoint and a credential reference ("DNS for models").
 * - `endpoint` a service URL.
 * - `agent`    an AppPort agent or application: origin, and optionally pinned capability digests.
 */

import { isRef, type Parsed, type RefName } from './names.js';

export const KINDS = ['value', 'secret', 'model', 'endpoint', 'agent'] as const;
export type Kind = (typeof KINDS)[number];

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface ModelTarget {
  provider: string;
  model: string;
  /** Absent: the provider's default endpoint. */
  endpoint?: string;
  /** A `secret` reference holding the provider credential. Resolved separately, by a caller allowed to reveal it. */
  credential?: RefName;
  /** Non-secret provider options (temperature, max tokens...). */
  options?: { [key: string]: Json };
}

export interface EndpointTarget {
  url: string;
  /** Non-secret headers only. Put credentials in a `secret` reference. */
  headers?: Record<string, string>;
}

export interface AgentTarget {
  /** `https://host[:port]`, or `http://` on loopback. */
  origin: string;
  application?: string;
  /** Pinned contracts: `name@version` -> AppPort `capabilityDigest` (`sha256:...`). Checked at write time. */
  capabilities?: Record<string, string>;
}

/** How a secret is held in a binding: a pointer into custody, never the material. */
export interface SecretTarget {
  credentialRef: string;
  version: number;
  /** The custody's id for this exact stored version, when it gives one: lets a restore be checked against its vault. */
  seal?: string;
}

export type Target = Json | ModelTarget | EndpointTarget | AgentTarget | SecretTarget;

export function isKind(value: unknown): value is Kind {
  return typeof value === 'string' && (KINDS as readonly string[]).includes(value);
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAPABILITY_REF = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+@[1-9][0-9]*$/;
const SECRET_LOOKING = /(api[_-]?key|secret|token|password|authorization|bearer)/i;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function httpUrl(input: unknown, field: string, { loopbackHttpOnly = false } = {}): Parsed<string> {
  if (typeof input !== 'string' || input.length > 2048) return { ok: false, error: `${field} must be a URL of at most 2048 characters` };
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, error: `${field} is not a URL` };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, error: `${field} must be http(s)` };
  if (url.username || url.password) return { ok: false, error: `${field} must not contain credentials` };
  if (loopbackHttpOnly && url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    return { ok: false, error: `${field} must be https unless it is a loopback address` };
  }
  return { ok: true, value: url.href };
}

/** Structural validation of one binding target for a kind. Secrets are validated where material is written. */
export function checkTarget(kind: Kind, target: unknown): Parsed<Target> {
  switch (kind) {
    case 'value':
      return { ok: true, value: target as Json };
    case 'secret':
      return { ok: false, error: 'secret material is written with `secret`, not as a binding target' };
    case 'model': {
      if (!isObject(target)) return { ok: false, error: 'a model target is an object' };
      const { provider, model, endpoint, credential, options, ...rest } = target;
      if (Object.keys(rest).length) return { ok: false, error: `unknown model fields: ${Object.keys(rest).join(', ')}` };
      if (typeof provider !== 'string' || !provider) return { ok: false, error: 'model.provider is required' };
      if (typeof model !== 'string' || !model) return { ok: false, error: 'model.model is required' };
      const out: ModelTarget = { provider, model };
      if (endpoint !== undefined && endpoint !== null) {
        const url = httpUrl(endpoint, 'model.endpoint');
        if (!url.ok) return url;
        out.endpoint = url.value;
      }
      if (credential !== undefined) {
        if (!isRef(credential)) return { ok: false, error: 'model.credential must be a ref:// to a secret' };
        out.credential = credential;
      }
      if (options !== undefined) {
        if (!isObject(options)) return { ok: false, error: 'model.options must be an object' };
        const leaked = Object.keys(options).find((k) => SECRET_LOOKING.test(k));
        if (leaked) return { ok: false, error: `model.options.${leaked} looks like a credential: use model.credential` };
        out.options = options as { [key: string]: Json };
      }
      return { ok: true, value: out };
    }
    case 'endpoint': {
      if (!isObject(target)) return { ok: false, error: 'an endpoint target is an object with a url' };
      const { url, headers, ...rest } = target;
      if (Object.keys(rest).length) return { ok: false, error: `unknown endpoint fields: ${Object.keys(rest).join(', ')}` };
      const checked = httpUrl(url, 'endpoint.url');
      if (!checked.ok) return checked;
      const out: EndpointTarget = { url: checked.value };
      if (headers !== undefined) {
        if (!isObject(headers) || !Object.values(headers).every((v) => typeof v === 'string')) {
          return { ok: false, error: 'endpoint.headers must map names to strings' };
        }
        const leaked = Object.keys(headers).find((k) => SECRET_LOOKING.test(k));
        if (leaked) return { ok: false, error: `endpoint.headers.${leaked} looks like a credential: use a secret reference` };
        out.headers = headers as Record<string, string>;
      }
      return { ok: true, value: out };
    }
    case 'agent': {
      if (!isObject(target)) return { ok: false, error: 'an agent target is an object with an origin' };
      const { origin, application, capabilities, ...rest } = target;
      if (Object.keys(rest).length) return { ok: false, error: `unknown agent fields: ${Object.keys(rest).join(', ')}` };
      const checked = httpUrl(origin, 'agent.origin', { loopbackHttpOnly: true });
      if (!checked.ok) return checked;
      const parsed = new URL(checked.value);
      if (parsed.pathname !== '/' || parsed.search || parsed.hash) return { ok: false, error: 'agent.origin must be a bare origin' };
      const out: AgentTarget = { origin: parsed.origin };
      if (application !== undefined) {
        if (typeof application !== 'string' || !application) return { ok: false, error: 'agent.application must be a string' };
        out.application = application;
      }
      if (capabilities !== undefined) {
        if (!isObject(capabilities)) return { ok: false, error: 'agent.capabilities maps name@version to a digest' };
        for (const [reference, digest] of Object.entries(capabilities)) {
          if (!CAPABILITY_REF.test(reference)) return { ok: false, error: `agent.capabilities: "${reference}" is not name@version` };
          if (typeof digest !== 'string' || !DIGEST.test(digest)) {
            return { ok: false, error: `agent.capabilities["${reference}"] must be sha256:<64 lowercase hex>` };
          }
        }
        out.capabilities = capabilities as Record<string, string>;
      }
      return { ok: true, value: out };
    }
  }
}
