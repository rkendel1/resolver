/**
 * Server-side checks a binding must pass before it is stored, beyond the structural checks in core.
 *
 * - `value`: the JSON Schema fixed at creation (@appport/schema).
 * - `model`: the provider and model against the AppPort Services intelligence catalog; a credential
 *   reference must name an existing, active `secret` in the same tenant.
 * - `agent`: the origin is discovered over AppPort and every pinned capability digest is recomputed from
 *   the served manifest (@appport/protocol). A binding that would point consumers at a different
 *   contract is refused here, before any consumer sees it.
 * - `endpoint`: structural only. The resolver never connects to endpoints.
 */

import { capabilityDigest } from '@appport/protocol';
import { fromJSONSchema } from '@appport/schema';
import { AppPort } from '@appport/sdk';
import { getIntelligenceProvider } from '@appport/services';
import type { AgentTarget, Binding, Json, Kind, ModelTarget } from '@appport/resolver-core';

export interface TargetCheckOptions {
  /** Look up another reference in the same tenant (for model credentials). */
  lookup: (ref: string) => Promise<{ kind: Kind; state: string } | null>;
  /** Accept model ids not listed in the catalog for providers that list their models. Default false. */
  allowUnlistedModels?: boolean;
  /** Discover agent origins and verify pinned digests. Default true. */
  verifyAgents?: boolean;
  agentTimeoutMs?: number;
}

export type TargetCheck = { ok: true } | { ok: false; reason: string; error: string };

const fail = (reason: string, error: string): TargetCheck => ({ ok: false, reason, error });

export function checkSchema(schema: Json): TargetCheck {
  try {
    fromJSONSchema(schema as never);
    return { ok: true };
  } catch (error) {
    return fail('resolver.invalid-schema', `the schema is not a usable JSON Schema: ${(error as Error).message}`);
  }
}

export async function checkTargets(kind: Kind, binding: Binding, schema: Json | null, options: TargetCheckOptions): Promise<TargetCheck> {
  for (const [i, target] of binding.targets.entries()) {
    const at = binding.targets.length > 1 ? `targets[${i}]: ` : '';
    const result =
      kind === 'value'
        ? checkValue(target.value as Json, schema)
        : kind === 'model'
          ? await checkModel(target.value as ModelTarget, options)
          : kind === 'agent'
            ? await checkAgent(target.value as AgentTarget, options)
            : ({ ok: true } as TargetCheck);
    if (!result.ok) return { ...result, error: `${at}${result.error}` };
  }
  return { ok: true };
}

function checkValue(value: Json, schema: Json | null): TargetCheck {
  if (schema === null) return { ok: true };
  const result = fromJSONSchema(schema as never).validate(value) as { ok: boolean; issues?: { path: (string | number)[]; message: string }[] };
  if (result.ok) return { ok: true };
  const issue = result.issues?.[0];
  return fail('resolver.schema-mismatch', `does not match the reference's schema${issue ? ` at /${issue.path.join('/')}: ${issue.message}` : ''}`);
}

async function checkModel(target: ModelTarget, options: TargetCheckOptions): Promise<TargetCheck> {
  const provider = getIntelligenceProvider(target.provider);
  if (!provider) return fail('resolver.unknown-provider', `unknown provider "${target.provider}"`);
  if (provider.modelSelection === 'catalog' && !options.allowUnlistedModels && !provider.models.some((m) => m.id === target.model)) {
    return fail('resolver.unknown-model', `"${target.model}" is not in the ${provider.id} catalog (${provider.models.map((m) => m.id).join(', ')})`);
  }
  if (target.endpoint && !provider.customEndpoint) {
    return fail('resolver.endpoint-not-allowed', `provider ${provider.id} does not take a custom endpoint`);
  }
  if (!target.endpoint && provider.endpoints.length === 0) {
    return fail('resolver.endpoint-required', `provider ${provider.id} needs an endpoint`);
  }
  if (target.credential) {
    const credential = await options.lookup(target.credential);
    if (!credential || credential.kind !== 'secret' || credential.state !== 'active') {
      return fail('resolver.credential-missing', `credential ${target.credential} is not an active secret reference`);
    }
  } else if (provider.credential === 'required') {
    return fail('resolver.credential-required', `provider ${provider.id} needs a credential: set credential to a secret reference`);
  }
  return { ok: true };
}

async function checkAgent(target: AgentTarget, options: TargetCheckOptions): Promise<TargetCheck> {
  if (options.verifyAgents === false) return { ok: true };
  let client;
  try {
    client = await AppPort.discover({ origin: target.origin, timeoutMs: options.agentTimeoutMs ?? 5000 });
    const manifest = await client.load();
    if (target.application && manifest.application.id !== target.application) {
      return fail('resolver.incompatible-target', `${target.origin} serves ${manifest.application.id}, not ${target.application}`);
    }
    for (const [reference, pinned] of Object.entries(target.capabilities ?? {})) {
      const at = reference.lastIndexOf('@');
      const served = capabilityDigest(manifest, reference.slice(0, at), Number(reference.slice(at + 1)));
      if (served === undefined) return fail('resolver.incompatible-target', `${target.origin} does not serve ${reference}`);
      if (served !== pinned) {
        return fail('resolver.incompatible-target', `${target.origin} serves ${reference} with contract ${served}, not the pinned ${pinned}`);
      }
    }
    return { ok: true };
  } catch (error) {
    return fail('resolver.agent-unreachable', `${target.origin} could not be discovered over AppPort (${(error as { code?: string }).code ?? (error as Error).message})`);
  } finally {
    await client?.close();
  }
}
