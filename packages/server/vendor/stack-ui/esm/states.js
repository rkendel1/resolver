// State semantics (docs/design-system-contract.md §6). Pure data and pure
// functions: no DOM, no network, no storage.
//
// Mappings are keyed by source FIELD, never by bare string: the same word means
// different things in different fields (Compute `ready` is an in-progress
// release phase and also verified process readiness).

export const TONES = Object.freeze(['positive', 'progress', 'attention', 'critical', 'neutral', 'unknown']);

export const GLYPHS = Object.freeze({
  positive: '●',
  progress: '◐',
  attention: '▲',
  critical: '✕',
  neutral: '○',
  unknown: '?',
});

export const OUTCOMES = Object.freeze(['submitted', 'accepted', 'completed', 'failed', 'cancelled', 'rejected', 'outcome_unknown']);
export const OUTCOME_LABELS = Object.freeze({
  submitted: 'Sending…',
  accepted: 'Started',
  completed: 'Done',
  failed: 'Failed',
  cancelled: 'Cancelled',
  rejected: 'Not accepted',
  outcome_unknown: 'Result unknown — check current state',
});
export const VERIFICATION_STATES = Object.freeze(['verified', 'verification_failed', 'not_verified', 'not_evaluated']);
export const FRESHNESS_STATES = Object.freeze(['live', 'cached', 'stale', 'unknown']);
export const CAPABILITY_STATES = Object.freeze(['available', 'partial', 'unsupported']);

/// "network_ready" → "Network ready". Matches the labels products show today.
export function humanize(value) {
  const text = String(value).replace(/_/g, ' ');
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

const P = 'positive';
const G = 'progress';
const A = 'attention';
const C = 'critical';
const N = 'neutral';
const U = 'unknown';

/// Condition-axis mappings. A value is either a tone or [tone, label].
/// Sources are cited so a reviewer can check each table against its enum.
const CONDITION = {
  // compute: crates/compute-environment/src/model.rs `ActualState`
  'compute.environment.actual_state': {
    running: P, completed: P, pending: G, starting: G, stopping: G, degraded: A, failed: C, denied: C, stopped: N,
  },
  // compute: crates/compute-environment/src/status.rs `Health`
  'compute.health': { healthy: P, unhealthy: C, unknown: U },
  // compute: crates/compute-environment/src/status.rs `ReadinessState` (environment)
  'compute.environment.readiness': {
    ready: P, created: G, starting: G, degraded: A, failed: C, unavailable: C,
  },
  // compute: crates/compute-core/src/computers.rs `ReadinessState` (process)
  'compute.process.readiness': { ready: P, starting: G, unready: A },
  // compute: crates/compute-core/src/computers.rs `ObservedProcess::status`, which may
  // also carry the machine's observed word when the machine is not running.
  'compute.process.state': {
    ready: P, running: P, pending: G, starting: G, stopping: G, unready: A, failed: C, lost: C,
    stopped: N, exited: N, destroyed: N, expired: N, unverified: U, unreachable: U,
  },
  // compute: crates/compute-state/src/model.rs `DeploymentStatus`
  'compute.deployment.status': {
    active: P, complete: P, pending: G, starting: G, ready: G, network_ready: G, switching: G, draining: G,
    failed: C, rolled_back: C,
  },
  // compute: crates/compute-state/src/model.rs `VersionStatus`
  'compute.version.status': { published: P, publishing: G, failed: C },
  // compute: crates/compute-state/src/model.rs `RolloutStatus`
  'compute.rollout.status': { active: P, applying: G, failed: C, superseded: N },
  // compute: crates/compute-core/src/jobs.rs `JobStatus`. `timed_out` is a definite
  // terminal failure (the job ran past its deadline and was stopped), not an
  // unknown outcome.
  'compute.job.status': {
    succeeded: P, created: G, accepted: G, queued: G, waiting_for_capacity: G, reserved: G, admitted: G,
    preparing: G, running: G, failed: C, rejected: C, timed_out: C, cancelled: N,
  },
  // compute: packages/compute-appport/src/computers.ts `ComputerReality.observed`
  'compute.computer.observed': {
    running: P, starting: G, reconciling: G, stopping: G, failed: C, lost: C,
    stopped: N, destroyed: N, expired: N, unverified: U, unreachable: U,
  },
  // compute: crates/compute-core/src/computers.rs `ComputerStatus` (stored)
  'compute.computer.status': {
    running: P, pending: G, provisioning: G, resuming: G, stopping: G, destroying: G,
    failed: C, lost: C, stopped: N, destroyed: N, expired: N, unreachable: U,
  },
  // flow_db: crates/feltdb-server/src/main.rs `/health/ready` `state`
  'feltdb.health.ready_state': { healthy: P, recovering: G, degraded: A, unavailable: C },
  // flow_db: packages/core/src/managed-recovery.ts `AuthorityAvailabilityState`
  'feltdb.authority.availability': { available: P, recovering: G, degraded: A, closed: N, unknown: U },
  // flow_db: /v1/control-plane/overview `authority.lease_clock_healthy` (boolean)
  'feltdb.authority.lease_clock_healthy': { true: [P, 'Healthy'], false: [A, 'Degraded'] },
  // authboundry: crates/authz/src/policy.rs decision `allow|deny`. A live check's
  // deny is critical; the same word on a historical record is neutral
  // (contract §6.3), so the two are separate fields.
  'authboundry.decision.live': { allow: [P, 'Allow'], deny: [C, 'Deny'] },
  'authboundry.decision.recorded': { allow: [P, 'Allow'], deny: [N, 'Deny'] },
  // authboundry: crates/server/src/control_routes.rs delegation status
  'authboundry.delegation.status': { active: P, pending: G, revoked: C, expired: N },
  // authboundry: apps/web/lib/applications.ts `ApplicationStatus`
  'authboundry.application.status': { active: P, awaiting_contract: G, disabled: N },
  // appport-services: src/jobs/models.ts `JobStatus`
  'appport.job.status': { completed: P, scheduled: G, pending: G, running: G, retrying: G, failed: C },
  // appport-services: src/notifications/models.ts `NotificationStatus`
  'appport.notification.status': { delivered: P, pending: G, failed: C, read: N, acknowledged: N, expired: N },
  // appport-services: an API key is revoked when its record has `revokedAt`
  // (src/api-keys). Revocation is a deliberate end state, not a fault.
  'appport.api_key.revoked': { false: [P, 'Active'], true: [N, 'Revoked'] },
  // appport-services: a webhook endpoint is disabled when it has `disabledAt`.
  'appport.webhook.disabled': { false: [P, 'Enabled'], true: [N, 'Disabled'] },
  // appport-services: src/jobs `Schedule.enabled`.
  'appport.schedule.enabled': { true: [P, 'Enabled'], false: [N, 'Disabled'] },
  // appport-services: src/configuration/models.ts `ConfigurationSecretView.configured`,
  // which is always `true` (a listed secret is a bound one). No other value is
  // mapped, so anything else would show as unknown rather than as a guess.
  'appport.configuration.secret.configured': { true: [P, 'Configured'] },
  // appboundry: packages/core/src/application-lifecycle.ts `ApplicationLifecyclePhase`
  'appboundry.lifecycle.phase': {
    ACTIVE: [P, 'Active'], DRAFT: [G, 'Draft'], VALIDATED: [G, 'Validated'], REGISTERED: [G, 'Registered'],
    CHANGE_PROPOSED: [A, 'Change proposed'], RETIRED: [N, 'Retired'],
  },
  // appboundry: apps/cloud-portal/src/read-model.ts capability provider
  // `compatibility[].compatible`, from evaluateCompatibility against a consumer.
  'appboundry.provider.compatible': { true: [P, 'Compatible'], false: [A, 'Incompatible'] },
  // appboundry: packages/core/src/execution-ledger.ts `ExecutionStatus`, the
  // ledger record the cloud portal lists. All five are written by
  // AuthorizedExecutionService (`running` on begin, the others on complete).
  'appboundry.execution.status': {
    succeeded: P, running: G, failed: C, timed_out: [C, 'Timed out'], cancelled: N,
  },
  // appboundry: packages/core/src/application-source.ts `ApplicationSourceStatus`.
  // `pending` is declared but no code path writes it, so it is not mapped.
  'appboundry.source.status': { connected: P, stale: A, failed: C, disconnected: N },
  // appboundry: packages/core/src/application-implementation.ts
  // `ApplicationImplementationStatus`, as a condition: whether the
  // implementation may still be selected. Whether it was verified is the
  // separate verification field below. `failed` is declared but never written.
  'appboundry.implementation.status': { verified: [P, 'Current'], stale: A, revoked: C },
  // appboundry: apps/cloud-portal/src/authority.ts provider `eligibility`
  // (ELIGIBLE | INELIGIBLE). Not being eligible in a context is not a fault.
  'appboundry.provider.eligibility': { ELIGIBLE: [P, 'Eligible'], INELIGIBLE: [N, 'Ineligible'] },
  // appboundry: apps/cloud-portal/src/read-model.ts `health.ready`
  'appboundry.health.ready': { true: [P, 'Ready'], false: [C, 'Not ready'] },
  // appboundry: apps/cloud-portal/src/read-model.ts `PortalHealthCheck.status`
  'appboundry.health.check': { available: P, degraded: A, unavailable: C },
};

/// Verification-axis mappings: field value → verification state.
const VERIFICATION = {
  // flow_db: crates/feltdb-server/src/control_plane.rs `revision_to_json` re-checks
  // a revision's content against its id.
  'feltdb.revision.integrity_verified': { true: 'verified', false: 'verification_failed' },
  // appboundry: packages/core/src/application-implementation.ts. `verified` is
  // written only after the source is verified, covers the capability and
  // attests the authoritative contract; `stale` means the contract has since
  // changed, so that verification no longer holds. `revoked` says nothing
  // about verification and is shown by the condition field instead.
  // Same source field as the condition above, on the verification axis.
  'appboundry.implementation.verification': { verified: 'verified', stale: 'not_verified' },
  // appboundry: packages/core/src/contract-attestation.ts `ContractAttestationStatus`.
  // The failed check is named by the value (repository identity or contract).
  'appboundry.attestation.status': {
    verified: 'verified', CONTRACT_MISMATCH: 'verification_failed', IDENTITY_MISMATCH: 'verification_failed',
  },
  // appboundry: packages/core/src/application-conformance.ts `ConformanceReport.status`;
  // the checks are the report's own checks, PASS → passed and FAIL → failed.
  'appboundry.conformance.status': { CONFORMING: 'verified', NON_CONFORMING: 'verification_failed' },
};

/// Freshness-axis mappings.
const FRESHNESS = {
  // compute: crates/compute-environment/src/api.rs `X-Compute-State`
  'compute.response.state': { live: 'live', cached: 'cached', stale: 'stale' },
  // flow_db: packages/core/src/runtime-snapshot.ts staleness
  'feltdb.snapshot.staleness': { current: 'live', stale: 'stale', unknown: 'unknown' },
};

const freezeAll = (table) => Object.freeze(Object.fromEntries(
  Object.entries(table).map(([field, values]) => [field, Object.freeze({ ...values })]),
));
const CONDITION_FIELDS = freezeAll(CONDITION);
const VERIFICATION_FIELDS = freezeAll(VERIFICATION);
const FRESHNESS_FIELDS = freezeAll(FRESHNESS);

const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

/// Every field this release maps, by axis.
export function fields() {
  return {
    condition: Object.keys(CONDITION_FIELDS),
    verification: Object.keys(VERIFICATION_FIELDS),
    freshness: Object.keys(FRESHNESS_FIELDS),
  };
}

/// The source values a field maps, in declaration order.
export function valuesOf(field) {
  const table = CONDITION_FIELDS[field] || VERIFICATION_FIELDS[field] || FRESHNESS_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  return Object.keys(table);
}

/// The condition of one source value. Unmapped values are `unknown` with the
/// raw value as their label, so nothing renders as healthy by omission.
export function resolve(field, value, options) {
  const table = CONDITION_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  const key = String(value);
  const entry = has(table, key) ? table[key] : null;
  const [tone, label] = entry === null ? [U, null] : (Array.isArray(entry) ? entry : [entry, null]);
  const text = (options && options.label) || label || (entry === null ? key : humanize(key));
  return { field, value: key, tone, label: text, glyph: GLYPHS[tone], mapped: entry !== null };
}

/// A verification state with its checks. `verified` requires at least one
/// listed check; without one the claim is `not_evaluated` (contract §6.1 rule 1).
export function verification(state, checks) {
  const list = normalizeChecks(checks);
  let normalized = VERIFICATION_STATES.includes(state) ? state : 'not_evaluated';
  if (normalized === 'verified' && list.length === 0) normalized = 'not_evaluated';
  if (normalized === 'verified' && list.some((check) => check.status === 'failed')) normalized = 'verification_failed';
  return { state: normalized, checks: list };
}

/// A verification state from a mapped source field.
export function verificationOf(field, value, checks) {
  const table = VERIFICATION_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  const key = String(value);
  const state = has(table, key) ? table[key] : 'not_evaluated';
  const list = normalizeChecks(checks).map((check) => ({
    ...check,
    status: check.status || (state === 'verified' ? 'passed' : state === 'verification_failed' ? 'failed' : undefined),
  }));
  return verification(state, list);
}

/// A freshness state from a mapped source field; anything else is `unknown`.
export function freshnessOf(field, value) {
  const table = FRESHNESS_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  const key = String(value);
  return has(table, key) ? table[key] : 'unknown';
}

/// A capability status; anything undeclared is `unsupported` (FeltDB's rule).
export function capability(status) {
  return CAPABILITY_STATES.includes(status) ? status : 'unsupported';
}

function normalizeChecks(checks) {
  if (!checks) return [];
  return checks.map((check) => (typeof check === 'string'
    ? { label: check }
    : { label: String(check.label), ...(check.status ? { status: check.status } : {}) }));
}
