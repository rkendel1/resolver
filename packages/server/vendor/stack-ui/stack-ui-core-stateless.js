/*! @stack-ui/core 0.3.0 — classic build, stateless (no theme preference). Exposes window.StackUI. */
'use strict';
(function (global) {
'use strict';
// ---- states.js
// State semantics (docs/design-system-contract.md §6). Pure data and pure
// functions: no DOM, no network, no storage.
//
// Mappings are keyed by source FIELD, never by bare string: the same word means
// different things in different fields (Compute `ready` is an in-progress
// release phase and also verified process readiness).

const TONES = Object.freeze(['positive', 'progress', 'attention', 'critical', 'neutral', 'unknown']);

const GLYPHS = Object.freeze({
  positive: '●',
  progress: '◐',
  attention: '▲',
  critical: '✕',
  neutral: '○',
  unknown: '?',
});

const OUTCOMES = Object.freeze(['submitted', 'accepted', 'completed', 'failed', 'cancelled', 'rejected', 'outcome_unknown']);
const OUTCOME_LABELS = Object.freeze({
  submitted: 'Sending…',
  accepted: 'Started',
  completed: 'Done',
  failed: 'Failed',
  cancelled: 'Cancelled',
  rejected: 'Not accepted',
  outcome_unknown: 'Result unknown — check current state',
});
const VERIFICATION_STATES = Object.freeze(['verified', 'verification_failed', 'not_verified', 'not_evaluated']);
const FRESHNESS_STATES = Object.freeze(['live', 'cached', 'stale', 'unknown']);
const CAPABILITY_STATES = Object.freeze(['available', 'partial', 'unsupported']);

/// "network_ready" → "Network ready". Matches the labels products show today.
function humanize(value) {
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
};

/// Verification-axis mappings: field value → verification state.
const VERIFICATION = {
  // flow_db: crates/feltdb-server/src/control_plane.rs `revision_to_json` re-checks
  // a revision's content against its id.
  'feltdb.revision.integrity_verified': { true: 'verified', false: 'verification_failed' },
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
function fields() {
  return {
    condition: Object.keys(CONDITION_FIELDS),
    verification: Object.keys(VERIFICATION_FIELDS),
    freshness: Object.keys(FRESHNESS_FIELDS),
  };
}

/// The source values a field maps, in declaration order.
function valuesOf(field) {
  const table = CONDITION_FIELDS[field] || VERIFICATION_FIELDS[field] || FRESHNESS_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  return Object.keys(table);
}

/// The condition of one source value. Unmapped values are `unknown` with the
/// raw value as their label, so nothing renders as healthy by omission.
function resolve(field, value, options) {
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
function verification(state, checks) {
  const list = normalizeChecks(checks);
  let normalized = VERIFICATION_STATES.includes(state) ? state : 'not_evaluated';
  if (normalized === 'verified' && list.length === 0) normalized = 'not_evaluated';
  if (normalized === 'verified' && list.some((check) => check.status === 'failed')) normalized = 'verification_failed';
  return { state: normalized, checks: list };
}

/// A verification state from a mapped source field.
function verificationOf(field, value, checks) {
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
function freshnessOf(field, value) {
  const table = FRESHNESS_FIELDS[field];
  if (!table) throw new Error(`unknown field: ${field}`);
  const key = String(value);
  return has(table, key) ? table[key] : 'unknown';
}

/// A capability status; anything undeclared is `unsupported` (FeltDB's rule).
function capability(status) {
  return CAPABILITY_STATES.includes(status) ? status : 'unsupported';
}

function normalizeChecks(checks) {
  if (!checks) return [];
  return checks.map((check) => (typeof check === 'string'
    ? { label: check }
    : { label: String(check.label), ...(check.status ? { status: check.status } : {}) }));
}

// ---- view.js
// Component structure (docs/design-system-contract.md §4–5) as plain trees:
//   { t: tag, a: attributes, c: children, on: { event: handler } }
// Children are trees, strings, numbers, null/false (skipped), arrays, or opaque
// slot content (a DOM Node or a React element) passed through untouched.
// dom.js and the React binding both render these trees, so the DOM a component
// produces is the same in every product.


// `k` is an optional identity among siblings (React's key); dom.js ignores it.
const node = (t, a, c, on, k) => ({ t, a: a || {}, c: c === undefined ? [] : [].concat(c), ...(on ? { on } : {}), ...(k === undefined || k === null ? {} : { k: String(k) }) });
const isTree = (value) => Boolean(value && typeof value === 'object' && typeof value.t === 'string' && value.a && Array.isArray(value.c));

const cx = (...names) => names.filter(Boolean).join(' ');
const present = (value) => value !== null && value !== undefined && value !== '';

/// Extra attributes a product passes through (data-*, aria-*, id, title).
const passthrough = (attrs) => {
  const out = {};
  for (const [key, value] of Object.entries(attrs || {})) {
    if (/^(data-|aria-)/.test(key) || key === 'id' || key === 'title') out[key] = value;
  }
  return out;
};

/// Deterministic timestamp text, identical in every renderer and timezone.
function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}
/// A <time> element, or the raw text when the value is not a valid time: a
/// malformed timestamp from a product must never break the page around it.
const timeNode = (value, cls) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? node('span', { class: cls }, String(value))
    : node('time', { class: cls, datetime: date.toISOString() }, formatTime(value));
};

function StatusIndicator(props) {
  const { field, value, detail, className, attrs } = props;
  const resolved = field ? resolve(field, value, { label: props.label }) : null;
  const tone = resolved ? resolved.tone : (props.tone || 'unknown');
  const label = resolved ? resolved.label : (present(props.label) ? props.label : humanize(tone));
  const glyph = props.glyph || GLYPHS[tone] || GLYPHS.unknown;
  return node('span', {
    class: cx('stack-status', `stack-status--${tone}`, className),
    'data-tone': tone,
    ...(resolved ? { 'data-field': resolved.field, 'data-value': resolved.value } : {}),
    ...passthrough(attrs),
  }, [
    node('span', { class: 'stack-status__glyph', 'aria-hidden': 'true' }, glyph),
    node('span', { class: 'stack-status__label' }, label),
    present(detail) ? node('span', { class: 'stack-status__detail' }, detail) : null,
  ]);
}

const VERIFICATION_GLYPHS = { verified: '✓', verification_failed: '✕', not_verified: '!', not_evaluated: '–' };

function VerificationBadge(props) {
  const { state, checks } = verification(props.state, props.checks);
  const failed = checks.filter((check) => check.status === 'failed');
  let label;
  if (state === 'verified') label = checks.length === 1 ? `Verified · ${checks[0].label}` : `Verified · ${checks.length} checks`;
  else if (state === 'verification_failed') {
    const named = failed.length ? failed : checks;
    label = named.length === 1 ? `Verification failed · ${named[0].label}`
      : named.length ? `Verification failed · ${named.length} checks` : 'Verification failed';
  } else label = state === 'not_verified' ? 'Not verified' : 'Not evaluated';
  return node('div', {
    class: cx('stack-verification', `stack-verification--${state}`, props.className),
    'data-verification': state,
    ...passthrough(props.attrs),
  }, [
    node('span', { class: 'stack-verification__glyph', 'aria-hidden': 'true' }, VERIFICATION_GLYPHS[state]),
    node('span', { class: 'stack-verification__label' }, label),
    present(props.at) ? [' · ', timeNode(props.at, 'stack-verification__at')] : null,
    present(props.evidenceHref) ? node('a', { class: 'stack-verification__evidence', href: props.evidenceHref }, 'Evidence') : null,
    checks.length > 1 ? node('ul', { class: 'stack-verification__checks' }, checks.map((check) => node('li', {
      class: 'stack-verification__check',
      ...(check.status ? { 'data-check-status': check.status } : {}),
    }, check.status ? `${check.label} — ${check.status}` : check.label))) : null,
  ]);
}

const FRESHNESS_LABELS = { live: 'Live', cached: 'Cached', stale: 'Stale', unknown: 'Freshness unknown' };
const FRESHNESS_GLYPHS = { live: '●', cached: '◷', stale: '▲', unknown: '?' };

function FreshnessLabel(props) {
  const freshness = FRESHNESS_LABELS[props.freshness] ? props.freshness : 'unknown';
  const showAsOf = present(props.asOf) && freshness !== 'live';
  return node('span', {
    class: cx('stack-freshness', `stack-freshness--${freshness}`, props.className),
    'data-freshness': freshness,
    ...passthrough(props.attrs),
  }, [
    node('span', { class: 'stack-freshness__glyph', 'aria-hidden': 'true' }, FRESHNESS_GLYPHS[freshness]),
    node('span', { class: 'stack-freshness__label' }, [
      FRESHNESS_LABELS[freshness],
      showAsOf ? [' · as of ', timeNode(props.asOf, 'stack-freshness__as-of')] : null,
      present(props.source) ? ` · ${props.source}` : null,
    ]),
  ]);
}

function Unavailable(props) {
  const status = props.status === 'partial' ? 'partial' : 'unsupported';
  const title = present(props.title) ? props.title : (status === 'partial' ? 'Partly available' : 'Not available');
  return node('div', {
    class: cx('stack-unavailable', `stack-unavailable--${status}`, props.className),
    role: 'note',
    'data-capability-status': status,
    ...(present(props.capability) ? { 'data-capability': props.capability } : {}),
    ...passthrough(props.attrs),
  }, [
    node(props.headingLevel ? heading(props.headingLevel) : 'p', { class: 'stack-unavailable__title' }, title),
    present(props.reason) ? node('p', { class: 'stack-unavailable__reason' }, props.reason) : null,
    props.children || null,
  ]);
}

function Loading(props) {
  const what = present(props.what) ? props.what : '';
  const text = props.long ? `Still loading${what ? ` ${what}` : ''}…` : `Loading${what ? ` ${what}` : ''}…`;
  return node('div', {
    class: cx('stack-loading', props.long ? 'stack-loading--long' : null, props.className),
    role: 'status',
    'aria-live': 'polite',
    ...passthrough(props.attrs),
  }, [
    node('span', { class: 'stack-loading__indicator', 'aria-hidden': 'true' }),
    node('span', { class: 'stack-loading__label' }, text),
  ]);
}

const heading = (level) => `h${Math.min(6, Math.max(1, Number(level) || 2))}`;

function EmptyState(props) {
  const variant = props.variant === 'no-match' ? 'no-match' : 'empty';
  const title = present(props.title) ? props.title : (variant === 'no-match' ? 'Nothing matches' : 'Nothing here yet');
  return node('div', {
    class: cx('stack-empty', `stack-empty--${variant}`, props.className),
    ...passthrough(props.attrs),
  }, [
    node(heading(props.headingLevel), { class: 'stack-empty__title' }, title),
    present(props.body) ? node('p', { class: 'stack-empty__body' }, props.body) : null,
    props.action ? node('div', { class: 'stack-empty__action' }, props.action) : null,
  ]);
}

function ErrorPanel(props) {
  const meta = [
    present(props.code) ? ['Code ', node('code', {}, props.code)] : null,
    present(props.requestId) ? [present(props.code) ? ' · ' : '', 'Request ', node('code', {}, props.requestId)] : null,
  ].filter(Boolean);
  return node('div', {
    class: cx('stack-error', props.className),
    role: 'alert',
    ...passthrough(props.attrs),
  }, [
    node('p', { class: 'stack-error__title' }, present(props.title) ? props.title : 'Something went wrong'),
    present(props.message) ? node('p', { class: 'stack-error__message' }, props.message) : null,
    meta.length ? node('p', { class: 'stack-error__meta' }, meta) : null,
    props.onRetry || props.actions ? node('div', { class: 'stack-error__actions' }, [
      props.onRetry ? Button({ label: props.retryLabel || 'Retry', onClick: props.onRetry }) : null,
      props.actions || null,
    ]) : null,
  ]);
}

function MetadataList(props) {
  return node('dl', { class: cx('stack-meta', props.className), ...passthrough(props.attrs) },
    (props.items || []).map((item) => {
      const missing = !present(item.value) && item.value !== 0 && item.value !== false;
      return node('div', { class: 'stack-meta__item', ...passthrough(item.attrs) }, [
        node('dt', { class: 'stack-meta__label' }, item.label),
        node('dd', {
          class: cx('stack-meta__value', item.mono ? 'stack-meta__value--mono' : null),
          ...(missing ? { 'data-missing': 'true' } : {}),
        }, missing ? '—' : (typeof item.value === 'boolean' ? String(item.value) : item.value)),
        present(item.hint) ? node('dd', { class: 'stack-meta__hint' }, item.hint) : null,
      ]);
    }));
}

function ResourceIdentity(props) {
  const length = Number(props.length) || 12;
  const id = present(props.id) ? String(props.id) : null;
  const truncated = id && id.length > length ? `${id.slice(0, length)}…` : id;
  const name = present(props.name)
    ? node(props.href ? 'a' : 'span', { class: 'stack-identity__name', ...(props.href ? { href: props.href } : {}) }, props.name)
    : null;
  return node('span', { class: cx('stack-identity', props.className), ...passthrough(props.attrs) }, [
    present(props.kind) ? node('span', { class: 'stack-identity__kind' }, props.kind) : null,
    name,
    id ? node('code', { class: 'stack-identity__id', title: id }, truncated === id ? id : [
      node('span', { 'aria-hidden': 'true' }, truncated),
      node('span', { class: 'stack-visually-hidden' }, id),
    ]) : null,
  ]);
}

function PageHeader(props) {
  return node('header', { class: cx('stack-page-header', props.className), ...passthrough(props.attrs) }, [
    present(props.eyebrow) ? node('p', { class: 'stack-page-header__eyebrow' }, props.eyebrow) : null,
    node('div', { class: 'stack-page-header__title-row' }, [
      node(heading(props.headingLevel || 1), { class: 'stack-page-header__title' }, props.title),
      props.status ? node('span', { class: 'stack-page-header__status' }, props.status) : null,
      props.actions ? node('div', { class: 'stack-page-header__actions' }, props.actions) : null,
    ]),
    present(props.description) ? node('p', { class: 'stack-page-header__description' }, props.description) : null,
    props.meta ? node('div', { class: 'stack-page-header__meta' }, props.meta) : null,
  ]);
}

const VARIANTS = ['primary', 'secondary', 'danger', 'ghost'];
const SIZES = ['sm', 'md', 'lg'];

function Button(props) {
  const variant = VARIANTS.includes(props.variant) ? props.variant : 'secondary';
  const size = SIZES.includes(props.size) ? props.size : 'md';
  const inert = Boolean(props.disabled || props.busy);
  return node('button', {
    class: cx('stack-button', `stack-button--${variant}`, `stack-button--${size}`, props.className),
    type: props.type === 'submit' ? 'submit' : 'button',
    ...(inert ? { disabled: true } : {}),
    ...(props.busy ? { 'aria-busy': 'true' } : {}),
    ...passthrough(props.attrs),
  }, [
    props.busy ? node('span', { class: 'stack-button__busy', 'aria-hidden': 'true' }) : null,
    node('span', { class: 'stack-button__label' }, props.label),
  ], props.onClick && !inert ? { click: props.onClick } : undefined);
}

// ---- Navigation and lists (PR3) ---------------------------------------------

/// A resource path. The last item is the current page.
function Breadcrumbs(props) {
  const items = (props.items || []).filter((item) => item && present(item.label));
  return node('nav', {
    class: cx('stack-breadcrumbs', props.className),
    'aria-label': props.label || 'Breadcrumb',
    ...passthrough(props.attrs),
  }, node('ol', { class: 'stack-breadcrumbs__list' }, items.map((item, index) => {
    const last = index === items.length - 1;
    return node('li', { class: 'stack-breadcrumbs__item' }, [
      index > 0 ? node('span', { class: 'stack-breadcrumbs__separator', 'aria-hidden': 'true' }, '/') : null,
      last || !present(item.href)
        ? node('span', { class: 'stack-breadcrumbs__current', ...(last ? { 'aria-current': 'page' } : {}) }, item.label)
        : node('a', { class: 'stack-breadcrumbs__link', href: item.href }, item.label),
    ]);
  })));
}

/// Moves focus between tabs with the arrow keys, Home and End (manual
/// activation: Enter or Space selects, as on any button). Works with a native
/// event and with React's synthetic event alike.
function tabsKeydown(event) {
  const keys = ['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End'];
  if (!keys.includes(event.key)) return;
  const list = event.currentTarget;
  const tabs = Array.from(list.querySelectorAll('[role="tab"]:not([disabled])'));
  if (!tabs.length) return;
  const current = tabs.indexOf(list.ownerDocument.activeElement);
  const vertical = list.getAttribute('aria-orientation') === 'vertical';
  const forward = vertical ? 'ArrowDown' : 'ArrowRight';
  const backward = vertical ? 'ArrowUp' : 'ArrowLeft';
  let next;
  if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = tabs.length - 1;
  else if (event.key === forward) next = current < 0 ? 0 : (current + 1) % tabs.length;
  else if (event.key === backward) next = current < 0 ? tabs.length - 1 : (current - 1 + tabs.length) % tabs.length;
  else return;
  event.preventDefault();
  // Focus moves; tabindex stays on the selected tab, so Tab into the list
  // returns to it, and a renderer that owns the attributes (React) never sees
  // them change underneath it.
  tabs[next].focus();
}

const idPart = (value) => String(value).replace(/[^A-Za-z0-9_-]/g, '-');

const skipToMain = (mainId) => (event) => {
  const main = event.currentTarget.ownerDocument.getElementById(mainId);
  if (!main) return;
  event.preventDefault();
  main.focus();
  if (typeof main.scrollIntoView === 'function') main.scrollIntoView();
};

/// Sections of one resource. Selecting a tab calls `onSelect(id)`; the product
/// decides what that means (show a panel, or change its route).
function Tabs(props) {
  const prefix = idPart(props.idPrefix || 'stack-tabs');
  const tabs = props.tabs || [];
  const active = tabs.some((tab) => tab.id === props.active && !tab.disabled) ? props.active : null;
  return node('div', {
    class: cx('stack-tabs', props.className),
    role: 'tablist',
    ...(present(props.label) ? { 'aria-label': props.label } : {}),
    ...passthrough(props.attrs),
  }, tabs.map((tab, index) => {
    const selected = tab.id === active;
    const focusable = selected || (active === null && index === 0);
    return node('button', {
      class: cx('stack-tabs__tab', selected ? 'stack-tabs__tab--selected' : null, tab.className),
      type: 'button',
      role: 'tab',
      id: `${prefix}-tab-${idPart(tab.id)}`,
      'aria-selected': selected ? 'true' : 'false',
      ...(present(props.panelId) ? { 'aria-controls': props.panelId } : {}),
      tabindex: focusable ? '0' : '-1',
      ...(tab.disabled ? { disabled: true, ...(present(tab.reason) ? { title: tab.reason } : {}) } : {}),
      ...passthrough(tab.attrs),
    }, [
      tab.label,
      present(tab.badge) ? node('span', { class: 'stack-tabs__badge' }, tab.badge) : null,
    ], props.onSelect && !tab.disabled ? { click: () => props.onSelect(tab.id) } : undefined);
  }), { keydown: tabsKeydown });
}

/// The region a tablist controls.
function TabPanel(props) {
  const prefix = idPart(props.idPrefix || 'stack-tabs');
  return node('div', {
    class: cx('stack-tabpanel', props.className),
    role: 'tabpanel',
    id: props.id,
    ...(present(props.active) ? { 'aria-labelledby': `${prefix}-tab-${idPart(props.active)}` } : {}),
    tabindex: '0',
    ...passthrough(props.attrs),
  }, props.children || null);
}

const SORT_GLYPHS = { ascending: '▲', descending: '▼' };

/// Enter or Space on a selectable row selects it, as a click does.
const rowKeydown = (onSelect) => (event) => {
  if (event.target !== event.currentTarget) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  onSelect();
};

/// A list of resources as a table. Rows are keyed by column id, so every row
/// has exactly one cell per header. Loading, failure, empty and no-match are
/// part of the table, not left to each screen.
function DataTable(props) {
  const columns = props.columns || [];
  const rows = props.rows || [];
  const label = present(props.label) ? props.label : 'Table';
  if (props.error) {
    return ErrorPanel({
      title: props.error.title || `${label} could not be read`,
      message: props.error.message,
      code: props.error.code,
      requestId: props.error.requestId,
      onRetry: props.error.onRetry,
      className: cx('stack-table-state', props.className),
      attrs: props.attrs,
    });
  }
  if (props.loading && !rows.length) return Loading({ what: props.loadingWhat || label.toLowerCase(), className: cx('stack-table-state', props.className), attrs: props.attrs });
  if (!rows.length) {
    const noMatch = Boolean(props.noMatch);
    return EmptyState({
      variant: noMatch ? 'no-match' : 'empty',
      title: noMatch ? (props.noMatchTitle || 'Nothing matches') : (props.emptyTitle || 'Nothing here yet'),
      body: noMatch ? props.noMatchBody : props.emptyBody,
      action: noMatch ? null : props.emptyAction,
      headingLevel: props.emptyHeadingLevel || 3,
      className: cx('stack-table-state', props.className),
      attrs: props.attrs,
    });
  }
  const sort = props.sort || {};
  const head = node('thead', {}, node('tr', {}, columns.map((column) => {
    const sorted = sort.column === column.id && SORT_GLYPHS[sort.direction] ? sort.direction : null;
    const content = column.sortable && props.onSort
      ? node('button', {
        class: 'stack-table__sort',
        type: 'button',
      }, [
        column.header,
        node('span', { class: 'stack-table__sort-indicator', 'aria-hidden': 'true' }, sorted ? SORT_GLYPHS[sorted] : '↕'),
      ], { click: () => props.onSort(column.id) })
      : column.header;
    return node('th', {
      class: cx('stack-table__header', column.align === 'end' ? 'stack-table__cell--end' : null),
      scope: 'col',
      ...(column.sortable && props.onSort ? { 'aria-sort': sorted || 'none' } : {}),
    }, content);
  })));
  const body = node('tbody', {}, rows.map((row) => {
    const selectable = typeof row.onSelect === 'function';
    return node('tr', {
      class: cx('stack-table__row', selectable ? 'stack-table__row--selectable' : null, row.selected ? 'stack-table__row--selected' : null, row.className),
      ...(selectable ? { tabindex: '0' } : {}),
      // aria-selected needs a grid; in a table the open row is the current one.
      ...(row.selected ? { 'aria-current': 'true' } : {}),
      ...passthrough(row.attrs),
    }, columns.map((column) => {
      const value = row.cells ? row.cells[column.id] : undefined;
      const missing = value === undefined || value === null;
      return node('td', {
        class: cx('stack-table__cell', column.align === 'end' ? 'stack-table__cell--end' : null),
        ...(missing ? { 'data-missing': 'true' } : {}),
      }, missing ? '—' : value);
    }), selectable ? { click: row.onSelect, keydown: rowKeydown(row.onSelect) } : undefined, row.key);
  }));
  return node('div', {
    class: cx('stack-table', props.className),
    role: 'region',
    'aria-label': label,
    tabindex: '0',
    ...(props.loading ? { 'aria-busy': 'true' } : {}),
    ...passthrough(props.attrs),
  }, node('table', { class: 'stack-table__table' }, [
    node('caption', { class: props.captionVisible ? 'stack-table__caption' : 'stack-visually-hidden' }, label),
    head,
    body,
  ]));
}

/// One labelled filter control: a text input or a select.
function filterControl(filter, prefix, onChange) {
  const id = `${prefix}-${idPart(filter.id)}`;
  const value = present(filter.value) ? String(filter.value) : '';
  const handler = onChange ? (event) => onChange(filter.id, event.target.value) : null;
  const control = filter.type === 'select'
    ? node('select', { class: 'stack-filter__control', id, name: filter.id },
      (filter.options || []).map((option) => {
        const optionValue = String(typeof option === 'object' ? option.value : option);
        return node('option', { value: optionValue, ...(optionValue === value ? { selected: true } : {}) },
          typeof option === 'object' ? option.label : option);
      }), handler ? { change: handler } : undefined)
    : node('input', {
      class: 'stack-filter__control', id, name: filter.id, type: 'search', value,
      ...(present(filter.placeholder) ? { placeholder: filter.placeholder } : {}),
    }, [], handler ? { input: handler } : undefined);
  return node('div', { class: 'stack-filter__field' }, [
    node('label', { class: 'stack-filter__label', for: id }, filter.label),
    control,
  ]);
}

/// Labelled filters for a list. Applying calls `onSubmit()`; the product reads
/// its own filter state and fetches. The result line is announced politely.
function FilterBar(props) {
  const prefix = idPart(props.idPrefix || 'stack-filter');
  const applied = Number(props.applied) || 0;
  return node('form', {
    class: cx('stack-filter', props.className),
    role: 'search',
    'aria-label': props.label || 'Filters',
    ...passthrough(props.attrs),
  }, [
    node('div', { class: 'stack-filter__controls' }, [
      (props.filters || []).map((filter) => filterControl(filter, prefix, props.onChange)),
      node('div', { class: 'stack-filter__actions' }, [
        Button({ label: props.applyLabel || 'Apply', type: 'submit', variant: 'secondary' }),
        applied && props.onClear ? Button({ label: props.clearLabel || 'Clear', variant: 'ghost', onClick: props.onClear }) : null,
      ]),
    ]),
    node('p', { class: 'stack-filter__result', role: 'status', 'aria-live': 'polite' }, present(props.result) ? props.result : ''),
  ], props.onSubmit ? { submit: (event) => { event.preventDefault(); props.onSubmit(); } } : undefined);
}

/// Cursor pagination: previous and next, and whatever summary the product can
/// state truthfully. It never invents a total or a page count.
function Pagination(props) {
  return node('nav', {
    class: cx('stack-pagination', props.className),
    'aria-label': props.label || 'Pagination',
    ...passthrough(props.attrs),
  }, [
    present(props.summary) ? node('p', { class: 'stack-pagination__summary' }, props.summary) : null,
    node('div', { class: 'stack-pagination__actions' }, [
      Button({ label: props.previousLabel || '← Previous', variant: 'ghost', disabled: !props.hasPrevious, onClick: props.onPrevious, attrs: { 'data-page': 'previous' } }),
      Button({ label: props.nextLabel || 'Next →', variant: 'ghost', disabled: !props.hasNext, onClick: props.onNext, attrs: { 'data-page': 'next' } }),
    ]),
  ]);
}

// ---- The product shell (docs/product-shell.md) ----------------------------

const THEME_OPTIONS = Object.freeze([
  { value: 'system', label: 'System theme' },
  { value: 'light', label: 'Light theme' },
  { value: 'dark', label: 'Dark theme' },
]);

/// The page frame every Stack product renders in its own build: product mark,
/// product context, search and account slots, theme preference, this
/// product's navigation, links out to other Stack products, and the main
/// landmark. It renders exactly what it is given: no data, no network, no
/// authorization.
function Shell(props) {
  const product = props.product || {};
  // A product with client-side routing takes ordinary clicks itself; a click
  // with a modifier (new tab, new window) stays a normal link.
  const navigate = (href) => (props.onNavigate ? {
    click: (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      props.onNavigate(href);
    },
  } : undefined);
  const mainId = idPart(props.mainId || 'stack-main');
  const groups = [];
  for (const item of props.navigation || []) {
    const name = item.group || '';
    let group = groups.find((entry) => entry.name === name);
    if (!group) groups.push(group = { name, items: [] });
    group.items.push(item);
  }
  for (const group of groups) group.items.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  const navItem = (item) => node('li', { class: 'stack-shell__nav-entry' }, node('a', {
    class: cx('stack-shell__nav-item', item.className),
    href: item.href,
    ...(item.current ? { 'aria-current': 'page' } : {}),
    ...passthrough(item.attrs),
  }, item.label, navigate(item.href)));
  const theme = props.theme;
  const themeId = `${mainId}-theme`;
  const others = props.otherProducts || [];
  return node('div', { class: cx('stack-shell', props.className), ...passthrough(props.attrs) }, [
    // Focuses the main landmark itself: in a hash-routed product, following
    // `#main` would change the route.
    node('a', { class: 'stack-shell__skip', href: `#${mainId}` }, props.skipLabel || 'Skip to content', { click: skipToMain(mainId) }),
    node('header', { class: 'stack-shell__bar' }, [
      node('a', { class: 'stack-shell__product', href: product.homeHref || '#' }, [
        present(product.mark) ? node('span', { class: 'stack-shell__mark', 'aria-hidden': 'true' }, product.mark) : null,
        node('span', { class: 'stack-shell__product-name' }, product.name || ''),
      ], navigate(product.homeHref || '#')),
      props.context ? node('div', { class: 'stack-shell__context' }, props.context) : null,
      props.search ? node('div', { class: 'stack-shell__search' }, props.search) : null,
      node('div', { class: 'stack-shell__end' }, [
        theme ? node('div', { class: 'stack-shell__prefs' }, [
          node('label', { class: 'stack-visually-hidden', for: themeId }, 'Theme'),
          node('select', { class: 'stack-shell__theme', id: themeId },
            THEME_OPTIONS.map((option) => node('option', {
              value: option.value, ...(option.value === (theme.preference || 'system') ? { selected: true } : {}),
            }, option.label)), theme.onChange ? { change: (event) => theme.onChange(event.target.value) } : undefined),
        ]) : null,
        props.account ? node('div', { class: 'stack-shell__account' }, props.account) : null,
      ]),
    ]),
    node('div', { class: 'stack-shell__body' }, [
      node('nav', { class: 'stack-shell__nav', 'aria-label': `${product.name || 'Product'} navigation` }, [
        groups.map((group) => node('div', { class: 'stack-shell__nav-group' }, [
          present(group.name) ? node('p', { class: 'stack-shell__nav-heading' }, group.name) : null,
          node('ul', { class: 'stack-shell__nav-list' }, group.items.map(navItem)),
        ])),
        present(props.activityHref) ? node('div', { class: 'stack-shell__nav-group stack-shell__activity' },
          node('ul', { class: 'stack-shell__nav-list' }, navItem({ label: props.activityLabel || 'Activity', href: props.activityHref, current: props.activityCurrent }))) : null,
        others.length ? node('div', { class: 'stack-shell__nav-group stack-shell__switcher' }, [
          node('p', { class: 'stack-shell__nav-heading' }, 'Other Stack products'),
          node('ul', { class: 'stack-shell__nav-list' }, others.map((other) => node('li', { class: 'stack-shell__nav-entry' },
            node('a', { class: 'stack-shell__nav-item', href: other.href }, other.name)))),
        ]) : null,
      ]),
      node('main', { class: 'stack-shell__main', id: mainId, tabindex: '-1', ...passthrough(props.mainAttrs) }, props.children || null),
    ]),
  ]);
}

// ---- Forms and dialogs (PR4) ------------------------------------------------

// HTML constraint attributes a field passes to its control unchanged. They
// mirror the product's own rules for the browser; the product still validates.
const CONSTRAINTS = ['pattern', 'min', 'max', 'step', 'minlength', 'maxlength', 'autocomplete', 'inputmode', 'list', 'spellcheck'];

const fieldId = (props) => idPart(present(props.id) ? props.id : `stack-field-${props.name || 'field'}`);

/// The label, hint and error around one control, wired by id: the label is
/// always visible (never a placeholder), and hint and error are announced with
/// the control through aria-describedby.
function field(props, id, control, kind) {
  return node('div', {
    class: cx('stack-field', `stack-field--${kind}`, props.error ? 'stack-field--invalid' : null, props.className),
    ...passthrough(props.attrs),
  }, [
    node('label', { class: 'stack-field__label', for: id }, [
      props.label,
      props.required ? node('span', { class: 'stack-field__required', 'aria-hidden': 'true' }, ' *') : null,
    ]),
    control,
    present(props.hint) ? node('p', { class: 'stack-field__hint', id: `${id}-hint` }, props.hint) : null,
    present(props.error) ? node('p', { class: 'stack-field__error', id: `${id}-error` }, props.error) : null,
  ]);
}

const describedBy = (props, id) => {
  const ids = [present(props.hint) ? `${id}-hint` : null, present(props.error) ? `${id}-error` : null].filter(Boolean);
  return ids.length ? { 'aria-describedby': ids.join(' ') } : {};
};

const controlState = (props, id) => ({
  ...(props.required ? { required: true } : {}),
  ...(props.readOnly ? { readonly: true } : {}),
  ...(props.disabled ? { disabled: true } : {}),
  ...(present(props.error) ? { 'aria-invalid': 'true' } : {}),
  ...describedBy(props, id),
});

/// A labelled text input, or a textarea with `multiline`. `onChange(value)` is
/// called on every edit; without it the control is uncontrolled and a form
/// reads it on submit.
function TextField(props) {
  const id = fieldId(props);
  // A value is rendered only when the product gives one ('' included), so a
  // field with onChange and no value stays free to type in, in every renderer.
  const given = props.value !== undefined && props.value !== null;
  const value = given ? String(props.value) : null;
  const handler = props.onChange ? { input: (event) => props.onChange(event.target.value) } : undefined;
  const constraints = {};
  for (const name of CONSTRAINTS) if (present(props[name])) constraints[name] = String(props[name]);
  const shared = {
    class: 'stack-field__control',
    id,
    ...(present(props.name) ? { name: props.name } : {}),
    ...(present(props.placeholder) ? { placeholder: props.placeholder } : {}),
    ...constraints,
    ...controlState(props, id),
  };
  const control = props.multiline
    ? node('textarea', { ...shared, rows: String(Number(props.rows) || 4) }, given ? value : [], handler)
    : node('input', { ...shared, type: props.type || 'text', ...(given ? { value } : {}) }, [], handler);
  return field(props, id, control, props.multiline ? 'multiline' : 'text');
}

/// A labelled select. Options are strings or `{value, label, disabled}`.
function Select(props) {
  const id = fieldId(props);
  const value = present(props.value) ? String(props.value) : null;
  const handler = props.onChange ? { change: (event) => props.onChange(event.target.value) } : undefined;
  const control = node('select', {
    class: 'stack-field__control',
    id,
    ...(present(props.name) ? { name: props.name } : {}),
    ...controlState(props, id),
  }, (props.options || []).map((option) => {
    const optionValue = String(typeof option === 'object' ? option.value : option);
    return node('option', {
      value: optionValue,
      ...(optionValue === value ? { selected: true } : {}),
      ...(typeof option === 'object' && option.disabled ? { disabled: true } : {}),
    }, typeof option === 'object' ? option.label : option);
  }), handler);
  return field(props, id, control, 'select');
}

/// A form of labelled fields with one submit button. Submitting never
/// navigates: `onSubmit(event)` is called and the product sends the request.
/// `busy` marks the submit button while that request is in flight.
function Form(props) {
  return node('form', {
    class: cx('stack-form', props.layout === 'inline' ? 'stack-form--inline' : null, props.className),
    ...(present(props.label) ? { 'aria-label': props.label } : {}),
    ...(present(props.id) ? { id: idPart(props.id) } : {}),
    ...(props.busy ? { 'aria-busy': 'true' } : {}),
    ...passthrough(props.attrs),
  }, [
    node('div', { class: 'stack-form__fields' }, props.children || null),
    node('div', { class: 'stack-form__actions' }, [
      Button({ label: props.submitLabel || 'Save', type: 'submit', variant: props.submitVariant || 'primary', busy: props.busy }),
      props.actions || null,
    ]),
  ], {
    submit: (event) => {
      event.preventDefault();
      if (props.onSubmit) props.onSubmit(event);
    },
  });
}

/// A modal dialog's structure (a native <dialog>). Opening it is the
/// renderer's job: `openDialog` in dom.js, or the React binding's `open` prop.
/// Esc never closes it by itself: it calls `onClose`, as the Cancel action
/// does, and a dialog without `onClose` (one that is busy) stays open.
function Dialog(props) {
  const id = idPart(props.id || 'stack-dialog');
  const described = [present(props.description) ? `${id}-description` : null, ...(props.describedBy || [])].filter(Boolean);
  return node('dialog', {
    class: cx('stack-dialog', props.className),
    id,
    ...(props.role === 'alertdialog' ? { role: 'alertdialog' } : {}),
    'aria-labelledby': `${id}-title`,
    ...(described.length ? { 'aria-describedby': described.join(' ') } : {}),
    ...passthrough(props.attrs),
  }, node('div', { class: 'stack-dialog__surface' }, [
    node('h2', { class: 'stack-dialog__title', id: `${id}-title` }, props.title),
    present(props.description) ? node('p', { class: 'stack-dialog__description', id: `${id}-description` }, props.description) : null,
    props.children ? node('div', { class: 'stack-dialog__body' }, props.children) : null,
    props.actions ? node('div', { class: 'stack-dialog__actions' }, props.actions) : null,
  ]), {
    cancel: (event) => { event.preventDefault(); if (props.onClose) props.onClose(); },
  });
}

/// Confirms a destructive or irreversible action (contract §7.8). It lists the
/// consequences the product states, names the action on its button (never
/// "OK"), and, with `requireText`, stays disabled until that text is typed.
/// `busy` and `error` show the request the confirmation started; the product
/// reports the outcome.
function ConfirmAction(props) {
  const id = idPart(props.id || 'stack-confirm');
  const consequences = (props.consequences || []).filter(present);
  const typedOk = !present(props.requireText) || props.typed === props.requireText;
  return Dialog({
    id,
    role: 'alertdialog',
    title: props.title,
    description: props.description,
    // The consequences are what the person must hear when the dialog opens.
    describedBy: consequences.length ? [`${id}-consequences`] : [],
    className: cx('stack-confirm', props.className),
    attrs: props.attrs,
    onClose: props.busy ? null : props.onCancel,
    children: [
      consequences.length ? node('ul', { class: 'stack-confirm__consequences', id: `${id}-consequences` }, consequences.map((text) => node('li', {}, text))) : null,
      present(props.requireText) ? TextField({
        id: `${id}-typed`,
        name: 'confirm',
        label: props.requireTextLabel || `Type ${props.requireText} to confirm`,
        value: props.typed === undefined || props.typed === null ? '' : props.typed,
        autocomplete: 'off',
        spellcheck: 'false',
        disabled: props.busy,
        onChange: props.onTypedChange,
      }) : null,
      props.error ? ErrorPanel({
        title: props.error.title || 'Not done',
        message: props.error.message,
        code: props.error.code,
        requestId: props.error.requestId,
      }) : null,
    ],
    actions: [
      Button({ label: props.cancelLabel || 'Cancel', variant: 'ghost', disabled: props.busy, onClick: props.onCancel, attrs: { 'data-dialog-cancel': 'true' } }),
      Button({ label: props.confirmLabel, variant: 'danger', busy: props.busy, disabled: !typedOk, onClick: props.onConfirm, attrs: { 'data-dialog-confirm': 'true' } }),
    ],
  });
}

const COMPONENTS = Object.freeze({
  Breadcrumbs, Tabs, TabPanel, DataTable, FilterBar, Pagination, Shell,
  StatusIndicator, VerificationBadge, FreshnessLabel, Unavailable, Loading, EmptyState,
  ErrorPanel, MetadataList, ResourceIdentity, PageHeader, Button,
  TextField, Select, Form, Dialog, ConfirmAction,
});

// ---- dom.js
// Framework-free rendering of view trees into DOM nodes. Builds nodes with
// createElement / createTextNode / setAttribute only: it never parses markup
// or evaluates code. The built bundle must not even name those APIs, because
// Compute scans its served script for them literally (scripts/check-boundary.mjs).


/// Render a view tree (or string, number, array, Node) to a DOM Node.
function toDom(value, doc) {
  const d = doc || document;
  if (value === null || value === undefined || value === false || value === true) return d.createDocumentFragment();
  if (typeof value === 'string' || typeof value === 'number') return d.createTextNode(String(value));
  if (Array.isArray(value)) {
    const fragment = d.createDocumentFragment();
    for (const item of value) fragment.appendChild(toDom(item, d));
    return fragment;
  }
  if (isTree(value)) {
    const element = d.createElement(value.t);
    for (const [key, attr] of Object.entries(value.a)) {
      if (attr === null || attr === undefined || attr === false) continue;
      element.setAttribute(key, attr === true ? '' : String(attr));
    }
    for (const [event, handler] of Object.entries(value.on || {})) element.addEventListener(event, handler);
    for (const child of value.c) element.appendChild(toDom(child, d));
    return element;
  }
  if (value && typeof value.nodeType === 'number') return value;
  throw new TypeError('toDom: unsupported child');
}

/// Moves focus to the shell's main landmark after a route change, so keyboard
/// and screen-reader users start at the new page's content.
function focusMain(id, doc) {
  const d = doc || document;
  // The same normalisation Shell applies to its mainId.
  const main = d.getElementById(String(id || 'stack-main').replace(/[^A-Za-z0-9_-]/g, '-'));
  if (main && typeof main.focus === 'function') main.focus({ preventScroll: true });
}

/// Each component as a function returning a DOM element, e.g.
///   StackUI.dom.StatusIndicator({ field: 'compute.health', value: 'healthy' })
const dom = Object.freeze(Object.fromEntries(
  Object.entries(COMPONENTS).map(([name, component]) => [name, (props, doc) => toDom(component(props || {}), doc)]),
));

// ---- Dialogs (PR4) -----------------------------------------------------------

/// Opens a rendered <dialog> as a modal and returns a function that closes it.
/// On close the dialog is removed and focus returns to whatever had it before
/// (normally the button that asked), as the dialog pattern requires.
function openDialog(dialog, doc) {
  const d = doc || dialog.ownerDocument || document;
  const returnTo = d.activeElement;
  if (!dialog.isConnected) d.body.appendChild(dialog);
  dialog.showModal();
  let closed = false;
  return function close() {
    if (closed) return;
    closed = true;
    if (dialog.open) dialog.close();
    dialog.remove();
    if (returnTo && returnTo.isConnected && typeof returnTo.focus === 'function') returnTo.focus();
  };
}

const failureOf = (error) => ({
  message: error && error.message ? error.message : String(error),
  ...(error && error.code ? { code: String(error.code) } : {}),
  ...(error && error.requestId ? { requestId: String(error.requestId) } : {}),
});

/// Asks for confirmation with ConfirmAction and resolves `true` once the
/// action is done, or `false` if the person cancels. With `action` (an async
/// function) the dialog stays open while it runs, shows it as busy, and shows
/// its error in place if it fails, so the person can retry or cancel; the
/// dialog closes only after the product reports success.
function confirmAction(props, doc) {
  const d = doc || document;
  let typed = '';
  let state = { busy: false, error: null };
  return new Promise((resolve) => {
    let dialog;
    let close;
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      close();
      resolve(result);
    };
    const render = () => toDom(ConfirmAction({
      ...props,
      ...state,
      typed,
      onTypedChange: (value) => {
        typed = value;
        // This helper owns the DOM it built, so it updates the one attribute
        // that depends on the typed text rather than rebuilding the dialog.
        const confirm = dialog.querySelector('[data-dialog-confirm]');
        confirm.disabled = value !== props.requireText || state.busy;
      },
      onCancel: () => { if (!state.busy) finish(false); },
      // Confirm is handled by delegation below: the button's disabled state
      // changes as text is typed, without rebuilding it.
      onConfirm: undefined,
    }), d);
    const confirm = async () => {
      if (!props.action) { finish(true); return; }
      update({ busy: true, error: null });
      try {
        await props.action();
        finish(true);
      } catch (error) {
        update({ busy: false, error: failureOf(error) });
      }
    };
    const update = (next) => {
      state = next;
      const fresh = render();
      dialog.replaceChildren(...fresh.childNodes);
      for (const attr of Array.from(fresh.attributes)) dialog.setAttribute(attr.name, attr.value);
      const target = dialog.querySelector(state.error ? '[data-dialog-confirm]' : '[data-dialog-cancel]');
      if (target && !target.disabled) target.focus();
    };
    dialog = render();
    dialog.addEventListener('click', (event) => {
      const button = event.target.closest('[data-dialog-confirm]');
      if (button && !button.disabled && !state.busy) confirm();
    });
    // The browser may close a modal itself (a repeated Esc). While the action
    // runs the dialog is shown again; otherwise that is a cancel.
    dialog.addEventListener('close', () => {
      if (done) return;
      if (state.busy) dialog.showModal();
      else finish(false);
    });
    close = openDialog(dialog, d);
    const first = dialog.querySelector(filled(props.requireText) ? 'input' : '[data-dialog-cancel]');
    if (first) first.focus();
  });
}

// Named apart from view.js's helpers: the classic build shares one scope.
const filled = (value) => value !== null && value !== undefined && value !== '';

/// A dialog holding a short form of labelled fields (the replacement for
/// `prompt()`). Resolves with the submitted values once `action(values)`
/// succeeds, or `null` if the person cancels. While `action` runs the submit
/// button is busy; its error is shown in the dialog.
function formDialog(props, doc) {
  const d = doc || document;
  const id = String(props.id || 'stack-form-dialog').replace(/[^A-Za-z0-9_-]/g, '-');
  return new Promise((resolve) => {
    let close;
    let busy = false;
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      close();
      resolve(result);
    };
    const dialog = toDom(Dialog({
      id,
      title: props.title,
      description: props.description,
      className: 'stack-form-dialog',
      onClose: () => { if (!busy) finish(null); },
    }), d);
    const body = d.createElement('div');
    body.className = 'stack-dialog__body';
    const errorSlot = d.createElement('div');
    const renderForm = () => toDom(Form({
      id: `${id}-form`,
      submitLabel: props.submitLabel || 'Save',
      busy,
      actions: Button({ label: props.cancelLabel || 'Cancel', variant: 'ghost', disabled: busy, onClick: () => { if (!busy) finish(null); }, attrs: { 'data-dialog-cancel': 'true' } }),
      children: (props.fields || []).map((fieldProps, index) => (fieldProps.options
        ? Select({ id: `${id}-field-${index}`, ...fieldProps })
        : TextField({ id: `${id}-field-${index}`, ...fieldProps }))),
      onSubmit: async (event) => {
        const values = Object.fromEntries(new FormData(event.target));
        if (!props.action) { finish(values); return; }
        busy = true;
        setBusy(event.target, true);
        errorSlot.replaceChildren();
        try {
          await props.action(values);
          finish(values);
        } catch (error) {
          busy = false;
          setBusy(event.target, false);
          errorSlot.replaceChildren(toDom(ErrorPanel({ title: 'Not saved', ...failureOf(error) }), d));
          event.target.querySelector('button[type="submit"]').focus();
        }
      },
    }), d);
    // Busy state without rebuilding the form, so typed values stay put.
    const setBusy = (form, value) => {
      for (const control of form.querySelectorAll('input, select, textarea, button')) control.disabled = value;
      const submit = form.querySelector('button[type="submit"]');
      if (value) submit.setAttribute('aria-busy', 'true'); else submit.removeAttribute('aria-busy');
    };
    body.append(errorSlot, renderForm());
    dialog.querySelector('.stack-dialog__surface').appendChild(body);
    dialog.addEventListener('close', () => {
      if (done) return;
      if (busy) dialog.showModal();
      else finish(null);
    });
    close = openDialog(dialog, d);
    const first = dialog.querySelector('input, select, textarea');
    if (first) first.focus();
  });
}

global.StackUI = Object.freeze({ version: "0.3.0", TONES, GLYPHS, OUTCOMES, OUTCOME_LABELS, VERIFICATION_STATES, FRESHNESS_STATES, CAPABILITY_STATES, humanize, fields, valuesOf, resolve, verification, verificationOf, freshnessOf, capability, isTree, formatTime, StatusIndicator, VerificationBadge, FreshnessLabel, Unavailable, Loading, EmptyState, ErrorPanel, MetadataList, ResourceIdentity, PageHeader, Button, Breadcrumbs, tabsKeydown, Tabs, TabPanel, DataTable, FilterBar, Pagination, THEME_OPTIONS, Shell, TextField, Select, Form, Dialog, ConfirmAction, COMPONENTS, toDom, focusMain, dom, openDialog, confirmAction, formDialog });
})(typeof window !== 'undefined' ? window : globalThis);
