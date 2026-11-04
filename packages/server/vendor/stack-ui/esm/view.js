// Component structure (docs/design-system-contract.md §4–5) as plain trees:
//   { t: tag, a: attributes, c: children, on: { event: handler } }
// Children are trees, strings, numbers, null/false (skipped), arrays, or opaque
// slot content (a DOM Node or a React element) passed through untouched.
// dom.js and the React binding both render these trees, so the DOM a component
// produces is the same in every product.

import { GLYPHS, humanize, resolve, verification } from './states.js';
import { PORTFOLIO, portfolioProduct } from './brand.js';

// `k` is an optional identity among siblings (React's key); dom.js ignores it.
const node = (t, a, c, on, k) => ({ t, a: a || {}, c: c === undefined ? [] : [].concat(c), ...(on ? { on } : {}), ...(k === undefined || k === null ? {} : { k: String(k) }) });
export const isTree = (value) => Boolean(value && typeof value === 'object' && typeof value.t === 'string' && value.a && Array.isArray(value.c));

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
export function formatTime(value) {
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

export function StatusIndicator(props) {
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

export function VerificationBadge(props) {
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

export function FreshnessLabel(props) {
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

export function Unavailable(props) {
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

export function Loading(props) {
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

export function EmptyState(props) {
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

export function ErrorPanel(props) {
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

export function MetadataList(props) {
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

export function ResourceIdentity(props) {
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

export function PageHeader(props) {
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

export function Button(props) {
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
export function Breadcrumbs(props) {
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
export function tabsKeydown(event) {
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
export function Tabs(props) {
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
export function TabPanel(props) {
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
export function DataTable(props) {
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
export function FilterBar(props) {
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
        // Live filters apply as they change, so there is nothing to submit.
        props.live ? null : Button({ label: props.applyLabel || 'Apply', type: 'submit', variant: 'secondary' }),
        applied && props.onClear ? Button({ label: props.clearLabel || 'Clear', variant: 'ghost', onClick: props.onClear }) : null,
      ]),
    ]),
    node('p', { class: 'stack-filter__result', role: 'status', 'aria-live': 'polite' }, present(props.result) ? props.result : ''),
  ], props.onSubmit || props.live ? {
    // Submitting a filter form never navigates (a single text field submits
    // on Enter even with no button).
    submit: (event) => { event.preventDefault(); if (props.onSubmit) props.onSubmit(); },
  } : undefined);
}

/// Cursor pagination: previous and next, and whatever summary the product can
/// state truthfully. It never invents a total or a page count.
export function Pagination(props) {
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

export const THEME_OPTIONS = Object.freeze([
  { value: 'system', label: 'System theme' },
  { value: 'light', label: 'Light theme' },
  { value: 'dark', label: 'Dark theme' },
]);

/// The page frame every Stack product renders in its own build: product mark,
/// product context, search and account slots, theme preference, this
/// product's navigation, links out to other Stack products, and the main
/// landmark. It renders exactly what it is given: no data, no network, no
/// authorization.
export function Shell(props) {
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
  // A product in the Boundry portfolio lists its siblings by default; a
  // product passes `otherProducts` to choose (or [] to show none).
  const others = props.otherProducts
    || (present(product.id) && portfolioProduct(product.id)
      ? PORTFOLIO.products.filter((entry) => entry.id !== product.id).map((entry) => ({ name: entry.name, href: entry.href }))
      : []);
  const family = present(product.id) && portfolioProduct(product.id) && props.family !== false;
  return node('div', {
    class: cx('stack-shell', props.className),
    ...(present(product.id) ? { 'data-stack-product': product.id } : {}),
    ...passthrough(props.attrs),
  }, [
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
        family ? node('a', { class: 'stack-shell__family', href: PORTFOLIO.company.href }, [
          BrandMark({ idPrefix: `${mainId}-family-mark` }),
          node('span', {}, ['A ', PORTFOLIO.company.name, ' product']),
        ]) : null,
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
        others.length || family ? node('div', { class: 'stack-shell__nav-group stack-shell__switcher' }, [
          node('p', { class: 'stack-shell__nav-heading' }, props.otherProductsLabel || 'Other Boundry products'),
          node('ul', { class: 'stack-shell__nav-list' }, [
            others.map((other) => node('li', { class: 'stack-shell__nav-entry' },
              node('a', { class: 'stack-shell__nav-item', href: other.href }, other.name))),
            family ? node('li', { class: 'stack-shell__nav-entry' }, node('a', { class: 'stack-shell__nav-item stack-shell__nav-item--company', href: PORTFOLIO.company.href }, ['About ', PORTFOLIO.company.name])) : null,
          ]),
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
export function TextField(props) {
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
export function Select(props) {
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
export function Form(props) {
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
export function Dialog(props) {
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
export function ConfirmAction(props) {
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

// ---- Evidence (PR5) -------------------------------------------------------

/// What a record shows and on what basis (contract §5, §7.9). Each claim has
/// its own label and value. A claim the product checked carries its
/// verification, shown with VerificationBadge; a claim without one is a
/// recorded fact, and the summary says so instead of implying it was checked.
export function EvidenceSummary(props) {
  const id = idPart(props.id || 'stack-evidence');
  const claims = (props.claims || []).filter((claim) => claim && present(claim.label));
  // A claim counts as checked only when a check was made: verified, failed,
  // or not verified. "Not evaluated" (including "verified" with no check
  // listed) is a record, like a claim with no verification at all.
  const states = claims.map((claim) => (present(claim.verification) ? verification(claim.verification, claim.checks).state : 'not_evaluated'));
  const checked = states.filter((value) => value !== 'not_evaluated');
  const verified = checked.filter((value) => value === 'verified').length;
  const failed = checked.filter((value) => value === 'verification_failed').length;
  const recorded = states.length - checked.length;
  const state = checked.length === 0 ? 'recorded' : verified === checked.length && recorded === 0 ? 'verified' : 'partial';
  const recordedNote = recorded ? ` · ${recorded} recorded, not checked` : '';
  const summary = state === 'recorded'
    ? 'Recorded facts · not independently verified'
    : state === 'verified'
      ? (checked.length === 1 ? 'Verified' : `All ${checked.length} claims verified`)
      : `${verified} of ${checked.length} checked claims verified${failed ? ` · ${failed} failed` : ''}${recordedNote}`;
  return node('section', {
    class: cx('stack-evidence', `stack-evidence--${state}`, props.className),
    'aria-labelledby': `${id}-title`,
    'data-evidence': state,
    ...passthrough(props.attrs),
  }, [
    node('div', { class: 'stack-evidence__header' }, [
      node(heading(props.headingLevel || 2), { class: 'stack-evidence__title', id: `${id}-title` }, present(props.title) ? props.title : 'Evidence'),
      props.outcome ? node('div', { class: 'stack-evidence__outcome' }, props.outcome) : null,
    ]),
    node('p', { class: 'stack-evidence__summary' }, summary),
    claims.length ? node('dl', { class: 'stack-evidence__claims' }, claims.map((claim) => {
      const missing = !present(claim.value) && claim.value !== 0 && claim.value !== false;
      return node('div', {
        class: 'stack-evidence__claim',
        ...(present(claim.verification) ? { 'data-verification': verification(claim.verification, claim.checks).state } : {}),
        ...passthrough(claim.attrs),
      }, [
        node('dt', { class: 'stack-evidence__label' }, claim.label),
        node('dd', {
          class: cx('stack-evidence__value', claim.mono ? 'stack-evidence__value--mono' : null),
          ...(missing ? { 'data-missing': 'true' } : {}),
        }, missing ? '—' : (typeof claim.value === 'boolean' ? String(claim.value) : claim.value)),
        present(claim.verification) ? node('dd', { class: 'stack-evidence__check' }, VerificationBadge({
          state: claim.verification, checks: claim.checks, evidenceHref: claim.evidenceHref,
        })) : null,
      ]);
    })) : null,
    present(props.source) || present(props.recordedAt)
      ? node('p', { class: 'stack-evidence__source' }, [
        present(props.source) ? props.source : 'Recorded',
        present(props.recordedAt) ? [' · ', timeNode(props.recordedAt, 'stack-evidence__at')] : null,
      ])
      : null,
  ]);
}

// ---- Notices, choices and history (0.6.0) ------------------------------------

const ALERT_TONES = ['info', 'attention', 'critical'];
const ALERT_GLYPHS = { info: 'i', attention: '▲', critical: '✕' };

/// A persistent page-level notice (contract §5). Critical notices interrupt
/// (role=alert); info and attention are announced politely (role=status).
/// Information is not a state: an Alert never stands in for a StatusIndicator.
export function Alert(props) {
  const tone = ALERT_TONES.includes(props.tone) ? props.tone : 'info';
  return node('div', {
    class: cx('stack-alert', `stack-alert--${tone}`, props.className),
    role: tone === 'critical' ? 'alert' : 'status',
    'data-tone': tone,
    ...passthrough(props.attrs),
  }, [
    node('span', { class: 'stack-alert__glyph', 'aria-hidden': 'true' }, ALERT_GLYPHS[tone]),
    node('div', { class: 'stack-alert__content' }, [
      present(props.title) ? node('p', { class: 'stack-alert__title' }, props.title) : null,
      props.children ? node('div', { class: 'stack-alert__body' }, props.children) : null,
      props.actions ? node('div', { class: 'stack-alert__actions' }, props.actions) : null,
    ]),
  ]);
}

/// One labelled checkbox. The label is the control's name and is always
/// visible; hint and error are described by id, as for every field.
/// `onChange(checked)` is called on every change; without it the box is
/// uncontrolled and a form reads it on submit.
export function Checkbox(props) {
  const id = fieldId(props);
  const given = props.checked !== undefined && props.checked !== null;
  const control = node('input', {
    class: 'stack-checkbox__control',
    type: 'checkbox',
    id,
    ...(present(props.name) ? { name: props.name } : {}),
    ...(present(props.value) ? { value: String(props.value) } : {}),
    ...(given && props.checked ? { checked: true } : {}),
    ...controlState(props, id),
  }, [], props.onChange ? { change: (event) => props.onChange(Boolean(event.target.checked)) } : undefined);
  return node('div', {
    class: cx('stack-checkbox', props.error ? 'stack-checkbox--invalid' : null, props.className),
    ...passthrough(props.attrs),
  }, [
    node('div', { class: 'stack-checkbox__row' }, [
      control,
      node('label', { class: 'stack-checkbox__label', for: id }, [
        props.label,
        props.required ? node('span', { class: 'stack-field__required', 'aria-hidden': 'true' }, ' *') : null,
      ]),
    ]),
    present(props.hint) ? node('p', { class: 'stack-field__hint', id: `${id}-hint` }, props.hint) : null,
    present(props.error) ? node('p', { class: 'stack-field__error', id: `${id}-error` }, props.error) : null,
  ]);
}

/// Related controls under one visible legend (a set of checkboxes, a pair of
/// fields). The legend names the group for assistive technology; a group
/// error is described on the fieldset.
export function FieldGroup(props) {
  const id = idPart(props.id || 'stack-group');
  const described = [present(props.hint) ? `${id}-hint` : null, present(props.error) ? `${id}-error` : null].filter(Boolean);
  return node('fieldset', {
    class: cx('stack-fieldgroup', props.error ? 'stack-fieldgroup--invalid' : null, props.className),
    id,
    ...(described.length ? { 'aria-describedby': described.join(' ') } : {}),
    ...(props.disabled ? { disabled: true } : {}),
    ...passthrough(props.attrs),
  }, [
    node('legend', { class: 'stack-fieldgroup__legend' }, [
      props.legend,
      props.required ? node('span', { class: 'stack-field__required', 'aria-hidden': 'true' }, ' *') : null,
    ]),
    present(props.hint) ? node('p', { class: 'stack-field__hint', id: `${id}-hint` }, props.hint) : null,
    node('div', { class: 'stack-fieldgroup__controls' }, props.children || null),
    present(props.error) ? node('p', { class: 'stack-field__error', id: `${id}-error` }, props.error) : null,
  ]);
}

/// Events, audit records and history, newest first as the product orders
/// them (contract §5, §7.9). Each item has a time; `actor`, `status`,
/// `detail` and `href` are optional. `hasMore` says older activity exists
/// instead of implying the list is complete. Loading, error and empty are
/// part of the timeline, as they are of DataTable.
export function ActivityTimeline(props) {
  const items = (props.items || []).filter((item) => item && present(item.summary));
  const label = present(props.label) ? props.label : 'Activity';
  let body;
  // `error` is the product's message, or { title, message, code, requestId, onRetry }.
  if (props.error) body = ErrorPanel(typeof props.error === 'string' ? { message: props.error } : props.error);
  else if (props.loading && !items.length) body = Loading({ what: present(props.what) ? props.what : 'activity' });
  else if (!items.length) body = EmptyState({ title: present(props.emptyTitle) ? props.emptyTitle : 'No activity recorded', headingLevel: props.headingLevel || 3 });
  else {
    body = node('ol', { class: 'stack-timeline__list', 'aria-label': label }, items.map((item, index) => node('li', {
      class: 'stack-timeline__item',
      ...passthrough(item.attrs),
    }, [
      node('span', { class: 'stack-timeline__marker', 'aria-hidden': 'true' }),
      node('div', { class: 'stack-timeline__content' }, [
        node('p', { class: 'stack-timeline__summary' }, present(item.href)
          ? node('a', { class: 'stack-timeline__link', href: item.href }, item.summary)
          : item.summary),
        node('p', { class: 'stack-timeline__meta' }, [
          present(item.at) ? timeNode(item.at, 'stack-timeline__at') : node('span', { class: 'stack-timeline__at', 'data-missing': 'true' }, 'Time not recorded'),
          present(item.actor) ? [' · ', node('span', { class: 'stack-timeline__actor' }, item.actor)] : null,
          item.status ? [' ', node('span', { class: 'stack-timeline__status' }, item.status)] : null,
        ]),
        item.detail ? node('div', { class: 'stack-timeline__detail' }, item.detail) : null,
      ]),
    ], undefined, present(item.id) ? item.id : index)));
  }
  return node('section', {
    class: cx('stack-timeline', props.className),
    ...(props.loading ? { 'aria-busy': 'true' } : {}),
    ...passthrough(props.attrs),
  }, [
    body,
    props.hasMore && items.length ? node('p', { class: 'stack-timeline__more' }, [
      present(props.moreHref)
        ? node('a', { href: props.moreHref, class: 'stack-timeline__link' }, props.moreLabel || 'Older activity exists')
        : (props.onMore ? Button({ label: props.moreLabel || 'Load older activity', onClick: props.onMore, busy: Boolean(props.loading) }) : (props.moreLabel || 'Older activity exists')),
    ]) : null,
  ]);
}

// ---- Brand and marketing foundation (0.6.0, docs/brand.md) --------------------

/// The Boundry mark: two bands forming a B, drawn from the company mark
/// tokens so it follows the theme. Decorative unless given a `title`.
export function BrandMark(props) {
  const id = idPart(props.idPrefix || 'stack-brand-mark');
  const titled = present(props.title);
  return node('svg', {
    class: cx('stack-brand-mark', props.className),
    xmlns: 'http://www.w3.org/2000/svg',
    viewBox: '0 0 340 315',
    focusable: 'false',
    ...(titled ? { role: 'img', 'aria-labelledby': `${id}-title` } : { 'aria-hidden': 'true' }),
    ...passthrough(props.attrs),
  }, [
    titled ? node('title', { id: `${id}-title` }, props.title) : null,
    node('defs', {}, node('linearGradient', { id: `${id}-fill`, x1: '0', y1: '0', x2: '340', y2: '0', gradientUnits: 'userSpaceOnUse' }, [
      node('stop', { class: 'stack-brand-mark__start', offset: '0.2' }),
      node('stop', { class: 'stack-brand-mark__end', offset: '0.85' }),
    ])),
    node('path', { fill: `url(#${id}-fill)`, d: 'M0 0H250C298 0 330 38 329 84C328 114 309 135 281 143L0 269V182L225 80H0Z' }),
    node('path', { fill: `url(#${id}-fill)`, d: 'M0 315L290 182C318 172 341 202 340 246C339 288 306 315 268 315Z' }),
  ]);
}

/// The theme control every site and product uses: System (the default,
/// following the operating system), Light or Dark. `onChange(preference)`
/// normally calls setThemePreference from theme.js.
export function ThemeSwitch(props) {
  const id = idPart(props.id || 'stack-theme');
  return node('div', { class: cx('stack-theme-switch', props.className), ...passthrough(props.attrs) }, [
    node('label', { class: 'stack-visually-hidden', for: id }, props.label || 'Theme'),
    node('select', { class: 'stack-theme-switch__control', id, 'data-stack-theme-control': '' },
      THEME_OPTIONS.map((option) => node('option', {
        value: option.value, ...(option.value === (props.preference || 'system') ? { selected: true } : {}),
      }, option.label)), props.onChange ? { change: (event) => props.onChange(event.target.value) } : undefined),
  ]);
}

const productOf = (props) => (props.product ? { ...(portfolioProduct(props.product.id) || {}), ...props.product } : null);

/// Header for a company or product website. The product's identity leads; a
/// product site also carries "A Boundry product" linking to boundry.company.
/// Navigation is ordinary links (it works without JavaScript) and wraps into
/// a scrollable row on narrow screens instead of hiding behind a menu.
export function SiteHeader(props) {
  const company = PORTFOLIO.company;
  const product = productOf(props);
  const name = product ? product.name : company.name;
  const homeHref = present(props.homeHref) ? props.homeHref : '/';
  return node('header', {
    class: cx('stack-site-header', props.className),
    ...(product && present(product.id) ? { 'data-stack-product': product.id } : {}),
    ...passthrough(props.attrs),
  }, [
    node('a', { class: 'stack-site-header__skip', href: `#${idPart(props.mainId || 'main')}` }, props.skipLabel || 'Skip to content'),
    node('div', { class: 'stack-site-header__inner' }, [
      node('div', { class: 'stack-site-header__identity' }, [
        node('a', { class: 'stack-site-header__home', href: homeHref, 'aria-label': `${name} home` }, [
          props.logo ? node('span', { class: 'stack-site-header__logo' }, props.logo)
            : product ? node('span', { class: 'stack-site-header__product-mark', 'aria-hidden': 'true' }, product.mark || name.slice(0, 2))
              : BrandMark({ className: 'stack-site-header__logo', idPrefix: `${idPart(props.mainId || 'main')}-mark` }),
          node('span', { class: 'stack-site-header__name' }, name),
        ]),
        product ? node('a', { class: 'stack-site-header__family', href: company.href }, ['A ', company.name, ' product']) : null,
      ]),
      (props.navigation || []).length ? node('nav', { class: 'stack-site-header__nav', 'aria-label': props.navigationLabel || 'Main' },
        node('ul', { class: 'stack-site-header__nav-list' }, props.navigation.map((item) => node('li', {}, node('a', {
          class: 'stack-site-header__nav-item',
          href: item.href,
          ...(item.current ? { 'aria-current': 'page' } : {}),
          ...passthrough(item.attrs),
        }, item.label))))) : null,
      node('div', { class: 'stack-site-header__end' }, [
        props.theme ? ThemeSwitch({ id: `${idPart(props.mainId || 'main')}-theme`, preference: props.theme.preference, onChange: props.theme.onChange }) : null,
        props.actions || null,
      ]),
    ]),
  ]);
}

/// Footer for a company or product website: the product's own link columns,
/// then the Boundry family — every product, the current one marked, and a
/// link to boundry.company — and the legal line.
export function SiteFooter(props) {
  const company = PORTFOLIO.company;
  const product = productOf(props);
  const columns = props.columns || [];
  const year = present(props.year) ? props.year : null;
  const owner = present(props.owner) ? props.owner : company.name;
  return node('footer', {
    class: cx('stack-site-footer', props.className),
    ...(product && present(product.id) ? { 'data-stack-product': product.id } : {}),
    ...passthrough(props.attrs),
  }, node('div', { class: 'stack-site-footer__inner' }, [
    node('div', { class: 'stack-site-footer__top' }, [
      node('div', { class: 'stack-site-footer__about' }, [
        node('p', { class: 'stack-site-footer__name' }, product ? product.name : company.name),
        present(props.tagline) ? node('p', { class: 'stack-site-footer__tagline' }, props.tagline) : null,
      ]),
      columns.map((column) => node('nav', { class: 'stack-site-footer__column', 'aria-label': column.title }, [
        node('p', { class: 'stack-site-footer__heading' }, column.title),
        node('ul', { class: 'stack-site-footer__list' }, (column.links || []).map((link) => node('li', {}, node('a', {
          class: 'stack-site-footer__link', href: link.href, ...passthrough(link.attrs),
        }, link.label)))),
      ])),
    ]),
    node('nav', { class: 'stack-site-footer__family', 'aria-label': `${company.name} products` }, [
      node('a', { class: 'stack-site-footer__company', href: company.href }, [
        BrandMark({ className: 'stack-site-footer__mark', idPrefix: `${idPart(props.id || 'stack-footer')}-mark` }),
        node('span', {}, product ? company.family : `${company.name} — ${company.tagline}`),
      ]),
      node('ul', { class: 'stack-site-footer__products' }, PORTFOLIO.products.map((entry) => node('li', {
        'data-stack-product': entry.id,
      }, node('a', {
        class: 'stack-site-footer__product',
        href: entry.href,
        ...(product && product.id === entry.id ? { 'aria-current': 'true' } : {}),
      }, [
        node('span', { class: 'stack-site-footer__product-name' }, entry.name),
        node('span', { class: 'stack-site-footer__product-category' }, entry.category),
      ])))),
    ]),
    node('p', { class: 'stack-site-footer__legal' }, [
      `© ${year ? `${year} ` : ''}${owner}`,
      product ? [' · ', product.name, ' is a ', node('a', { href: company.href }, `${company.name} product`)] : null,
      props.legal ? [' · ', props.legal] : null,
    ]),
  ]));
}

export const COMPONENTS = Object.freeze({
  Breadcrumbs, Tabs, TabPanel, DataTable, FilterBar, Pagination, Shell,
  StatusIndicator, VerificationBadge, FreshnessLabel, Unavailable, Loading, EmptyState,
  ErrorPanel, MetadataList, ResourceIdentity, PageHeader, Button,
  TextField, Select, Form, Dialog, ConfirmAction, EvidenceSummary,
  Alert, Checkbox, FieldGroup, ActivityTimeline,
  BrandMark, ThemeSwitch, SiteHeader, SiteFooter,
});
