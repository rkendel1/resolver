// Resolver management pages, rendered with the shared Stack design system (vendor/stack-ui's stateless
// build, loaded before this script as `window.StackUI`), the way AppPort Services renders its own.
// The pages store nothing in the browser: there is no theme control, the colour scheme follows the
// operating system, and the session is an HttpOnly cookie this script never sees.
//
// The server sends one page description (`#resolver-page`: which page, and the navigation). This script
// renders the shell and the page with StackUI's DOM helpers. It builds nodes with createElement and
// textContent only: it never parses markup. Every request goes to this resolver's /_resolver routes.
'use strict';
(function () {
  const S = window.StackUI;
  const config = JSON.parse(document.getElementById('resolver-page').textContent);
  const routeOf = (id) => (config.navigation.find((item) => item.id === id) || { route: '/resolver' }).route;

  // ---- Requests -------------------------------------------------------------

  /// Sends a request and returns its JSON body (null for 204). A failure keeps the product's message and
  /// code; a request that never got an answer says the outcome is unknown rather than guessing it failed.
  async function request(path, method, body) {
    let response;
    try {
      response = await fetch(path, {
        method: method || 'GET',
        credentials: 'same-origin',
        headers: body === undefined ? {} : { 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      const error = new Error('Result unknown — check current state. The request did not get an answer.');
      error.code = 'NO_RESPONSE';
      throw error;
    }
    if (response.status === 204) return null;
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const detail = payload && payload.error;
      const error = new Error((detail && detail.message) || 'The request failed with status ' + response.status + '.');
      error.code = (detail && detail.code) || 'HTTP_' + response.status;
      error.reason = detail && detail.reason;
      error.status = response.status;
      if (response.status === 401 && config.page !== 'sign-in') signIn();
      throw error;
    }
    return payload;
  }
  const failureOf = (error) => ({ message: error.message, code: error.reason || error.code });
  const query = (params) => '?' + new URLSearchParams(params).toString();

  function signIn() {
    const next = location.pathname + location.search;
    location.assign(config.signIn + query({ next }));
  }

  // ---- Small builders --------------------------------------------------------

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      node.setAttribute(name, value === true ? '' : String(value));
    }
    for (const child of [].concat(children === undefined ? [] : children)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
    }
    return node;
  }
  const when = (value) => (value ? el('time', { datetime: value }, S.formatTime(value)) : undefined);
  const code = (value) => el('code', {}, String(value));
  const link = (href, text) => el('a', { href }, text);
  const referenceLink = (ref) => link(routeOf('references') + query({ ref }), ref);
  const state = (value) => S.dom.StatusIndicator({ tone: value === 'revoked' ? 'critical' : 'positive', label: value === 'revoked' ? 'Revoked' : 'Active' });

  /// One line describing a binding target, by kind.
  function describe(kind, value) {
    if (value === null || value === undefined) return '—';
    if (kind === 'model') return value.provider + ' · ' + value.model + (value.endpoint ? ' @ ' + value.endpoint : '');
    if (kind === 'endpoint') return value.url;
    if (kind === 'agent') return value.origin + (value.capabilities ? ' (' + Object.keys(value.capabilities).length + ' pinned)' : '');
    if (kind === 'secret') return 'vault version ' + value.version;
    const text = JSON.stringify(value);
    return text.length > 90 ? text.slice(0, 87) + '…' : text;
  }

  /// "90% stable · 10% canary", "failover: primary → secondary", or the single target.
  function split(binding, kind) {
    if (!binding) return '—';
    const targets = binding.targets || [];
    if (binding.strategy === 'weighted') {
      const total = targets.reduce((sum, t) => sum + (t.weight || 0), 0) || 1;
      return targets.map((t) => Math.round(((t.weight || 0) * 100) / total) + '% ' + describe(kind, t.value) + (t.label ? ' (' + t.label + ')' : '')).join(' · ');
    }
    if (binding.strategy === 'failover') return 'failover: ' + targets.map((t) => describe(kind, t.value) + (t.label ? ' (' + t.label + ')' : '')).join(' → ');
    return describe(kind, targets[0] && targets[0].value);
  }

  /// Where a section reports what happened: a polite status line for success, the shared ErrorPanel for
  /// a failure.
  function outcome() {
    const status = el('p', { class: 'resolver-outcome__ok', role: 'status', tabindex: '-1' });
    const problem = el('div', { class: 'resolver-outcome__problem' });
    const node = el('div', { class: 'resolver-outcome' }, [status, problem]);
    return {
      node,
      ok(message, detail, focus) {
        problem.replaceChildren();
        status.replaceChildren(message, ...(detail ? [detail] : []));
        if (focus) status.focus();
      },
      fail(error, title, onRetry) {
        status.replaceChildren();
        problem.replaceChildren(S.dom.ErrorPanel({ title: title || 'Not done', ...failureOf(error), ...(onRetry ? { onRetry } : {}) }));
      },
      clear() {
        status.replaceChildren();
        problem.replaceChildren();
      },
    };
  }

  /// A list read from the resolver and shown as a DataTable: loading first, then rows, an empty state,
  /// or the error with Retry (reads are safe to retry). Only the newest read may draw.
  function list(options) {
    const node = el('div', { class: 'resolver-list' });
    let rows = [];
    let latest = 0;
    const draw = (extra) => node.replaceChildren(S.dom.DataTable({ label: options.label, columns: options.columns, rows, emptyTitle: options.empty, emptyBody: options.emptyBody, ...extra }));
    async function refresh() {
      const mine = ++latest;
      draw({ loading: true, loadingWhat: options.label.toLowerCase() });
      try {
        const items = await options.read();
        if (mine !== latest) return;
        rows = items.map(options.row);
        draw({ noMatch: items.length === 0 && options.filtered && options.filtered() });
      } catch (error) {
        if (mine !== latest) return;
        rows = [];
        draw({ error: { title: options.label + ' could not be read', ...failureOf(error), onRetry: refresh } });
      }
    }
    return { node, refresh };
  }

  const button = (label, onClick, variant) => S.dom.Button({ label, onClick, ...(variant ? { variant } : {}), size: 'sm' });
  const section = (title, children) => el('section', { 'aria-labelledby': 'section-' + title.replace(/\W+/g, '-').toLowerCase() }, [
    el('h2', { id: 'section-' + title.replace(/\W+/g, '-').toLowerCase() }, title),
    ...children,
  ]);

  /// Parses JSON a person typed, with the parse error as the message.
  function parseJson(text, what) {
    try {
      return JSON.parse(text);
    } catch (error) {
      const failure = new Error(what + ' is not valid JSON: ' + error.message);
      failure.code = 'INVALID_JSON';
      throw failure;
    }
  }

  // ---- Shared reads -------------------------------------------------------------

  /// The signed-in caller, read once per page.
  let sessionRead;
  const readSession = () => (sessionRead = sessionRead || request('/_resolver/session'));

  const readList = (prefix) => request('/_resolver/references' + (prefix ? query({ prefix }) : '')).then((r) => r.refs);
  const readReference = (ref, key) => request('/_resolver/reference' + query(key ? { ref, key } : { ref }));
  let catalog;
  const readCatalog = () => (catalog = catalog || request('/_resolver/catalog').then((r) => r.providers));

  // ---- Pages --------------------------------------------------------------------

  const PAGES = {};

  PAGES.overview = function () {
    const counts = el('ul', { class: 'resolver-cards' }, config.navigation.filter((item) => item.id !== 'overview').map((item) => el('li', { class: 'resolver-card' }, [
      el('h2', { class: 'resolver-card__title' }, link(item.route, item.label)),
      el('p', { class: 'resolver-card__body' }, config.descriptions[item.id] || ''),
      el('p', { class: 'resolver-card__count', 'data-count-for': item.id }),
    ])));
    const recent = list({
      label: 'Recently changed',
      empty: 'No references yet',
      emptyBody: 'Create one on the References page, or with `resolver set`.',
      columns: [
        { id: 'ref', header: 'Reference' },
        { id: 'kind', header: 'Kind' },
        { id: 'revision', header: 'Revision', align: 'end' },
        { id: 'state', header: 'State' },
        { id: 'updated', header: 'Updated' },
      ],
      read: async () => {
        const refs = await readList();
        const byKind = (kind) => refs.filter((r) => r.kind === kind && r.state === 'active').length;
        const set = (id, text) => { const n = counts.querySelector('[data-count-for="' + id + '"]'); if (n) n.textContent = text; };
        const count = (n, one, many) => n + ' ' + (n === 1 ? one : many);
        set('references', count(refs.length, 'reference', 'references'));
        set('models', count(byKind('model'), 'model alias', 'model aliases'));
        set('secrets', count(byKind('secret'), 'secret', 'secrets'));
        return refs.slice().sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1)).slice(0, 8);
      },
      row: (r) => ({ key: r.ref, cells: { ref: referenceLink(r.ref), kind: r.kind, revision: r.revision, state: state(r.state), updated: when(r.updatedAt) } }),
    });
    recent.refresh();
    return [
      S.dom.PageHeader({ title: 'Resolver', description: 'Stable names for models, providers, secrets, endpoints, agents and configuration. Change what a name points to and every running application follows, with no redeploy.' }),
      counts,
      section('Recently changed', [recent.node]),
    ];
  };

  PAGES.references = function () {
    const ref = new URLSearchParams(location.search).get('ref');
    return ref ? referenceDetail(ref) : referenceList();
  };

  function referenceList() {
    const result = outcome();
    let prefix = '';
    let kind = '';
    const table = list({
      label: 'References',
      empty: 'No references yet',
      emptyBody: 'Create the first one with New reference.',
      filtered: () => Boolean(prefix || kind),
      columns: [
        { id: 'ref', header: 'Reference' },
        { id: 'kind', header: 'Kind' },
        { id: 'revision', header: 'Revision', align: 'end' },
        { id: 'state', header: 'State' },
        { id: 'updated', header: 'Updated' },
      ],
      read: async () => (await readList(prefix || undefined)).filter((r) => !kind || r.kind === kind),
      row: (r) => ({ key: r.ref, cells: { ref: referenceLink(r.ref), kind: r.kind, revision: r.revision, state: state(r.state), updated: when(r.updatedAt) } }),
    });
    const filters = el('div', { class: 'resolver-filters' }, [
      S.dom.TextField({ id: 'filter-prefix', label: 'Prefix', hint: 'e.g. ref://prod/', onChange: (v) => { prefix = v.trim(); table.refresh(); } }),
      S.dom.Select({ id: 'filter-kind', label: 'Kind', hint: 'Show one kind of reference.', options: [{ value: '', label: 'Every kind' }, 'value', 'secret', 'model', 'endpoint', 'agent'], onChange: (v) => { kind = v; table.refresh(); } }),
    ]);
    const create = button('New reference', async () => {
      const values = await S.formDialog({
        id: 'new-reference',
        title: 'New reference',
        description: 'A name for something that changes. Its kind is fixed once created. Secrets are created on the Secrets page, models on the Models page.',
        submitLabel: 'Create reference',
        fields: [
          { name: 'ref', label: 'Reference', required: true, hint: 'ref://<namespace>/<name>, e.g. ref://prod/payments/endpoint', spellcheck: 'false', autocomplete: 'off' },
          { name: 'kind', label: 'Kind', options: [{ value: 'value', label: 'Value (JSON configuration)' }, { value: 'endpoint', label: 'Endpoint' }, { value: 'agent', label: 'Agent' }], value: 'value' },
          { name: 'value', label: 'Value (JSON)', required: true, multiline: true, rows: 4, hint: 'Endpoint: {"url":"https://…"}. Agent: {"origin":"https://…","capabilities":{"name@1":"sha256:…"}}.', spellcheck: 'false' },
          { name: 'reason', label: 'Reason', hint: 'Recorded in the history.' },
        ],
        action: async (v) => {
          const done = await request('/_resolver/references', 'POST', { ref: v.ref.trim(), kind: v.kind, binding: { value: parseJson(v.value, 'The value') }, expectedRevision: 0, ...(v.reason ? { reason: v.reason } : {}) });
          result.ok('Created ', code(done.ref + ' at revision ' + done.revision), true);
        },
      });
      if (values) table.refresh();
    }, 'primary');
    table.refresh();
    return [
      S.dom.PageHeader({ title: 'References', description: 'Every name and what it points to. Open one to change it, see its history, roll back or revoke it.', actions: create }),
      result.node,
      filters,
      table.node,
    ];
  }

  function referenceDetail(ref) {
    const result = outcome();
    const header = el('div');
    const binding = el('div');
    const tryKey = el('div');
    const actions = el('div', { class: 'resolver-actions' });
    let current = null;
    let revision = 0;
    let kind = '';

    const history = list({
      label: 'History',
      empty: 'No revisions',
      columns: [
        { id: 'revision', header: 'Revision', align: 'end' },
        { id: 'action', header: 'Change' },
        { id: 'target', header: 'Bound to' },
        { id: 'actor', header: 'By' },
        { id: 'reason', header: 'Reason' },
        { id: 'at', header: 'When' },
        { id: 'act', header: 'Actions' },
      ],
      read: async () => {
        const data = await readReference(ref);
        current = data.current;
        kind = data.summary ? data.summary.kind : '';
        revision = data.history.length ? data.history[data.history.length - 1].revision : 0;
        draw(data);
        return data.history.slice().reverse();
      },
      row: (entry) => ({
        key: String(entry.revision),
        cells: {
          revision: entry.revision,
          action: entry.action + (entry.restoredFrom ? ' (from ' + entry.restoredFrom + ')' : ''),
          target: entry.targets ? el('span', { class: 'resolver-target' }, split({ strategy: entry.strategy, targets: entry.targets }, kind)) : undefined,
          actor: code(entry.actor),
          reason: entry.reason,
          at: when(entry.at),
          act: entry.targets && current && entry.revision !== revision ? button('Roll back to ' + entry.revision, () => rollback(entry.revision)) : undefined,
        },
      }),
    });

    function draw(data) {
      const revoked = data.revoked;
      const c = data.current;
      header.replaceChildren(
        S.dom.Breadcrumbs({ items: [{ label: 'References', href: routeOf('references') }, { label: ref }] }),
        S.dom.PageHeader({
          title: ref,
          status: state(revoked ? 'revoked' : 'active'),
          description: revoked ? 'Revoked: every resolution of this name fails. History is kept.' : undefined,
          meta: c ? S.dom.MetadataList({ items: [
            { label: 'Kind', value: c.kind },
            { label: 'Revision', value: String(c.currentRevision) },
            { label: 'Cache TTL', value: c.ttlSeconds + ' s' },
            { label: 'Updated', value: when(c.updatedAt) },
          ] }) : undefined,
        }),
      );
      if (!c) {
        binding.replaceChildren();
        tryKey.replaceChildren();
        actions.replaceChildren();
        return;
      }
      const total = c.targets.reduce((sum, t) => sum + (t.weight || 0), 0);
      binding.replaceChildren(section('Bound to', [
        el('p', { class: 'resolver-note' }, c.strategy === 'weighted' ? 'Weighted split: each caller key always gets the same target while the weights are unchanged.'
          : c.strategy === 'failover' ? 'Failover: callers try the targets in this order.' : 'A single target.'),
        S.dom.DataTable({
          label: 'Targets',
          columns: [
            { id: 'n', header: '#', align: 'end' },
            { id: 'label', header: 'Label' },
            { id: 'target', header: 'Target' },
            { id: 'share', header: c.strategy === 'weighted' ? 'Share' : 'Order', align: 'end' },
          ],
          rows: c.targets.map((t, i) => ({ key: String(i), cells: {
            n: i + 1,
            label: t.label,
            target: el('span', { class: 'resolver-target' }, describe(c.kind, t.value)),
            share: c.strategy === 'weighted' ? Math.round(((t.weight || 0) * 100) / (total || 1)) + '% (' + (t.weight || 0) + ')' : String(i + 1),
          } })),
        }),
      ]));
      if (c.strategy === 'weighted') {
        const answer = el('p', { role: 'status', class: 'resolver-note' });
        tryKey.replaceChildren(section('Which target does a caller get?', [
          S.dom.Form({
            label: 'Try a caller key',
            layout: 'inline',
            submitLabel: 'Check',
            children: S.dom.TextField({ id: 'try-key', name: 'key', label: 'Caller key', required: true, hint: 'The key the application passes, e.g. a user or tenant id.' }),
            onSubmit: async (event) => {
              const key = new FormData(event.target).get('key');
              try {
                const data = await readReference(ref, key);
                const s = data.current.selected;
                answer.replaceChildren(String(key) + ' gets target ' + (s.index + 1) + (s.label ? ' (' + s.label + ')' : '') + ': ' + describe(data.current.kind, s.value));
              } catch (error) {
                answer.replaceChildren('Could not check: ' + error.message);
              }
            },
          }),
          answer,
        ]));
      } else tryKey.replaceChildren();
      actions.replaceChildren(
        c.kind === 'secret' ? button('Set a new value', setSecret, 'primary') : button('Change binding', editBinding, 'primary'),
        button('Revoke', revoke, 'danger'),
      );
    }

    async function editBinding() {
      const values = await S.formDialog({
        id: 'edit-binding',
        title: 'Change ' + ref,
        description: 'The binding as JSON: {"value": …} for one target, or {"strategy":"weighted"|"failover","targets":[{"value":…,"weight":…,"label":…}]}. Running applications pick it up without a redeploy.',
        submitLabel: 'Save revision ' + (revision + 1),
        fields: [
          { name: 'binding', label: 'Binding (JSON)', required: true, multiline: true, rows: 10, spellcheck: 'false', value: JSON.stringify(current.strategy === 'single' ? { value: current.targets[0].value } : { strategy: current.strategy, targets: current.targets }, null, 2) },
          { name: 'reason', label: 'Reason', hint: 'Recorded in the history.' },
        ],
        action: async (v) => {
          const done = await request('/_resolver/references', 'POST', { ref, binding: parseJson(v.binding, 'The binding'), expectedRevision: revision, ...(v.reason ? { reason: v.reason } : {}) });
          result.ok('Saved revision ' + done.revision + '.', undefined, true);
        },
      });
      if (values) history.refresh();
    }

    async function setSecret() {
      const values = await S.formDialog({
        id: 'set-secret',
        title: 'Set a new value for ' + ref,
        description: 'The value goes to the vault as a new version. It is never shown again, here or anywhere.',
        submitLabel: 'Store new version',
        fields: [
          { name: 'secret', label: 'New value', type: 'password', required: true, autocomplete: 'off' },
          { name: 'reason', label: 'Reason', hint: 'Recorded in the history.' },
        ],
        action: async (v) => {
          const done = await request('/_resolver/references', 'POST', { ref, secret: v.secret, expectedRevision: revision, ...(v.reason ? { reason: v.reason } : {}) });
          result.ok('Stored as revision ' + done.revision + '.', undefined, true);
        },
      });
      if (values) history.refresh();
    }

    async function rollback(to) {
      const done = await S.confirmAction({
        id: 'confirm-rollback',
        title: 'Roll back ' + ref + ' to revision ' + to + '?',
        confirmLabel: 'Roll back',
        consequences: ['The binding of revision ' + to + ' becomes revision ' + (revision + 1) + '.', 'Running applications follow it without a redeploy.', 'Nothing is deleted: the history keeps every revision.'],
        action: () => request('/_resolver/rollback', 'POST', { ref, toRevision: to, expectedRevision: revision }),
      });
      if (done) {
        result.ok('Rolled back to revision ' + to + '.', undefined, true);
        history.refresh();
      }
    }

    async function revoke() {
      const done = await S.confirmAction({
        id: 'confirm-revoke',
        title: 'Revoke ' + ref + '?',
        confirmLabel: 'Revoke',
        requireText: ref,
        consequences: [
          'Every resolution of this name fails from now on, including pinned revisions.',
          'Running applications stop getting it on their next request.',
          kind === 'secret' ? 'The secret material is destroyed in the vault.' : 'The history is kept.',
          'The name can never be used again.',
        ],
        action: () => request('/_resolver/revoke', 'POST', { ref, expectedRevision: revision }),
      });
      if (done) {
        result.ok('Revoked.', undefined, true);
        history.refresh();
      }
    }

    history.refresh();
    return [header, result.node, actions, binding, tryKey, section('History', [history.node])];
  }

  PAGES.models = function () {
    const result = outcome();
    const table = list({
      label: 'Model aliases',
      empty: 'No model aliases yet',
      emptyBody: 'Create one with New model alias. Applications resolve the alias, never a model id.',
      columns: [
        { id: 'ref', header: 'Alias' },
        { id: 'target', header: 'Resolves to' },
        { id: 'revision', header: 'Revision', align: 'end' },
        { id: 'updated', header: 'Updated' },
        { id: 'act', header: 'Actions' },
      ],
      read: async () => {
        const refs = (await readList()).filter((r) => r.kind === 'model' && r.state === 'active');
        return Promise.all(refs.map(async (r) => ({ summary: r, data: await readReference(r.ref) })));
      },
      row: ({ summary, data }) => ({
        key: summary.ref,
        cells: {
          ref: referenceLink(summary.ref),
          target: el('span', { class: 'resolver-target' }, split(data.current, 'model')),
          revision: summary.revision,
          updated: when(summary.updatedAt),
          act: el('span', {}, [
            button('Retarget', () => retarget(summary.ref, data.current)),
            data.current.strategy === 'single' ? button('Start canary', () => canary(summary.ref, data.current)) : null,
            data.current.strategy === 'weighted' ? button('Promote canary', () => promote(summary.ref, data.current)) : null,
          ]),
        },
      }),
    });

    async function modelFields(defaults) {
      const providers = await readCatalog();
      const d = defaults || {};
      return [
        { name: 'provider', label: 'Provider', options: providers.map((p) => ({ value: p.id, label: p.name })), value: d.provider || providers[0].id },
        { name: 'model', label: 'Model', required: true, value: d.model || '', spellcheck: 'false', hint: 'Known models: ' + providers.map((p) => p.id + ' — ' + (p.models.map((m) => m.id).join(', ') || 'any')).join('; ') },
        { name: 'endpoint', label: 'Endpoint (optional)', value: d.endpoint || '', hint: 'Only for providers that take one (ollama, opencode, custom).', spellcheck: 'false' },
        { name: 'credential', label: 'Credential reference', value: d.credential || '', hint: 'A secret reference, e.g. ref://prod/llm/openai-key.', spellcheck: 'false' },
      ];
    }
    const target = (v) => ({
      provider: v.provider,
      model: v.model.trim(),
      ...(v.endpoint && v.endpoint.trim() ? { endpoint: v.endpoint.trim() } : {}),
      ...(v.credential && v.credential.trim() ? { credential: v.credential.trim() } : {}),
    });
    const primary = (current) => current.targets.slice().sort((a, b) => (b.weight || 0) - (a.weight || 0))[0].value;

    async function create() {
      const values = await S.formDialog({
        id: 'new-model',
        title: 'New model alias',
        description: 'Applications resolve this alias. Retarget it later without a redeploy.',
        submitLabel: 'Create alias',
        fields: [{ name: 'ref', label: 'Alias', required: true, hint: 'e.g. ref://prod/chat/model', spellcheck: 'false', autocomplete: 'off' }, ...(await modelFields())],
        action: async (v) => {
          const done = await request('/_resolver/references', 'POST', { ref: v.ref.trim(), kind: 'model', binding: { value: target(v) }, expectedRevision: 0 });
          result.ok('Created ', code(done.ref), true);
        },
      });
      if (values) table.refresh();
    }

    async function retarget(ref, current) {
      const values = await S.formDialog({
        id: 'retarget-model',
        title: 'Retarget ' + ref,
        description: 'Every application resolving this alias moves on its next request. Any traffic split is replaced by this one target.',
        submitLabel: 'Retarget',
        fields: [...(await modelFields(primary(current))), { name: 'reason', label: 'Reason', hint: 'Recorded in the history.' }],
        action: async (v) => {
          await request('/_resolver/references', 'POST', { ref, binding: { value: target(v) }, expectedRevision: current.currentRevision, ...(v.reason ? { reason: v.reason } : {}) });
          result.ok('Retargeted ', code(ref), true);
        },
      });
      if (values) table.refresh();
    }

    async function canary(ref, current) {
      const values = await S.formDialog({
        id: 'canary-model',
        title: 'Start a canary for ' + ref,
        description: 'Send a share of callers to a candidate model. Each caller key sticks to one model while the split is unchanged.',
        submitLabel: 'Start canary',
        fields: [...(await modelFields()), { name: 'percent', label: 'Canary share (%)', type: 'number', min: 1, max: 99, required: true, value: '10' }, { name: 'reason', label: 'Reason' }],
        action: async (v) => {
          const percent = Math.round(Number(v.percent));
          if (!(percent >= 1 && percent <= 99)) {
            const error = new Error('The canary share must be between 1 and 99.');
            error.code = 'INVALID_INPUT';
            throw error;
          }
          await request('/_resolver/references', 'POST', {
            ref,
            binding: { strategy: 'weighted', targets: [{ value: current.targets[0].value, weight: 100 - percent, label: 'stable' }, { value: target(v), weight: percent, label: 'canary' }] },
            expectedRevision: current.currentRevision,
            ...(v.reason ? { reason: v.reason } : {}),
          });
          result.ok('Canary started on ', code(ref), true);
        },
      });
      if (values) table.refresh();
    }

    async function promote(ref, current) {
      const candidate = current.targets.find((t) => t.label === 'canary') || current.targets[current.targets.length - 1];
      const done = await S.confirmAction({
        id: 'confirm-promote',
        title: 'Send all of ' + ref + ' to ' + describe('model', candidate.value) + '?',
        confirmLabel: 'Promote',
        consequences: ['Every caller moves to this model on its next request.', 'The previous split stays in the history; roll back from the reference page.'],
        action: () => request('/_resolver/references', 'POST', { ref, binding: { value: candidate.value }, expectedRevision: current.currentRevision, reason: 'promote canary' }),
      });
      if (done) {
        result.ok('Promoted ', code(ref), true);
        table.refresh();
      }
    }

    table.refresh();
    return [
      S.dom.PageHeader({ title: 'Models', description: 'Model aliases: applications ask for an alias, you decide which provider and model it means, and can split traffic between two.', actions: button('New model alias', create, 'primary') }),
      result.node,
      table.node,
    ];
  };

  PAGES.secrets = function () {
    const result = outcome();
    const table = list({
      label: 'Secrets',
      empty: 'No secrets yet',
      emptyBody: 'Store an API key or credential with New secret.',
      columns: [
        { id: 'ref', header: 'Reference' },
        { id: 'version', header: 'Vault version', align: 'end' },
        { id: 'state', header: 'State' },
        { id: 'updated', header: 'Updated' },
        { id: 'act', header: 'Actions' },
      ],
      read: async () => {
        const refs = (await readList()).filter((r) => r.kind === 'secret');
        return Promise.all(refs.map(async (r) => ({ summary: r, data: r.state === 'active' ? await readReference(r.ref) : null })));
      },
      row: ({ summary, data }) => ({
        key: summary.ref,
        cells: {
          ref: referenceLink(summary.ref),
          version: data && data.current ? data.current.selected.value.version : undefined,
          state: state(summary.state),
          updated: when(summary.updatedAt),
          act: summary.state === 'active' ? el('span', {}, [button('Set new value', () => setValue(summary.ref, summary.revision)), button('Revoke', () => revoke(summary.ref, summary.revision), 'danger')]) : undefined,
        },
      }),
    });

    async function create() {
      const values = await S.formDialog({
        id: 'new-secret',
        title: 'New secret',
        description: 'The value goes to the encrypted vault. It is never shown again; applications with a reveal grant read it at run time.',
        submitLabel: 'Store secret',
        fields: [
          { name: 'ref', label: 'Reference', required: true, hint: 'e.g. ref://prod/llm/openai-key', spellcheck: 'false', autocomplete: 'off' },
          { name: 'secret', label: 'Value', type: 'password', required: true, autocomplete: 'off' },
        ],
        action: async (v) => {
          const done = await request('/_resolver/references', 'POST', { ref: v.ref.trim(), kind: 'secret', secret: v.secret, expectedRevision: 0 });
          result.ok('Stored ', code(done.ref), true);
        },
      });
      if (values) table.refresh();
    }

    async function setValue(ref, revision) {
      const values = await S.formDialog({
        id: 'rotate-secret',
        title: 'Set a new value for ' + ref,
        description: 'Stored as a new vault version. Applications get it on their next request.',
        submitLabel: 'Store new version',
        fields: [{ name: 'secret', label: 'New value', type: 'password', required: true, autocomplete: 'off' }, { name: 'reason', label: 'Reason' }],
        action: async (v) => {
          await request('/_resolver/references', 'POST', { ref, secret: v.secret, expectedRevision: revision, ...(v.reason ? { reason: v.reason } : {}) });
          result.ok('New value stored for ', code(ref), true);
        },
      });
      if (values) table.refresh();
    }

    async function revoke(ref, revision) {
      const done = await S.confirmAction({
        id: 'confirm-revoke-secret',
        title: 'Revoke ' + ref + '?',
        confirmLabel: 'Revoke and destroy',
        requireText: ref,
        consequences: ['The secret material is destroyed in the vault and cannot be recovered.', 'Every application using it stops getting it on its next request.', 'The name can never be used again.'],
        action: () => request('/_resolver/revoke', 'POST', { ref, expectedRevision: revision }),
      });
      if (done) {
        result.ok('Revoked ', code(ref), true);
        table.refresh();
      }
    }

    table.refresh();
    return [
      S.dom.PageHeader({ title: 'Secrets', description: 'API keys and credentials. Values go into the vault and never come back to this page.', actions: button('New secret', create, 'primary') }),
      result.node,
      table.node,
    ];
  };

  PAGES.access = function () {
    const result = outcome();
    let keyNames = new Map();
    let me;
    const keys = list({
      label: 'API keys',
      empty: 'No API keys',
      columns: [
        { id: 'name', header: 'Name' },
        { id: 'principal', header: 'Principal' },
        { id: 'prefix', header: 'Prefix' },
        { id: 'status', header: 'Status' },
        { id: 'act', header: 'Actions' },
      ],
      read: async () => {
        me = (await readSession().catch(() => ({}))).principal;
        const data = await request('/_resolver/keys');
        keyNames = new Map(data.keys.map((k) => [k.id, k.name]));
        return data.keys;
      },
      row: (k) => ({
        key: k.id,
        cells: {
          name: k.id === me ? k.name + ' (you)' : k.name,
          principal: code(k.id),
          prefix: code(k.prefix),
          status: S.dom.StatusIndicator({ tone: k.status === 'active' ? 'positive' : 'critical', label: k.status === 'active' ? 'Active' : 'Revoked' }),
          act: k.status === 'active' ? button('Revoke', () => revokeKey(k), 'danger') : undefined,
        },
      }),
    });
    const grants = list({
      label: 'Grants',
      empty: 'No grants',
      emptyBody: 'A key can do nothing until it is granted read, reveal, write or admin on some references.',
      columns: [
        { id: 'subject', header: 'Principal' },
        { id: 'actions', header: 'May' },
        { id: 'pattern', header: 'On' },
        { id: 'created', header: 'Granted' },
        { id: 'act', header: 'Actions' },
      ],
      read: async () => (await request('/_resolver/grants')).grants,
      row: (g) => ({
        key: g.id,
        cells: {
          subject: keyNames.get(g.subject) ? el('span', {}, [keyNames.get(g.subject) + ' ', code(g.subject)]) : code(g.subject),
          actions: g.actions.join(', '),
          pattern: code(g.pattern),
          created: when(g.createdAt),
          act: button('Remove', () => removeGrant(g), 'danger'),
        },
      }),
    });
    const refresh = async () => {
      await keys.refresh();
      await grants.refresh();
    };

    const grantHint = 'read: resolve and watch. reveal: read secret values. write: change, roll back, revoke. admin: keys and grants (on * only).';

    async function createKey() {
      let created = null;
      const values = await S.formDialog({
        id: 'new-key',
        title: 'New API key',
        description: 'For an application or a teammate. The key is shown once.',
        submitLabel: 'Create key',
        fields: [
          { name: 'name', label: 'Name', required: true, hint: 'e.g. checkout-service' },
          { name: 'actions', label: 'May (comma-separated)', value: 'read', hint: grantHint },
          { name: 'pattern', label: 'On references', value: 'ref://prod/*', hint: '*, an exact ref://, or a prefix ending in /*', spellcheck: 'false' },
        ],
        action: async (v) => {
          const actions = v.actions.split(',').map((a) => a.trim()).filter(Boolean);
          created = await request('/_resolver/keys', 'POST', { name: v.name.trim(), grants: actions.length ? [{ actions, pattern: v.pattern.trim() }] : [] });
        },
      });
      if (values && created) {
        result.ok('Created ' + created.name + '. Copy this key now; it is not shown again:', el('span', { class: 'resolver-secret' }, created.secret), true);
        refresh();
      }
    }

    async function revokeKey(k) {
      const done = await S.confirmAction({
        id: 'confirm-revoke-key',
        title: 'Revoke the API key ' + k.name + '?',
        confirmLabel: 'Revoke key',
        requireText: k.name,
        consequences: [
          'Every application using this key is refused on its next request, including open connections.',
          'Its grants stop applying.',
          k.id === me ? 'This is the key you are signed in with: you will be signed out.' : null,
        ],
        action: () => request('/_resolver/keys/revoke', 'POST', { id: k.id }),
      });
      if (done) {
        result.ok('Revoked ' + k.name + '.', undefined, true);
        refresh();
      }
    }

    async function addGrant() {
      const options = Array.from(keyNames.entries()).map(([id, name]) => ({ value: id, label: name + ' (' + id.slice(0, 8) + '…)' }));
      const values = await S.formDialog({
        id: 'new-grant',
        title: 'Grant access',
        submitLabel: 'Grant',
        fields: [
          options.length ? { name: 'subject', label: 'Principal', options } : { name: 'subject', label: 'Principal id', required: true },
          { name: 'actions', label: 'May (comma-separated)', required: true, value: 'read', hint: grantHint },
          { name: 'pattern', label: 'On references', required: true, value: 'ref://prod/*', spellcheck: 'false' },
        ],
        action: (v) => request('/_resolver/grants', 'POST', { subject: v.subject, actions: v.actions.split(',').map((a) => a.trim()).filter(Boolean), pattern: v.pattern.trim() }),
      });
      if (values) {
        result.ok('Granted.', undefined, true);
        grants.refresh();
      }
    }

    async function removeGrant(g) {
      const done = await S.confirmAction({
        id: 'confirm-remove-grant',
        title: 'Remove this grant?',
        confirmLabel: 'Remove grant',
        consequences: [(keyNames.get(g.subject) || g.subject) + ' may no longer ' + g.actions.join(', ') + ' ' + g.pattern + ', from its next request.'],
        action: () => request('/_resolver/grants/remove', 'POST', { id: g.id }),
      });
      if (done) {
        result.ok('Grant removed.', undefined, true);
        grants.refresh();
      }
    }

    refresh();
    return [
      S.dom.PageHeader({ title: 'Access', description: 'Who may resolve, reveal or change which references. Deny by default.' }),
      result.node,
      section('API keys', [el('div', { class: 'resolver-actions' }, button('New API key', createKey, 'primary')), keys.node]),
      section('Grants', [el('div', { class: 'resolver-actions' }, button('Grant access', addGrant)), grants.node]),
    ];
  };

  PAGES['sign-in'] = function () {
    const result = outcome();
    const raw = new URLSearchParams(location.search).get('next') || '';
    // Only a path on this origin: never an open redirect.
    const next = raw.startsWith('/') && !raw.startsWith('//') && !raw.startsWith('/\\') ? raw : routeOf('overview');
    const form = S.dom.Form({
      label: 'Sign in',
      submitLabel: 'Sign in',
      children: S.dom.TextField({ id: 'api-key', name: 'apiKey', label: 'API key', type: 'password', required: true, autocomplete: 'off', hint: 'An API key with a grant on this resolver (`resolver init` prints the first one).' }),
      onSubmit: async (event) => {
        const apiKey = new FormData(event.target).get('apiKey');
        try {
          await request('/_resolver/session', 'POST', { apiKey });
          location.assign(next);
        } catch (error) {
          result.fail(error, 'Not signed in');
        }
      },
    });
    return [
      S.dom.PageHeader({ title: 'Sign in', description: 'The key is exchanged for a session cookie this page cannot read. Nothing is stored in the browser.' }),
      result.node,
      el('div', { class: 'resolver-signin' }, form),
    ];
  };

  // ---- Frame -------------------------------------------------------------------

  const account = el('div', { class: 'resolver-account' });
  async function showAccount() {
    if (config.page === 'sign-in') return;
    try {
      const session = await readSession();
      account.replaceChildren(
        el('span', {}, ['Signed in as ', session.name || (session.operator ? 'the operator' : code(session.principal.slice(0, 8) + '…')), ' · tenant ', code(session.tenant)]),
        session.canSignOut ? button('Sign out', async () => {
          await request('/_resolver/session', 'DELETE').catch(() => undefined);
          location.assign(config.signIn);
        }) : null,
      );
    } catch {
      // request() already sent an unauthenticated caller to sign in.
    }
  }

  const page = (PAGES[config.page] || PAGES.overview)();
  document.body.prepend(S.dom.Shell({
    product: { name: 'Resolver', homeHref: routeOf('overview'), mark: 'R' },
    mainId: 'resolver-main',
    account,
    navigation: config.navigation.map((item) => ({
      id: item.id,
      label: item.id === 'overview' ? 'Overview' : item.label,
      href: item.route,
      order: item.order,
      current: item.id === config.page,
      attrs: { 'data-surface': item.id },
    })),
    children: page,
  }));
  showAccount();
})();
