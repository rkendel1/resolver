/**
 * The packaged management pages, on the shared Stack design system, built the way AppPort Services builds
 * its own: every page is one HTML document holding the vendored design-system styles and stateless classic
 * script (`vendor/stack-ui`, checked against its SHA256SUMS), this package's page styles and script (`ui/`),
 * and a JSON description of the page and its navigation. The browser renders the page with the design
 * system's DOM helpers; nothing is parsed as markup, and nothing is kept in browser storage.
 *
 * Each page carries a Content-Security-Policy that admits exactly its own inline script and style (by hash),
 * requests to its own origin only, and no framing.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { PAGES, type UiPage } from './contribution.js';

interface Assets {
  style: string;
  designSystem: string;
  page: string;
  csp: string;
}

let assets: Assets | undefined;

const hash = (text: string) => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

/** Paths are relative to `src/ui/` and `dist/ui/`, both two levels below the package root. */
function loadAssets(): Assets {
  if (assets) return assets;
  const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
  const style = [read('vendor/stack-ui/tokens.css'), read('vendor/stack-ui/core.css'), read('ui/management.css')].join('\n');
  const designSystem = read('vendor/stack-ui/stack-ui-core-stateless.js');
  const page = read('ui/management.js');
  const csp = [
    "default-src 'none'",
    `script-src ${hash(designSystem)} ${hash(page)}`,
    `style-src ${hash(style)}`,
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
  assets = { style, designSystem, page, csp };
  return assets;
}

/** JSON that is safe inside a <script> element: no `<`, and no line separators. */
function scriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

const escapeText = (value: string) => value.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

export const SIGN_IN: UiPage = { id: 'sign-in', title: 'Sign in', route: '/resolver/sign-in', order: 100, description: '', capabilities: [] };

/** One management page and the headers it must be served with. */
export function renderPage(page: UiPage, options: { session?: { principal: string; tenant: string; signOut: boolean } } = {}): { html: string; headers: Record<string, string> } {
  const { style, designSystem, page: pageScript, csp } = loadAssets();
  const title = page.id === 'overview' ? 'Resolver' : `Resolver · ${page.title}`;
  const description = {
    page: page.id,
    navigation: PAGES.map(({ id, title: label, route, order }) => ({ id, label, route, order })),
    descriptions: Object.fromEntries(PAGES.map((p) => [p.id, p.description])),
    signIn: SIGN_IN.route,
    ...(options.session ? { session: options.session } : {}),
  };
  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    `<title>${escapeText(title)}</title><style>${style}</style></head><body>` +
    `<noscript><p class="resolver-noscript">The ${escapeText(page.title)} page needs JavaScript.</p></noscript>` +
    `<script type="application/json" id="resolver-page">${scriptJson(description)}</script>` +
    `<script>${designSystem}</script><script>${pageScript}</script>` +
    '</body></html>';
  return {
    html,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': csp,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  };
}
