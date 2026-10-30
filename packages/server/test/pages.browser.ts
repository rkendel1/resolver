/// <reference lib="dom" />
// The management pages in a real browser, against a real resolver: sign-in, the Stack shell with every
// page, labelled dialogs instead of prompt(), ConfirmAction with typed confirmation for destructive
// actions, a failed read shown as an error, secrets never reaching the page, nothing in browser storage,
// and axe (serious and critical) in light and dark at 1280 and 640 pixels.
//
// Needs Chromium: CHROMIUM_PATH, or the browser playwright-core installs. Run: npm run test:browser.
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chromium, type Browser, type Page } from 'playwright-core';
import { startResolver, type Harness } from './harness.js';

const executablePath = process.env.CHROMIUM_PATH ?? [chromium.executablePath(), '/opt/pw-browsers/chromium-1243/chrome-linux/chrome'].find((p) => p && existsSync(p));
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const SECRET = 'sk-browser-MUST-NOT-REACH-THE-PAGE';

let h: Harness;
let browser: Browser;

beforeAll(async () => {
  if (!executablePath) throw new Error('Chromium is required: set CHROMIUM_PATH');
  browser = await chromium.launch({ executablePath });
  h = await startResolver();
  await h.admin.put({ ref: 'ref://prod/llm/openai-key', kind: 'secret', secret: SECRET, expectedRevision: 0 });
  await h.admin.put({ ref: 'ref://prod/llm/anthropic-key', kind: 'secret', secret: 'sk-ant', expectedRevision: 0 });
  await h.admin.put({ ref: 'ref://prod/chat/model', kind: 'model', binding: { value: { provider: 'openai', model: 'gpt-4o', credential: 'ref://prod/llm/openai-key' } }, expectedRevision: 0, reason: 'launch' });
  await h.admin.put({ ref: 'ref://prod/flags/checkout', kind: 'value', binding: { value: { newFlow: false } }, expectedRevision: 0 });
});
afterAll(async () => {
  await browser?.close();
  await h?.close();
});

// One sign-in per key: the form is exercised once and its session reused, which keeps the suite under
// the sign-in rate limit.
const sessions = new Map<string, Awaited<ReturnType<import('playwright-core').BrowserContext['storageState']>>>();

async function open(path: string, options: { width?: number; colorScheme?: 'light' | 'dark'; key?: string } = {}) {
  const key = options.key ?? h.adminKey;
  const storageState = sessions.get(key);
  const context = await browser.newContext({ viewport: { width: options.width ?? 1280, height: 900 }, colorScheme: options.colorScheme ?? 'light', ...(storageState ? { storageState } : {}) });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of 401/.test(m.text())) errors.push(m.text());
  });
  if (storageState) {
    await page.goto(`${h.url}${path}`);
  } else {
    await page.goto(`${h.url}/resolver/sign-in?next=${encodeURIComponent(path)}`);
    await page.getByLabel('API key').fill(key);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL((url) => url.pathname + url.search === path);
    sessions.set(key, await context.storageState());
  }
  await settled(page);
  return { page, errors, close: () => context.close() };
}

async function settled(page: Page) {
  await page.waitForSelector('.stack-shell__main');
  await page.waitForFunction(() => !document.querySelector('.stack-shell__main .stack-loading') && !document.querySelector('.stack-shell__main [aria-busy="true"]'));
}

async function axe(page: Page): Promise<string[]> {
  // The page's CSP admits only its own scripts, so axe is evaluated through the driver, not a script tag.
  await page.evaluate(axeSource);
  const result = await page.evaluate(async () => (window as unknown as { axe: { run(d: Document, o: object): Promise<{ violations: Array<{ id: string; impact: string; nodes: Array<{ target: string[] }> }> }> } }).axe.run(document, { resultTypes: ['violations'] }));
  return result.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
}

const PAGES = ['/resolver', '/references', '/models', '/secrets', '/access', '/references?ref=ref%3A%2F%2Fprod%2Fchat%2Fmodel'];

describe('management pages in a browser', () => {
  it('sends an anonymous visitor to sign in and back, and never redirects off the origin', async () => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(`${h.url}/models`);
    await page.waitForURL(/\/resolver\/sign-in\?next=%2Fmodels/);
    await page.goto(`${h.url}/resolver/sign-in?next=${encodeURIComponent('//evil.example/x')}`);
    await page.getByLabel('API key').fill(h.adminKey);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL(`${h.url}/resolver`);
    expect(await page.evaluate(() => ({ cookie: document.cookie, local: localStorage.length, session: sessionStorage.length }))).toEqual({ cookie: '', local: 0, session: 0 });
    await context.close();
  });

  for (const colorScheme of ['light', 'dark'] as const) {
    for (const width of [1280, 640]) {
      it(`renders every page in the Stack shell with no serious accessibility violations (${colorScheme}, ${width}px)`, async () => {
        for (const path of PAGES) {
          const { page, errors, close } = await open(path, { colorScheme, width });
          expect(await page.locator('.stack-shell__nav a[aria-current="page"]').count(), path).toBe(1);
          expect((await axe(page)).join('\n'), `${path} ${colorScheme} ${width}`).toBe('');
          expect(await page.content()).not.toContain(SECRET);
          expect(errors, path).toEqual([]);
          await close();
        }
      });
    }
  }

  it('creates a secret in a labelled dialog; the value never reaches the page', async () => {
    const { page, errors, close } = await open('/secrets');
    await page.getByRole('button', { name: 'New secret' }).click();
    const dialog = page.getByRole('dialog', { name: 'New secret' });
    await dialog.getByLabel('Reference').fill('ref://prod/llm/new-key');
    await dialog.getByLabel('Value').fill('sk-typed-in-the-browser');
    await dialog.getByRole('button', { name: 'Store secret' }).click();
    await page.getByRole('status').filter({ hasText: 'Stored' }).waitFor();
    await settled(page);
    await page.getByRole('link', { name: 'ref://prod/llm/new-key' }).waitFor();
    expect(await page.content()).not.toContain('sk-typed-in-the-browser');
    expect(await h.admin.secret('ref://prod/llm/new-key')).toBe('sk-typed-in-the-browser');
    expect(errors).toEqual([]);
    await close();
  });

  it('starts and promotes a model canary; running clients follow', async () => {
    const { page, close } = await open('/models');
    await page.getByRole('button', { name: 'Start canary' }).click();
    const dialog = page.getByRole('dialog', { name: /Start a canary/ });
    await dialog.getByLabel('Provider').selectOption('anthropic');
    await dialog.getByLabel('Model').fill('claude-sonnet-5-5');
    await dialog.getByLabel('Credential reference').fill('ref://prod/llm/anthropic-key');
    await dialog.getByLabel('Canary share (%)').fill('25');
    await dialog.getByRole('button', { name: 'Start canary' }).click();
    await page.getByText(/75% openai · gpt-4o \(stable\) · 25% anthropic · claude-sonnet-5-5 \(canary\)/).waitFor();

    await page.getByRole('button', { name: 'Promote canary' }).click();
    const confirm = page.getByRole('alertdialog');
    await confirm.getByRole('button', { name: 'Promote' }).click();
    await page.getByRole('status').filter({ hasText: 'Promoted' }).waitFor();
    expect(await h.admin.get('ref://prod/chat/model')).toMatchObject({ provider: 'anthropic', model: 'claude-sonnet-5-5' });
    await close();
  });

  it('shows the resolver\'s validation error inside the dialog and keeps it open', async () => {
    const { page, close } = await open('/models');
    await page.getByRole('button', { name: 'New model alias' }).click();
    const dialog = page.getByRole('dialog', { name: 'New model alias' });
    await dialog.getByLabel('Alias').fill('ref://prod/chat/other');
    await dialog.getByLabel('Provider').selectOption('anthropic');
    await dialog.getByLabel('Model').fill('not-a-real-model');
    await dialog.getByRole('button', { name: 'Create alias' }).click();
    await dialog.getByRole('alert').filter({ hasText: /not in the anthropic catalog/ }).waitFor();
    expect(await dialog.isVisible()).toBe(true);
    await close();
  });

  it('requires the reference name to be typed before revoking, and rolls back from history', async () => {
    const { page, close } = await open('/references?ref=ref%3A%2F%2Fprod%2Fflags%2Fcheckout');
    await page.getByRole('button', { name: 'Change binding' }).click();
    const edit = page.getByRole('dialog', { name: /Change ref:\/\/prod\/flags\/checkout/ });
    await edit.getByLabel('Binding (JSON)').fill('{"value":{"newFlow":true}}');
    await edit.getByLabel('Reason').fill('launch the new flow');
    await edit.getByRole('button', { name: /Save revision 2/ }).click();
    await page.getByRole('status').filter({ hasText: 'Saved revision 2' }).waitFor();
    await settled(page);

    await page.getByRole('button', { name: 'Roll back to 1' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Roll back' }).click();
    await page.getByRole('status').filter({ hasText: 'Rolled back to revision 1' }).waitFor();
    expect(await h.admin.get('ref://prod/flags/checkout')).toEqual({ newFlow: false });

    await page.getByRole('button', { name: 'Revoke' }).click();
    const confirm = page.getByRole('alertdialog');
    const revoke = confirm.getByRole('button', { name: 'Revoke' });
    expect(await revoke.isDisabled()).toBe(true);
    await confirm.getByLabel(/Type ref:\/\/prod\/flags\/checkout to confirm/).fill('ref://prod/flags/checkout');
    expect(await revoke.isDisabled()).toBe(false);
    await revoke.click();
    await page.getByText('Revoked: every resolution of this name fails.').waitFor();
    await close();
  });

  it('shows a failed read as an error with Retry, not an empty list', async () => {
    const { key } = await h.clientWith([[['read'], 'ref://prod/*']]);
    const { page, close } = await open('/access', { key });
    await page.getByRole('alert').filter({ hasText: 'API keys could not be read' }).waitFor();
    expect(await page.getByRole('button', { name: 'Retry' }).count()).toBeGreaterThan(0);
    await close();
  });

  it('creates an API key with a grant and shows the key once', async () => {
    const { page, close } = await open('/access');
    await page.getByRole('button', { name: 'New API key' }).click();
    const dialog = page.getByRole('dialog', { name: 'New API key' });
    await dialog.getByLabel('Name').fill('billing-batch');
    await dialog.getByLabel('May (comma-separated)').fill('read');
    await dialog.getByLabel('On references').fill('ref://prod/flags/*');
    await dialog.getByRole('button', { name: 'Create key' }).click();
    const shown = page.locator('.resolver-secret');
    await shown.waitFor();
    expect(await shown.textContent()).toMatch(/^app_live_/);
    await page.reload();
    await settled(page);
    expect(await page.locator('.resolver-secret').count()).toBe(0);
    expect(await page.getByRole('region', { name: 'API keys' }).getByRole('cell', { name: 'billing-batch', exact: true }).count()).toBe(1);
    await close();
  });
});
