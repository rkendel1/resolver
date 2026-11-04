#!/usr/bin/env node
// Boundry design-foundation conformance (docs/release.md "Conformance").
// Run by every Boundry site and product build so a build that drifts from
// the design system fails. Zero dependencies.
//
//   node conformance.mjs --product <id>|--company
//        --html <file|dir>...         built pages to check (dirs are searched for *.html)
//        [--css <file|dir>...]        the product's OWN stylesheets (not the vendored ones)
//        [--require-header-family]    product sites: the header carries "A Boundry product"
//        [--tokens <tokens.css>]      defaults to the vendored copy next to this file
//
// Exit 0 when every check passes; 1 with a list of failures otherwise.

import { readFileSync, readdirSync, statSync, existsSync, realpathSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const args = { html: [], css: [], product: null, company: false, headerFamily: false, tokens: null };
  let list = null;
  for (const arg of argv) {
    if (arg === '--html') list = args.html;
    else if (arg === '--css') list = args.css;
    else if (arg === '--company') { args.company = true; list = null; }
    else if (arg === '--require-header-family') { args.headerFamily = true; list = null; }
    else if (arg === '--product' || arg === '--tokens') list = arg;
    else if (list === '--product') { args.product = arg; list = null; }
    else if (list === '--tokens') { args.tokens = arg; list = null; }
    else if (Array.isArray(list)) list.push(arg);
    else throw new Error(`unexpected argument ${arg}`);
  }
  return args;
}

const files = (paths, extension) => paths.flatMap((path) => {
  if (!existsSync(path)) throw new Error(`not found: ${path}`);
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path).flatMap((name) => (name === 'node_modules' || name === 'vendor' ? [] : files([join(path, name)], extension)))
    .filter((file) => file.endsWith(extension));
});

const firstExisting = (candidates) => candidates.find((path) => existsSync(path)) || null;

/// Checks built pages and product stylesheets; returns a list of failures.
export async function checkConformance(options) {
  const failures = [];
  const fail = (where, what) => failures.push(`${where}: ${what}`);
  // The vendored modules sit beside this file in every distribution:
  // package layout (core/bin → core/src) or static release (root → esm/).
  const modules = firstExisting([join(here, '../src'), join(here, 'esm')]);
  if (!modules) throw new Error('conformance: cannot find the design-foundation modules next to this script');
  const { PORTFOLIO } = await import(pathToFileURL(join(modules, 'brand.js')).href);
  const { THEME_INIT_SCRIPT } = await import(pathToFileURL(join(modules, 'theme.js')).href);
  const tokensPath = options.tokens || firstExisting([join(here, '../../tokens/css/tokens.css'), join(here, 'tokens.css')]);

  if (!options.company && !PORTFOLIO.products.some((p) => p.id === options.product)) {
    fail('arguments', `--product must be a Boundry portfolio id (${PORTFOLIO.products.map((p) => p.id).join(', ')}) or use --company`);
    return failures;
  }
  const pages = files(options.html, '.html');
  if (!pages.length) fail('arguments', 'no built HTML pages found');
  const company = PORTFOLIO.company.href.replace(/\/$/, '');
  const linksCompany = (html) => new RegExp(`href="${company.replace(/\./g, '\\.')}/?"`).test(html);

  for (const page of pages) {
    const html = readFileSync(page, 'utf8');
    const where = page;
    // React escapes nothing in a script's __html, so the shared script text appears verbatim.
    if (!html.includes(THEME_INIT_SCRIPT)) fail(where, 'missing the shared pre-paint theme script (THEME_INIT_SCRIPT)');
    if (!html.includes('data-stack-theme-control')) fail(where, 'missing the shared theme control (ThemeSwitch or Shell theme): sites must offer System, Light and Dark');
    const hasFooter = /class="stack-site-footer[\s"]/.test(html);
    if (!hasFooter) {
      // One cause, one message: without the shared footer the family links below are missing too.
      fail(where, 'missing the shared SiteFooter (the Boundry family footer): render SiteFooter({ product: { id } })');
    } else {
      if (!linksCompany(html)) fail(where, `no link to ${company}`);
      const missing = PORTFOLIO.products.filter((product) => !html.includes(`href="${product.href}"`));
      if (missing.length) fail(where, `the Boundry family footer does not link to ${missing.map((p) => `${p.name} (${p.href})`).join(', ')}: the vendored foundation may be out of date`);
    }
    if (!options.company) {
      if (!new RegExp(`data-stack-product="${options.product}"`).test(html)) fail(where, `the page does not declare data-stack-product="${options.product}"`);
      if (hasFooter && !html.includes('is a <a href="https://boundry.company">Boundry product</a>')) fail(where, 'the footer does not state that the product is a Boundry product (pass product: { id } to SiteFooter)');
      if (options.headerFamily && !/<header[\s\S]*?A Boundry product[\s\S]*?<\/header>/.test(html)) fail(where, 'the header does not carry "A Boundry product"');
    }
  }

  // Product stylesheets may not redefine foundation tokens or restyle shared semantics.
  const canonical = tokensPath ? readFileSync(tokensPath, 'utf8') : null;
  if (!canonical) fail('arguments', 'cannot find the vendored tokens.css (pass --tokens)');
  for (const sheet of files(options.css, '.css')) {
    const css = readFileSync(sheet, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    for (const match of css.matchAll(/(--stack-[a-z0-9-]+)\s*:/g)) {
      fail(sheet, `redefines ${match[1]}: foundation tokens belong to the design system (contract §3.6); use a --<product>-* token`);
    }
    for (const match of css.matchAll(/([^{}]+)\{/g)) {
      const selector = match[1].trim();
      if (/\.stack-(status|verification|freshness|evidence|alert|error|unavailable|button)\b/.test(selector)) {
        fail(sheet, `restyles shared semantics (${selector.slice(0, 80)}): states, evidence and actions look the same in every product`);
      }
    }
  }
  return failures;
}

// Run as a command — directly, or through the package's bin link (node_modules/.bin is a
// symlink, so compare real paths; comparing the link itself would silently skip every check).
const invokedDirectly = (() => {
  try { return Boolean(process.argv[1]) && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (invokedDirectly) {
  try {
    const failures = await checkConformance(parseArgs(process.argv.slice(2)));
    if (failures.length) {
      console.error(`Boundry design-foundation conformance failed (${failures.length}):\n  ${failures.join('\n  ')}`);
      process.exit(1);
    }
    console.log('Boundry design-foundation conformance: passed');
  } catch (error) {
    console.error(`conformance: ${error.message}`);
    process.exit(2);
  }
}
