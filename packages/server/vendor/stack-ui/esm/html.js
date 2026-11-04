// Serializes view trees to HTML text for pages built ahead of time without a
// browser: static company and product websites that must read and navigate
// with JavaScript off (docs/decisions.md D23, revisiting D14). It produces the
// same DOM as dom.js — the browser parity test parses its output and compares
// it with toDom — and it is not part of the classic build.
// Every text node and attribute value is escaped; event handlers are dropped
// (a static page wires behaviour with dom.js or its own script); opaque slot
// content (DOM nodes, React elements) cannot be serialized and throws.

import { COMPONENTS, isTree } from './view.js';

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const TEXT = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };
const ATTR = { ...TEXT, '"': '&quot;' };
const escapeText = (value) => String(value).replace(/[&<>]/g, (c) => TEXT[c]);
const escapeAttr = (value) => String(value).replace(/[&<>"]/g, (c) => ATTR[c]);
const NAME = /^[A-Za-z][A-Za-z0-9_:.-]*$/;

/// HTML text for a view tree, string, number or array of them.
export function toHtml(value) {
  if (value === null || value === undefined || value === false || value === true) return '';
  if (typeof value === 'string' || typeof value === 'number') return escapeText(value);
  if (Array.isArray(value)) return value.map(toHtml).join('');
  if (isTree(value)) {
    if (!NAME.test(value.t)) throw new TypeError(`toHtml: bad tag ${value.t}`);
    let attrs = '';
    for (const [key, attr] of Object.entries(value.a)) {
      if (attr === null || attr === undefined || attr === false) continue;
      if (!NAME.test(key) || /^on/i.test(key)) throw new TypeError(`toHtml: bad attribute ${key}`);
      attrs += attr === true ? ` ${key}` : ` ${key}="${escapeAttr(attr)}"`;
    }
    if (VOID.has(value.t)) return `<${value.t}${attrs}>`;
    // A textarea's text is its value; it is escaped like any other text.
    return `<${value.t}${attrs}>${value.c.map(toHtml).join('')}</${value.t}>`;
  }
  throw new TypeError('toHtml: unsupported child (opaque slot content cannot be serialized)');
}

/// Each component as a function returning HTML text, e.g.
///   html.SiteFooter({ product: { id: 'feltdb' }, year: 2026 })
export const html = Object.freeze(Object.fromEntries(
  Object.entries(COMPONENTS).map(([name, component]) => [name, (props) => toHtml(component(props || {}))]),
));
