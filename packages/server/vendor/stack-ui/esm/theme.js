// The theme preference (docs/product-shell.md §2): `system`, `light` or `dark`,
// stored per product origin. This is the only state the design system keeps,
// and the only module allowed to touch storage. Every access is wrapped: a
// private window, blocked site data or a throwing accessor leaves the page on
// the system theme, never broken.

export const THEME_STORAGE_KEY = 'stack-ui.theme';
export const THEME_PREFERENCES = Object.freeze(['system', 'light', 'dark']);

const storageOf = (scope) => {
  try {
    return scope && scope.localStorage ? scope.localStorage : null;
  } catch {
    return null;
  }
};

/// The stored preference, or `system` when there is none or it cannot be read.
export function readThemePreference(scope) {
  const storage = storageOf(scope || globalThis);
  if (!storage) return 'system';
  try {
    const value = storage.getItem(THEME_STORAGE_KEY);
    return THEME_PREFERENCES.includes(value) ? value : 'system';
  } catch {
    return 'system';
  }
}

/// Remembers a preference. Returns whether it was stored.
export function storeThemePreference(preference, scope) {
  const storage = storageOf(scope || globalThis);
  if (!storage || !THEME_PREFERENCES.includes(preference)) return false;
  try {
    if (preference === 'system') storage.removeItem(THEME_STORAGE_KEY);
    else storage.setItem(THEME_STORAGE_KEY, preference);
    return true;
  } catch {
    return false;
  }
}

/// Applies a preference to the document: `light` or `dark` set
/// `data-stack-theme`; `system` removes it and follows the operating system.
export function applyThemePreference(preference, root) {
  const element = root || (typeof document !== 'undefined' ? document.documentElement : null);
  if (!element) return;
  if (preference === 'light' || preference === 'dark') element.setAttribute('data-stack-theme', preference);
  else element.removeAttribute('data-stack-theme');
}

/// Reads, applies and returns the stored preference: call once at start-up,
/// before the first render, so the page never flashes the other theme.
export function initThemePreference(scope, root) {
  const preference = readThemePreference(scope);
  applyThemePreference(preference, root);
  return preference;
}

/// Stores and applies a preference chosen in the shell's theme control.
export function setThemePreference(preference, scope, root) {
  const value = THEME_PREFERENCES.includes(preference) ? preference : 'system';
  storeThemePreference(value, scope);
  applyThemePreference(value, root);
  return value;
}

/// The same start-up step as initThemePreference, as script text for the
/// <head> of a page rendered ahead of time (a static or server-rendered
/// site), so the stored theme applies before the first paint. It reads only
/// THEME_STORAGE_KEY, sets only data-stack-theme, and fails closed to the
/// system theme.
export const THEME_INIT_SCRIPT = `(function(){try{var v=window.localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});if(v==="light"||v==="dark")document.documentElement.setAttribute("data-stack-theme",v);}catch(e){}})();`;
