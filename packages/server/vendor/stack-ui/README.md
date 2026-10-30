# Vendored @stack-ui static build

The shared Stack design system (`rkendel1/stack-ui`), vendored because the
management pages are server-delivered HTML with no client build step. The same
release AppPort Services vendors (`rkendel1/appport-services/vendor/stack-ui`).

- Every file comes unmodified from `release/stack-ui-static-<VERSION>/` of
  `rkendel1/stack-ui` (`node scripts/package-static.mjs`).
- `src/ui/pages.ts` inlines `tokens.css`, `core.css` and
  `stack-ui-core-stateless.js` into every management page, with
  `ui/management.css` and `ui/management.js`. No extra routes are served.
- The stateless build has no theme preference, so the pages keep nothing in
  browser storage and follow the operating system's colour scheme.
  `stack-ui-core.js` is the full build, kept so this directory stays identical
  to the release.
- `test/ui.test.ts` checks every file against `SHA256SUMS`.

To upgrade: copy the new release directory over this one (keep this README)
and run `npm test`.
