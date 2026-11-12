import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const src = (pkg: string) => fileURLToPath(new URL(`./packages/${pkg}/src/index.ts`, import.meta.url));

export default defineConfig({
  resolve: {
    // Exact matches, so a subpath (`@appport/resolver-client/authorization`) is not taken for the package root.
    alias: [
      { find: /^@appport\/resolver-core$/, replacement: src('core') },
      { find: /^@appport\/resolver-client\/authorization$/, replacement: fileURLToPath(new URL('./packages/client/src/authorization.ts', import.meta.url)) },
      { find: /^@appport\/resolver-client$/, replacement: src('client') },
      { find: /^@appport\/resolver$/, replacement: src('server') },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    testTimeout: 20000,
    hookTimeout: 30000,
  },
});
