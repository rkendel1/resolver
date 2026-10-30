import { defineConfig } from 'vitest/config';
import base from './vitest.config.js';

// The browser suite only: mergeConfig would append to the base `include` and run the unit tests too.
export default defineConfig({
  resolve: base.resolve,
  test: { include: ['packages/*/test/**/*.browser.ts'], testTimeout: 120000, hookTimeout: 60000, fileParallelism: false },
});
