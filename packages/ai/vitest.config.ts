import { defineConfig } from 'vitest/config';

// (C6) 30s was a global default sized for live-API tests, but ~90% of this
// suite is pure unit tests that never make a network call — a hung unit test
// used to cost 30s before failing. Live tests (test/*.live.test.ts) set their
// own longer timeout explicitly below; everything else gets a fast default.
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 10000,
  }
});