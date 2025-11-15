import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom', // Changed from 'node' to support browser APIs
    include: ['tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist', 'src/**/*.test.ts', 'src/**/*.test.tsx', 'src/__tests__/**/*'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.test.ts',
        '**/*.config.ts',
      ],
    },
    testTimeout: 10000, // Increased timeout for Argon2
  },
});
