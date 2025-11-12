import eslint from '@eslint/js';

export default [
  eslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: await import('@typescript-eslint/parser').then(m => m.default),
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        crypto: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off',
    },
  },
  {
    ignores: ['dist', 'node_modules', '**/*.test.ts', 'tests', 'src/components', 'src/core', 'src/data', 'src/domain', 'src/features', 'src/hooks', 'src/presentation', 'src/styles', 'src/test', 'src/types', 'src/assets', 'src/main.tsx', 'src/__tests__'],
  },
];
