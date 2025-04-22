import eslint from '@eslint/js'
import noOnlyTests from 'eslint-plugin-no-only-tests'
import prettier from 'eslint-plugin-prettier/recommended'
import tseslint from 'typescript-eslint'

export default [
  {
    ignores: ['**/dist', '**/coverage', '**/typechain-types']
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
  {
    rules: {
      'no-console': ['error', { allow: ['warn', 'error'] }],
      '@typescript-eslint/no-shadow': 'error',
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_'
        }
      ],
      'noOnlyTests/no-only-tests': 'error'
    },
    plugins: {
      noOnlyTests
    }
  },
  {
    files: ['script/**/*.ts'],
    rules: {
      // Allow `console.log` in Hardhat scripts
      'no-console': 'off'
    }
  },
  {
    files: ['test/**/*.spec.ts'],
    rules: {
      // Chai assertions can be unused expressions (for example, `to.be.true`).
      '@typescript-eslint/no-unused-expressions': 'off'
    }
  },
  {
    files: ['./**/*.ts'],
    rules: {
      '@typescript-eslint/no-shadow': 'off'
    }
  },
  { ignores: ['**/node_modules', '**/.data'] }
]
