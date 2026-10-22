'use strict';

/** ESLint flat configuration for the Node.js source and test files. */
module.exports = [
  {
    ignores: ['node_modules/**', 'coverage/**']
  },
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: {
        Buffer: 'readonly',
        __dirname: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        process: 'readonly',
        URL: 'readonly'
      }
    },
    rules: {
      'comma-dangle': ['error', 'never'],
      curly: 'error',
      eqeqeq: 'error',
      indent: ['error', 2],
      'no-undef': 'error',
      'no-unused-vars': ['error', { args: 'after-used' }],
      'object-curly-spacing': ['error', 'always'],
      quotes: ['error', 'single', { avoidEscape: true }],
      semi: ['error', 'always']
    }
  }
];
