/**
 * Jest config — plain CommonJS so it parses with no `ts-node` dependency.
 * Test files are still TypeScript; `ts-jest` transpiles them (see `transform`).
 *
 * @type {import('jest').Config}
 */
const config = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: './tsconfig.json' }],
  },
  testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts', '!**/*.d.ts'],
  coverageThreshold: {
    global: {
      statements: 85,
      branches: 75,
      functions: 85,
      lines: 85,
    },
  },
};

module.exports = config;
