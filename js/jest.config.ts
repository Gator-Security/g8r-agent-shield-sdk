import type { Config } from 'jest';

const config: Config = {
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

export default config;
