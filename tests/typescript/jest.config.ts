import type { Config } from 'jest';

const config: Config = {
  // Use a preset to automatically configure Jest for TypeScript
  preset: 'ts-jest',

  // The test environment that will be used for testing
  testEnvironment: 'node',

  // Directories to scan for test files
  testMatch: ['<rootDir>/test/**/*.test.ts'],

  // The root directory that Jest should scan for tests and modules
  rootDir: '.',

  globalSetup: '<rootDir>/test/jest.global-setup.ts',
};

export default config;
