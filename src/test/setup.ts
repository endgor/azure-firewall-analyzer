import '@testing-library/jest-dom';

// Global test setup for Azure Firewall Analyzer
// This file is imported by Vitest before running tests

// Mock console.warn and console.error during tests to reduce noise
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(() => {
  console.warn = (...args) => {
    // Only show warnings in test output if they're relevant
    if (args[0] && typeof args[0] === 'string') {
      const message = args[0];
      // Allow specific warnings that are relevant to our tests
      if (message.includes('Azure') || message.includes('firewall') || message.includes('rule')) {
        originalConsoleWarn(...args);
      }
    }
  };

  console.error = (...args) => {
    // Only show errors that aren't expected test errors
    if (args[0] && typeof args[0] === 'string') {
      const message = args[0];
      // Allow specific errors that are relevant to our tests
      if (!message.includes('Warning: ReactDOM.render is no longer supported')) {
        originalConsoleError(...args);
      }
    }
  };
});

afterAll(() => {
  console.warn = originalConsoleWarn;
  console.error = originalConsoleError;
});

// Global test utilities and mocks can be added here
export const mockConsole = {
  warn: vi.fn(),
  error: vi.fn(),
  log: vi.fn()
};

// Helper to reset all mocks between tests
export const resetAllMocks = () => {
  vi.clearAllMocks();
  mockConsole.warn.mockClear();
  mockConsole.error.mockClear();
  mockConsole.log.mockClear();
};