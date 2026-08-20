import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  authenticate,
  AuthenticationError,
} from '../../src/apple/authenticate';
import type { Account } from '../../src/types';

const mocks = vi.hoisted(() => ({
  authenticateWithGsa: vi.fn(),
}));

vi.mock('../../src/apple/gsa', () => {
  class GsaVerificationRequiredError extends Error {}
  return {
    authenticateWithGsa: mocks.authenticateWithGsa,
    GsaVerificationRequiredError,
  };
});
describe('apple/authenticate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the GSA account result', async () => {
    const account = {
      email: 'test@example.com',
      password: 'password',
      appleId: 'test@example.com',
      store: '143441',
      firstName: 'Test',
      lastName: 'User',
      passwordToken: 'token',
      directoryServicesIdentifier: '123',
      cookies: [],
      deviceIdentifier: 'aabbccddeeff',
    } satisfies Account;
    mocks.authenticateWithGsa.mockResolvedValue(account);

    await expect(
      authenticate(
        'test@example.com',
        'password',
        undefined,
        undefined,
        'aabbccddeeff',
      ),
    ).resolves.toBe(account);
  });

  it('maps GSA verification requests to the UI authentication error', async () => {
    const { GsaVerificationRequiredError } = await import(
      '../../src/apple/gsa'
    );
    mocks.authenticateWithGsa.mockRejectedValue(
      new GsaVerificationRequiredError(),
    );

    const promise = authenticate(
      'test@example.com',
      'password',
      undefined,
      undefined,
      'aabbccddeeff',
    );

    await expect(promise).rejects.toBeInstanceOf(AuthenticationError);
    await expect(promise).rejects.toMatchObject({ codeRequired: true });
  });
});
