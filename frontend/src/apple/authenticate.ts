import {
  authenticateWithGsa,
  GsaVerificationRequiredError,
} from './gsa';
import i18n from '../i18n';
import type { Account, Cookie } from '../types';

export class AuthenticationError extends Error {
  constructor(
    message: string,
    public readonly codeRequired: boolean = false,
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export async function authenticate(
  email: string,
  password: string,
  code?: string,
  existingCookies?: Cookie[],
  deviceId: string = '',
): Promise<Account> {
  try {
    return await authenticateWithGsa(
      email,
      password,
      code,
      existingCookies,
      deviceId,
    );
  } catch (error) {
    if (error instanceof GsaVerificationRequiredError) {
      throw new AuthenticationError(
        i18n.t('errors.auth.requiresVerification'),
        true,
      );
    }
    throw error;
  }
}
