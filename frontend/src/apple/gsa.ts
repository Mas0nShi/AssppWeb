import { apiGet } from '../api/client';
import { extractAndMergeCookies } from './cookies';
import { userAgent } from './config';
import {
  createSrpProof,
  decryptSpd,
  equalBytes,
  srpPublicKey,
} from './gsaCrypto';
import { buildPlist, parsePlistLoose } from './plist';
import i18n from '../i18n';
import type { AppleRequestOptions, AppleResponse } from './request';
import type { Account, Cookie } from '../types';

const gsaHost = 'gsa.apple.com';
const gsaPath = '/grandslam/GsService2';
const gsaUserAgent = 'Xcode';
const storeAuthPath = '/WebObjects/MZFinance.woa/wa/authenticate';
const transientStatuses = new Set([0, 429, 500, 502, 503, 504]);

interface AnisetteHeaders {
  'X-Apple-I-Client-Time': string;
  'X-Apple-I-MD': string;
  'X-Apple-I-MD-LU': string;
  'X-Apple-I-MD-M': string;
  'X-Apple-I-MD-RINFO': string;
  'X-Apple-I-SRL-NO': string;
  'X-Apple-I-TimeZone': string;
  'X-Apple-Locale': string;
  'X-MMe-Client-Info': string;
  'X-Mme-Device-Id': string;
}

interface GsaStatus {
  ec?: number | string;
  em?: string;
  au?: string;
}

interface GsaResponse {
  Status?: GsaStatus;
  B?: Uint8Array;
  M2?: Uint8Array;
  c?: Uint8Array | string;
  i?: number | string;
  s?: Uint8Array;
  sp?: string;
  spd?: Uint8Array;
  [key: string]: unknown;
}

interface GsaSession {
  spd: Record<string, any>;
  status: GsaStatus;
}

export type AppleTransport = (
  options: AppleRequestOptions,
) => Promise<AppleResponse>;

export interface GsaDependencies {
  request?: AppleTransport;
  anisette?: () => Promise<AnisetteHeaders>;
  randomBytes?: (length: number) => Uint8Array;
}

export class GsaProtocolError extends Error {
  constructor(
    message: string,
    public readonly code?: number,
  ) {
    super(message);
    this.name = 'GsaProtocolError';
  }
}

export class GsaVerificationRequiredError extends Error {
  constructor() {
    super(i18n.t('errors.auth.requiresVerification'));
    this.name = 'GsaVerificationRequiredError';
  }
}

function statusCode(status?: GsaStatus): number | undefined {
  if (status?.ec === undefined || status.ec === null) return undefined;
  const code = Number(status.ec);
  return Number.isFinite(code) ? code : undefined;
}

function statusError(status: GsaStatus | undefined, fallback: string): Error {
  const message = status?.em || fallback;
  return new GsaProtocolError(message, statusCode(status));
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function requireBytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error(`Apple GSA response is missing ${name}`);
}

function cpdFromAnisette(ani: AnisetteHeaders): Record<string, unknown> {
  return {
    'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
    'X-Apple-I-MD': ani['X-Apple-I-MD'],
    'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
    'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
    'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
    'X-Apple-I-SRL-NO': ani['X-Apple-I-SRL-NO'],
    'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
    'X-Apple-Locale': ani['X-Apple-Locale'],
    'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
    bootstrap: true,
    icscrec: true,
    loc: 'en_US',
    pbe: false,
    prkgen: true,
    svct: 'iCloud',
  };
}

async function fetchAnisette(): Promise<AnisetteHeaders> {
  const response = await apiGet<Partial<AnisetteHeaders>>('/api/anisette');
  const required: (keyof AnisetteHeaders)[] = [
    'X-Apple-I-Client-Time',
    'X-Apple-I-MD',
    'X-Apple-I-MD-LU',
    'X-Apple-I-MD-M',
    'X-Apple-I-MD-RINFO',
    'X-Apple-I-TimeZone',
    'X-MMe-Client-Info',
    'X-Mme-Device-Id',
  ];
  for (const name of required) {
    if (!response[name]) {
      throw new Error(`Anisette response is missing ${name}`);
    }
  }
  return {
    ...response,
    'X-Apple-I-SRL-NO': response['X-Apple-I-SRL-NO'] || '0',
    'X-Apple-Locale': response['X-Apple-Locale'] || 'en_US',
  } as AnisetteHeaders;
}

async function gsaPost(
  payload: Record<string, unknown>,
  ani: AnisetteHeaders,
  request: AppleTransport,
): Promise<GsaResponse> {
  let lastStatus = 0;
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await request({
      method: 'POST',
      host: gsaHost,
      path: gsaPath,
      headers: {
        Accept: '*/*',
        'Content-Type': 'text/x-xml-plist',
        'User-Agent': gsaUserAgent,
        'X-MMe-Client-Info': ani['X-MMe-Client-Info'],
      },
      body: buildPlist(payload),
    });
    lastStatus = response.status;
    if (response.status === 200) {
      if (!response.body.trim()) {
        throw new GsaProtocolError(
          i18n.t('errors.auth.emptyBody', { status: response.status }),
        );
      }
      const parsed = parsePlistLoose(response.body) as Record<string, unknown>;
      return (parsed.Response || parsed) as GsaResponse;
    }
    if (!transientStatuses.has(response.status)) break;
  }
  throw new GsaProtocolError(`Apple GSA returned HTTP ${lastStatus}`);
}

async function srpLogin(
  email: string,
  password: string,
  ani: AnisetteHeaders,
  request: AppleTransport,
  makeRandomBytes: (length: number) => Uint8Array,
): Promise<GsaSession> {
  const privateKey = makeRandomBytes(32);
  const clientPublicKey = srpPublicKey(privateKey);
  const cpd = cpdFromAnisette(ani);

  const initial = await gsaPost(
    {
      Header: { Version: '1.0.1' },
      Request: {
        A2k: clientPublicKey,
        cpd,
        o: 'init',
        ps: ['s2k', 's2k_fo'],
        u: email,
      },
    },
    ani,
    request,
  );
  if (statusCode(initial.Status) !== 0) {
    throw statusError(initial.Status, 'Apple GSA initialization failed');
  }

  const proof = await createSrpProof(email, password, privateKey, {
    salt: requireBytes(initial.s, 'salt'),
    serverPublicKey: requireBytes(initial.B, 'server public key'),
    iterations: Number(initial.i),
    protocol: initial.sp || 's2k',
  });
  const complete = await gsaPost(
    {
      Header: { Version: '1.0.1' },
      Request: {
        M1: proof.clientProof,
        c: initial.c,
        cpd,
        o: 'complete',
        u: email,
      },
    },
    ani,
    request,
  );
  if (statusCode(complete.Status) !== 0) {
    throw statusError(complete.Status, 'Apple GSA authentication failed');
  }

  const serverProof = requireBytes(complete.M2, 'server proof');
  if (!equalBytes(serverProof, proof.expectedServerProof)) {
    throw new Error('Apple GSA server proof did not match');
  }
  const encryptedSpd = requireBytes(complete.spd, 'encrypted session data');
  const spdXml = await decryptSpd(proof.sessionKey, encryptedSpd);
  const spd = parsePlistLoose(spdXml) as Record<string, any>;
  return { spd, status: complete.Status || {} };
}

function identityToken(adsid: string, gsToken: string): string {
  const bytes = new TextEncoder().encode(`${adsid}:${gsToken}`);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function twoFactorHeaders(
  ani: AnisetteHeaders,
  adsid: string,
  gsToken: string,
): Record<string, string> {
  return {
    Accept: 'text/x-xml-plist',
    'Accept-Language': 'en-us',
    'Content-Type': 'text/x-xml-plist',
    Loc: ani['X-Apple-Locale'],
    'User-Agent': gsaUserAgent,
    'X-Apple-App-Info': 'com.apple.gs.xcode.auth',
    'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
    'X-Apple-I-MD': ani['X-Apple-I-MD'],
    'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
    'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
    'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
    'X-Apple-I-SRL-NO': ani['X-Apple-I-SRL-NO'],
    'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
    'X-Apple-Locale': ani['X-Apple-Locale'],
    'X-Apple-Identity-Token': identityToken(adsid, gsToken),
    'X-MMe-Client-Info': ani['X-MMe-Client-Info'],
    'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
    'X-Xcode-Version': '11.2 (11B41)',
  };
}

async function sendTwoFactorPush(
  ani: AnisetteHeaders,
  adsid: string,
  gsToken: string,
  request: AppleTransport,
): Promise<void> {
  try {
    await request({
      method: 'GET',
      host: gsaHost,
      path: '/auth/verify/trusteddevice',
      headers: twoFactorHeaders(ani, adsid, gsToken),
    });
  } catch {
    // The account can still display a code even when the push endpoint fails.
  }
}

async function validateTwoFactor(
  ani: AnisetteHeaders,
  adsid: string,
  gsToken: string,
  code: string,
  request: AppleTransport,
): Promise<void> {
  const response = await request({
    method: 'GET',
    host: gsaHost,
    path: `${gsaPath}/validate`,
    headers: {
      ...twoFactorHeaders(ani, adsid, gsToken),
      'security-code': code,
    },
  });
  if (response.status !== 200 || !response.body.trim()) {
    throw new GsaProtocolError(
      `Apple two-factor verification returned HTTP ${response.status}`,
    );
  }
  const parsed = parsePlistLoose(response.body) as Record<string, any>;
  const status = (parsed.Status || parsed.Response?.Status || parsed) as GsaStatus;
  if (statusCode(status) !== 0) {
    throw statusError(status, 'The verification code was rejected');
  }
}

function sessionIdentity(session: GsaSession): {
  adsid: string;
  gsToken: string;
} {
  const adsid = String(session.spd.adsid || '');
  const gsToken = String(
    session.spd.GsIdmsToken || session.spd.GsIdToken || '',
  );
  if (!adsid || !gsToken) {
    throw new Error('Apple GSA session is missing identity tokens');
  }
  return { adsid, gsToken };
}

function isTwoFactorRequired(status: GsaStatus): boolean {
  return (
    status.au === 'trustedDeviceSecondaryAuth' ||
    status.au === 'secondaryAuth'
  );
}

function podFromLocation(location: string): string | undefined {
  const url = new URL(location);
  return (
    url.searchParams.get('Pod') ||
    url.hostname.match(/^p(\d+)-buy\.itunes\.apple\.com$/)?.[1] ||
    undefined
  );
}

async function storeAuthenticate(
  email: string,
  pet: string,
  ani: AnisetteHeaders,
  adsid: string,
  gsToken: string,
  deviceId: string,
  existingCookies: Cookie[] | undefined,
  request: AppleTransport,
): Promise<{
  parsed: Record<string, any>;
  cookies: Cookie[];
  pod?: string;
  storeFront: string;
}> {
  const body = buildPlist({
    appleId: email,
    attempt: '1',
    createSession: 'true',
    guid: deviceId,
    password: pet,
    rmp: '0',
    why: 'signIn',
  });
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-apple-plist',
    'User-Agent': userAgent,
    'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
    'X-Apple-I-MD': ani['X-Apple-I-MD'],
    'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
    'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
    'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
    'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
    'X-Apple-Identity-Token': identityToken(adsid, gsToken),
    'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
  };

  let host = 'buy.itunes.apple.com';
  let path = `${storeAuthPath}?guid=${encodeURIComponent(deviceId)}`;
  let cookies = existingCookies ? [...existingCookies] : [];
  let pod: string | undefined;
  let storeFront = '';

  for (let redirect = 0; redirect <= 4; redirect++) {
    const response = await request({
      method: 'POST',
      host,
      path,
      headers,
      body,
      cookies,
    });
    cookies = extractAndMergeCookies(response.rawHeaders, cookies);
    storeFront =
      response.headers['x-set-apple-store-front'] || storeFront;
    pod = response.headers.pod || pod;

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.location;
      if (!location) {
        throw new Error(i18n.t('errors.auth.redirectLocation'));
      }
      const redirectUrl = new URL(location, `https://${host}${path}`);
      if (
        redirectUrl.hostname !== 'buy.itunes.apple.com' &&
        !/^p\d+-buy\.itunes\.apple\.com$/.test(redirectUrl.hostname)
      ) {
        throw new Error('Apple authentication redirected to an invalid host');
      }
      pod = podFromLocation(redirectUrl.toString()) || pod;
      host = redirectUrl.hostname;
      path = `${redirectUrl.pathname}${redirectUrl.search}`;
      continue;
    }

    if (!response.body.trim()) {
      throw new Error(
        i18n.t('errors.auth.emptyBody', { status: response.status }),
      );
    }
    const parsed = parsePlistLoose(response.body) as Record<string, any>;
    if (!parsed.passwordToken || !parsed.dsPersonId) {
      const message =
        parsed.dialog?.explanation ||
        parsed.customerMessage ||
        i18n.t('errors.auth.missingAccountInfo');
      throw new Error(message);
    }
    return { parsed, cookies, pod, storeFront };
  }

  throw new Error('Apple authentication redirected too many times');
}

export async function authenticateWithGsa(
  email: string,
  password: string,
  code: string | undefined,
  existingCookies: Cookie[] | undefined,
  deviceId: string,
  dependencies: GsaDependencies = {},
): Promise<Account> {
  const request =
    dependencies.request || (await import('./request')).appleRequest;
  const getAnisette = dependencies.anisette || fetchAnisette;
  const makeRandomBytes = dependencies.randomBytes || randomBytes;
  const ani = await getAnisette();

  let session = await srpLogin(
    email,
    password,
    ani,
    request,
    makeRandomBytes,
  );
  let identity = sessionIdentity(session);

  if (isTwoFactorRequired(session.status)) {
    if (!code) {
      await sendTwoFactorPush(ani, identity.adsid, identity.gsToken, request);
      throw new GsaVerificationRequiredError();
    }
    await validateTwoFactor(
      ani,
      identity.adsid,
      identity.gsToken,
      code,
      request,
    );
    session = await srpLogin(
      email,
      password,
      ani,
      request,
      makeRandomBytes,
    );
    if (isTwoFactorRequired(session.status)) {
      throw new Error('Apple two-factor verification did not complete');
    }
    identity = sessionIdentity(session);
  }

  const pet = session.spd.t?.['com.apple.gs.idms.pet']?.token;
  if (!pet) throw new Error('Apple GSA session did not contain a PET');

  const result = await storeAuthenticate(
    email,
    String(pet),
    ani,
    identity.adsid,
    identity.gsToken,
    deviceId,
    existingCookies,
    request,
  );
  const accountInfo = result.parsed.accountInfo || {};
  const address = accountInfo.address || {};

  return {
    email,
    password,
    appleId: String(accountInfo.appleId || email),
    store: result.storeFront.split('-')[0] || '',
    firstName: String(address.firstName || session.spd.fn || ''),
    lastName: String(address.lastName || session.spd.ln || ''),
    passwordToken: String(result.parsed.passwordToken),
    directoryServicesIdentifier: String(result.parsed.dsPersonId),
    cookies: result.cookies,
    deviceIdentifier: deviceId,
    pod: result.pod,
  };
}
