import { describe, expect, it } from 'vitest';
import {
  authenticateWithGsa,
  GsaProtocolError,
  GsaVerificationRequiredError,
} from '../../src/apple/gsa';
import { buildPlist, parsePlist } from '../../src/apple/plist';
import type { AppleRequestOptions, AppleResponse } from '../../src/apple/request';

function hex(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

function response(
  status: number,
  body: string,
  headers: Record<string, string> = {},
  rawHeaders: [string, string][] = [],
): AppleResponse {
  return {
    status,
    statusText: '',
    headers,
    rawHeaders,
    body,
  };
}

const privateKey = hex(
  '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
);
const salt = new Uint8Array(Array.from({ length: 16 }, (_, i) => i));
const serverPublicKey = hex(
  '0bb3c2b5a44ea51f8b55344dedb23d32025edeb13e6677c27b8ba7244605a1eb' +
    'db5ccbbec83b8baaaf83aa364b15fc2acaf3245dc1640e740466f0bea62200534' +
    'f548d4f3525123e50d86ed02d0daf24c5fa9a91f46b575d343310a5515a0d7aa' +
    'cde1c1fb3b1de876d84756192468b0181d9781b55cad373342af2eb31261406ae' +
    '0cb6fc0d9d1d59784ee9907fdf5d3ea2a411c602c56172aa3bbe8e0b4e6d104' +
    '33e0782809112198b12b51ce55957290cb0c23083fa0b3de1f3d917117b99bef' +
    '578dacc1b246e2e1dd4f116389a297aeda6987824f9f644f3394a6e809acdddc' +
    '583ce1a441c187a40f8a9448197b18b7c01efc11c8d211dc1a77bd53f2a879b',
);
const serverProof = hex(
  'f2a6578bd80fa569c92aa9edca3fff5e2521d6b2fa90cf32e75d5bf2ad37b4f3',
);
const encryptedSpd = hex(
  '5d78631b1360781d12b9e5bd04b552581e99d61fd94816b474677ac3a4e51fea' +
    'f7502eed37ccc04c239fcc5ff580b6d968ad6ff5e9b31d1f8c659f0b48b894ad' +
    '2cfe13dff3e2fb9092463857548274f6845e68c9b7579056f302df4e476963fa0' +
    'a598e18dbe13b13391ea7114e6e677b002a2955228ef79a65f227933bf9205bd' +
    '6aac0ee40f9b21c104c6d4279b822446bdd7d7043e36390781fd4b4be7d673b7' +
    'fc31ee9f8676776a3685998e5486809873947098988e038fa242daff2239caae4' +
    '3954da322d286d0ee25ae3e1e7db4fab1e73ded656fbce7f9878f143e3d299',
);

const anisette = async () => ({
  'X-Apple-I-Client-Time': '2026-08-20T09:36:58Z',
  'X-Apple-I-MD': 'md',
  'X-Apple-I-MD-LU': 'md-lu',
  'X-Apple-I-MD-M': 'md-m',
  'X-Apple-I-MD-RINFO': '17106176',
  'X-Apple-I-SRL-NO': '0',
  'X-Apple-I-TimeZone': 'UTC',
  'X-Apple-Locale': 'en_US',
  'X-MMe-Client-Info': '<MacBookPro13,2> <macOS;13.1;22C65>',
  'X-Mme-Device-Id': '7F20A94F-FFF1-4B2C-A687-B6DE2FD363AB',
});
function srpResponses(status: Record<string, unknown> = { ec: 0 }) {
  return [
    response(
      200,
      buildPlist({
        Response: {
          Status: { ec: 0 },
          B: serverPublicKey,
          c: 'cookie',
          i: 20_000,
          s: salt,
          sp: 's2k',
        },
      }),
    ),
    response(
      200,
      buildPlist({
        Response: {
          Status: status,
          M2: serverProof,
          spd: encryptedSpd,
        },
      }),
    ),
  ];
}

function queuedTransport(responses: AppleResponse[]) {
  const requests: AppleRequestOptions[] = [];
  const request = async (options: AppleRequestOptions) => {
    requests.push(options);
    const next = responses.shift();
    if (!next) throw new Error('Unexpected Apple request');
    return next;
  };
  return { request, requests };
}

describe('apple/gsa', () => {
  it('surfaces the structured Apple error code for invalid credentials', async () => {
    const { request } = queuedTransport([
      response(
        200,
        buildPlist({
          Response: {
            Status: {
              ec: -20101,
              em: 'Your account information was entered incorrectly.',
            },
          },
        }),
      ),
    ]);

    const promise = authenticateWithGsa(
      'random-invalid@example.com',
      'random-password',
      undefined,
      undefined,
      'aabbccddeeff',
      { request, anisette, randomBytes: () => privateKey },
    );

    await expect(promise).rejects.toMatchObject({
      name: 'GsaProtocolError',
      code: -20101,
      message: 'Your account information was entered incorrectly.',
    } satisfies Partial<GsaProtocolError>);
  });

  it('exchanges the PET for StoreServices tokens and preserves redirects and cookies', async () => {
    const responses = [
      ...srpResponses(),
      response(
        302,
        '',
        {
          location:
            'https://p7-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?Pod=7',
        },
        [
          [
            'set-cookie',
            'mz_at0=first; Domain=.itunes.apple.com; Path=/; Secure; HttpOnly',
          ],
        ],
      ),
      response(
        200,
        buildPlist({
          accountInfo: {
            appleId: 'test@example.com',
            address: { firstName: 'Test', lastName: 'User' },
          },
          dsPersonId: '67890',
          passwordToken: 'password-token',
        }),
        { pod: '7', 'x-set-apple-store-front': '143441-1,29' },
        [
          [
            'set-cookie',
            'mz_at0=second; Domain=.itunes.apple.com; Path=/; Secure; HttpOnly',
          ],
        ],
      ),
    ];
    const { request, requests } = queuedTransport(responses);

    const account = await authenticateWithGsa(
      'test@example.com',
      'correct horse battery staple',
      undefined,
      [
        {
          name: 'existing',
          value: 'cookie',
          path: '/',
          httpOnly: false,
          secure: true,
        },
      ],
      'aabbccddeeff',
      { request, anisette, randomBytes: () => privateKey },
    );

    expect(requests.map(({ host }) => host)).toEqual([
      'gsa.apple.com',
      'gsa.apple.com',
      'buy.itunes.apple.com',
      'p7-buy.itunes.apple.com',
    ]);
    const complete = parsePlist(requests[1].body || '');
    expect(Buffer.from(complete.Request.M1).toString('hex')).toBe(
      '8b8b69f8c8ddb7f79886478ba340599da240539b693e6e0fc4eb40aa35659cf6',
    );
    const storeBody = parsePlist(requests[2].body || '');
    expect(storeBody.password).toBe('pet-value');
    expect(storeBody.createSession).toBe('true');
    expect(requests[2].headers?.['X-Apple-Identity-Token']).toBe(
      'MTIzNDU6dG9rZW4tdmFsdWU=',
    );
    expect(requests[3].body).toBe(requests[2].body);
    expect(requests[3].cookies?.map(({ name }) => name)).toContain('mz_at0');

    expect(account.passwordToken).toBe('password-token');
    expect(account.directoryServicesIdentifier).toBe('67890');
    expect(account.store).toBe('143441');
    expect(account.pod).toBe('7');
    expect(account.cookies.find(({ name }) => name === 'mz_at0')?.value).toBe(
      'second',
    );
    expect(account.cookies.map(({ name }) => name)).toContain('existing');
  });

  it('triggers the trusted-device flow before requesting a code', async () => {
    const { request, requests } = queuedTransport([
      ...srpResponses({ ec: 0, au: 'trustedDeviceSecondaryAuth' }),
      response(200, ''),
    ]);

    const promise = authenticateWithGsa(
      'test@example.com',
      'correct horse battery staple',
      undefined,
      undefined,
      'aabbccddeeff',
      { request, anisette, randomBytes: () => privateKey },
    );

    await expect(promise).rejects.toBeInstanceOf(
      GsaVerificationRequiredError,
    );
    expect(requests[2]).toMatchObject({
      host: 'gsa.apple.com',
      path: '/auth/verify/trusteddevice',
      method: 'GET',
    });
  });
});
