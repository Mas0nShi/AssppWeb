// SRP-6a and SPD helpers for Apple's GrandSlam authentication protocol.
// The group is the RFC 5054 2048-bit group and the proof layout matches pysrp.

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const modulus = BigInt(
  '0x' +
    'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A' +
    '37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8' +
    '083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F' +
    '97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B' +
    '43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B' +
    '524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73' +
    '03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D' +
    '89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73',
);
const generator = 2n;
const modulusBytes = 256;

export interface SrpChallenge {
  salt: Uint8Array;
  serverPublicKey: Uint8Array;
  iterations: number;
  protocol: string;
}

export interface SrpProof {
  clientPublicKey: Uint8Array;
  clientProof: Uint8Array;
  sessionKey: Uint8Array;
  expectedServerProof: Uint8Array;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length === 0) return 0n;
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return BigInt(`0x${hex}`);
}

function bigIntToBytes(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array();
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = `0${hex}`;
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

function padLeft(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length > length) {
    throw new Error('SRP integer exceeds the group width');
  }
  const result = new Uint8Array(length);
  result.set(bytes, length - bytes.length);
  return result;
}

function modPow(base: bigint, exponent: bigint, modulo: bigint): bigint {
  let result = 1n;
  let current = ((base % modulo) + modulo) % modulo;
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = (result * current) % modulo;
    power >>= 1n;
    current = (current * current) % modulo;
  }
  return result;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    arrayBuffer(concatBytes(...parts)),
  );
  return new Uint8Array(digest);
}

async function hmacSha256(
  key: Uint8Array,
  value: string,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      arrayBuffer(textEncoder.encode(value)),
    ),
  );
}

async function derivePassword(
  password: string,
  protocol: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const passwordHash = await sha256(textEncoder.encode(password));
  let passwordMaterial = passwordHash;
  if (protocol === 's2k_fo') {
    const hex = Array.from(passwordHash)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
    passwordMaterial = textEncoder.encode(hex);
  } else if (protocol !== 's2k') {
    throw new Error(`Unsupported Apple SRP protocol: ${protocol}`);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(passwordMaterial),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: arrayBuffer(salt),
      iterations,
    },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export function srpPublicKey(privateKey: Uint8Array): Uint8Array {
  const privateValue = bytesToBigInt(privateKey);
  if (privateValue === 0n) throw new Error('SRP private key must not be zero');
  return bigIntToBytes(modPow(generator, privateValue, modulus));
}

export async function createSrpProof(
  email: string,
  password: string,
  privateKey: Uint8Array,
  challenge: SrpChallenge,
): Promise<SrpProof> {
  if (!Number.isSafeInteger(challenge.iterations) || challenge.iterations <= 0) {
    throw new Error('Invalid Apple SRP iteration count');
  }

  const privateValue = bytesToBigInt(privateKey);
  const clientPublicKey = srpPublicKey(privateKey);
  const serverPublicValue = bytesToBigInt(challenge.serverPublicKey);
  if (serverPublicValue % modulus === 0n) {
    throw new Error('Invalid Apple SRP server public key');
  }

  const paddedModulus = padLeft(bigIntToBytes(modulus), modulusBytes);
  const paddedGenerator = padLeft(bigIntToBytes(generator), modulusBytes);
  const paddedClientPublicKey = padLeft(clientPublicKey, modulusBytes);
  const paddedServerPublicKey = padLeft(
    bigIntToBytes(serverPublicValue),
    modulusBytes,
  );

  const multiplier = bytesToBigInt(
    await sha256(paddedModulus, paddedGenerator),
  );
  const scramblingParameter = bytesToBigInt(
    await sha256(paddedClientPublicKey, paddedServerPublicKey),
  );
  if (scramblingParameter === 0n) {
    throw new Error('Invalid Apple SRP scrambling parameter');
  }

  const derivedPassword = await derivePassword(
    password,
    challenge.protocol,
    challenge.salt,
    challenge.iterations,
  );
  const passwordHash = await sha256(
    textEncoder.encode(':'),
    derivedPassword,
  );
  const privatePasswordValue = bytesToBigInt(
    await sha256(challenge.salt, passwordHash),
  );

  const verifier = modPow(generator, privatePasswordValue, modulus);
  let base =
    (serverPublicValue - (multiplier * verifier) % modulus) % modulus;
  if (base < 0n) base += modulus;
  const sharedSecret = bigIntToBytes(
    modPow(
      base,
      privateValue + scramblingParameter * privatePasswordValue,
      modulus,
    ),
  );
  const sessionKey = await sha256(sharedSecret);

  const modulusHash = await sha256(paddedModulus);
  const generatorHash = await sha256(paddedGenerator);
  const groupHash = new Uint8Array(modulusHash.length);
  for (let i = 0; i < groupHash.length; i++) {
    groupHash[i] = modulusHash[i] ^ generatorHash[i];
  }

  const clientProof = await sha256(
    groupHash,
    await sha256(textEncoder.encode(email)),
    challenge.salt,
    clientPublicKey,
    bigIntToBytes(serverPublicValue),
    sessionKey,
  );
  const expectedServerProof = await sha256(
    clientPublicKey,
    clientProof,
    sessionKey,
  );

  return {
    clientPublicKey,
    clientProof,
    sessionKey,
    expectedServerProof,
  };
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference === 0;
}

export async function decryptSpd(
  sessionKey: Uint8Array,
  ciphertext: Uint8Array,
): Promise<string> {
  const keyBytes = await hmacSha256(sessionKey, 'extra data key:');
  const ivBytes = (await hmacSha256(sessionKey, 'extra data iv:')).slice(0, 16);
  const key = await crypto.subtle.importKey(
    'raw',
    arrayBuffer(keyBytes),
    'AES-CBC',
    false,
    ['decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: arrayBuffer(ivBytes) },
    key,
    arrayBuffer(ciphertext),
  );
  return textDecoder.decode(plaintext);
}
