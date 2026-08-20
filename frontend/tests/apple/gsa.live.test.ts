import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  authenticateWithGsa,
  GsaProtocolError,
} from '../../src/apple/gsa';
import type { AppleTransport } from '../../src/apple/gsa';

const runLive = process.env.GSA_LIVE === '1';

const curlTransport: AppleTransport = async (options) => {
  const directory = mkdtempSync(join(tmpdir(), 'asspp-gsa-live-'));
  const headerPath = join(directory, 'headers.txt');
  const bodyPath = join(directory, 'body.bin');
  try {
    const args = [
      '-sS',
      '--max-time',
      '30',
      '-X',
      options.method,
      `https://${options.host}${options.path}`,
      '-D',
      headerPath,
      '-o',
      bodyPath,
      '-w',
      '%{http_code}',
    ];
    const proxy = process.env.GSA_SMOKE_PROXY;
    if (proxy) args.push('--proxy', proxy);
    for (const [name, value] of Object.entries(options.headers || {})) {
      args.push('-H', `${name}: ${value}`);
    }
    if (options.body !== undefined) args.push('--data-binary', '@-');
    const status = Number(
      execFileSync('/usr/bin/curl', args, {
        input: options.body,
        encoding: 'utf8',
        maxBuffer: 2 * 1024 * 1024,
      }),
    );
    const rawHeaders: [string, string][] = readFileSync(headerPath, 'utf8')
      .split(/\r?\n/)
      .flatMap((line) => {
        const separator = line.indexOf(':');
        if (separator <= 0) return [];
        return [[line.slice(0, separator), line.slice(separator + 1).trim()]];
      });
    return {
      status,
      statusText: '',
      headers: Object.fromEntries(
        rawHeaders.map(([name, value]) => [name.toLowerCase(), value]),
      ),
      rawHeaders,
      body: readFileSync(bodyPath, 'utf8'),
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

describe.runIf(runLive)('apple/gsa live smoke', () => {
  it(
    'gets a structured Apple error for random credentials',
    async () => {
      const anisetteUrl =
        process.env.ANISETTE_SMOKE_URL || 'http://127.0.0.1:16969';
      const anisette = async () => {
        const response = await fetch(anisetteUrl);
        if (!response.ok) {
          throw new Error(`Anisette smoke endpoint returned ${response.status}`);
        }
        return response.json();
      };

      const email = `asspp-smoke-${crypto.randomUUID()}@example.invalid`;
      const password = crypto.randomUUID();
      try {
        await authenticateWithGsa(
          email,
          password,
          undefined,
          undefined,
          'aabbccddeeff',
          { request: curlTransport, anisette },
        );
        throw new Error('Random Apple credentials unexpectedly authenticated');
      } catch (error) {
        expect(error).toBeInstanceOf(GsaProtocolError);
        const protocolError = error as GsaProtocolError;
        expect(protocolError.code).toBeTypeOf('number');
        expect(protocolError.message.length).toBeGreaterThan(0);
        console.info(
          `Apple GSA structured rejection: ec=${protocolError.code} ${protocolError.message}`,
        );
      }
    },
    60_000,
  );
});
