import { Router, Request, Response } from 'express';
import http from 'http';
import https from 'https';
import {
  ANISETTE_MAX_BYTES,
  ANISETTE_TIMEOUT_MS,
  config,
} from '../config.js';

const router = Router();

const allowedHeaders = [
  'X-Apple-I-Client-Time',
  'X-Apple-I-MD',
  'X-Apple-I-MD-LU',
  'X-Apple-I-MD-M',
  'X-Apple-I-MD-RINFO',
  'X-Apple-I-SRL-NO',
  'X-Apple-I-TimeZone',
  'X-Apple-Locale',
  'X-MMe-Client-Info',
  'X-Mme-Device-Id',
] as const;

const requiredHeaders = [
  'X-Apple-I-MD',
  'X-Apple-I-MD-M',
  'X-Mme-Device-Id',
] as const;

router.get('/anisette', async (_req: Request, res: Response) => {
  try {
    const url = new URL(config.anisetteUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new Error('Unsupported anisette URL protocol');
    }
    const transport = url.protocol === 'https:' ? https : http;
    const body = await new Promise<string>((resolve, reject) => {
      const request = transport.get(
        url,
        {
          headers: { Accept: 'application/json' },
          timeout: ANISETTE_TIMEOUT_MS,
        },
        (response) => {
          let data = '';
          let totalBytes = 0;
          response.on('data', (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes > ANISETTE_MAX_BYTES) {
              request.destroy();
              reject(new Error('Anisette response too large'));
              return;
            }
            data += chunk;
          });
          response.on('end', () => {
            if (
              !response.statusCode ||
              response.statusCode < 200 ||
              response.statusCode >= 300
            ) {
              reject(
                new Error(
                  `Anisette upstream returned HTTP ${response.statusCode || 0}`,
                ),
              );
              return;
            }
            resolve(data);
          });
          response.on('error', reject);
        },
      );
      request.on('error', reject);
      request.on('timeout', () => {
        request.destroy();
        reject(new Error('Anisette request timed out'));
      });
    });

    const parsed = JSON.parse(body) as Record<string, unknown>;
    for (const name of requiredHeaders) {
      if (typeof parsed[name] !== 'string' || !parsed[name]) {
        throw new Error(`Anisette response is missing ${name}`);
      }
    }

    const filtered: Record<string, string> = {};
    for (const name of allowedHeaders) {
      if (typeof parsed[name] === 'string') filtered[name] = parsed[name];
    }
    res.json(filtered);
  } catch (error) {
    console.error(
      'Anisette proxy error:',
      error instanceof Error ? error.message : error,
    );
    res.status(502).json({ error: 'Anisette request failed' });
  }
});

export default router;
