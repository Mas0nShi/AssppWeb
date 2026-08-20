import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'events';
import express from 'express';
import http from 'http';
import request from 'supertest';
import anisetteRoutes from '../src/routes/anisette.js';

function createApp() {
  const app = express();
  app.use('/api', anisetteRoutes);
  return app;
}

describe('Anisette Route', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns only the anisette attestation headers', async () => {
    vi.spyOn(http, 'get').mockImplementation((
      _url: any,
      _options: any,
      callback: any,
    ) => {
      const response = new EventEmitter() as any;
      response.statusCode = 200;
      setTimeout(() => {
        response.emit(
          'data',
          JSON.stringify({
            'X-Apple-I-MD': 'md',
            'X-Apple-I-MD-M': 'md-m',
            'X-Mme-Device-Id': 'device',
            'X-Apple-I-Client-Time': '2026-08-20T09:36:58Z',
            secret: 'must-not-be-reflected',
          }),
        );
        response.emit('end');
      }, 0);
      callback(response);
      return new EventEmitter() as any;
    });

    const result = await request(createApp()).get('/api/anisette');

    expect(result.status).toBe(200);
    expect(result.body['X-Apple-I-MD']).toBe('md');
    expect(result.body['X-Mme-Device-Id']).toBe('device');
    expect(result.body.secret).toBeUndefined();
  });

  it('rejects incomplete upstream responses', async () => {
    vi.spyOn(http, 'get').mockImplementation((
      _url: any,
      _options: any,
      callback: any,
    ) => {
      const response = new EventEmitter() as any;
      response.statusCode = 200;
      setTimeout(() => {
        response.emit('data', JSON.stringify({ 'X-Apple-I-MD': 'md' }));
        response.emit('end');
      }, 0);
      callback(response);
      return new EventEmitter() as any;
    });

    const result = await request(createApp()).get('/api/anisette');

    expect(result.status).toBe(502);
    expect(result.body.error).toBe('Anisette request failed');
  });
});
