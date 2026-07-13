import { describe, it, expect, vi } from 'vitest';
import crypto from 'crypto';
import {
  generateWebhookSecret,
  resolveSecretRotation,
  matchesEvent,
  signWebhookBody,
  signWebhookDelivery,
  buildSignedHeaders,
  verifyWebhookSignature,
  verifyWebhookDelivery,
  deliverWebhook,
  deliverWebhookUnsafe,
  deliverWebhooks,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  DELIVERY_ID_HEADER,
} from '../index';

describe('generateWebhookSecret', () => {
  it('returns a 256-bit hex secret, unique per call', () => {
    const a = generateWebhookSecret();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(generateWebhookSecret());
  });
});

describe('resolveSecretRotation (always-signed invariant)', () => {
  it('leaves undefined as undefined (no change)', () => {
    expect(resolveSecretRotation(undefined)).toBeUndefined();
  });
  it('keeps a non-empty string as-is', () => {
    expect(resolveSecretRotation('abc')).toBe('abc');
  });
  it('rotates null or empty to a fresh secret rather than clearing', () => {
    expect(resolveSecretRotation(null)).toMatch(/^[0-9a-f]{64}$/);
    expect(resolveSecretRotation('')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('matchesEvent', () => {
  it('matches an exact event and the wildcard, not an unrelated one', () => {
    expect(matchesEvent(['book.added'], 'book.added')).toBe(true);
    expect(matchesEvent(['*'], 'anything')).toBe(true);
    expect(matchesEvent(['book.added'], 'book.deleted')).toBe(false);
  });
});

describe('signWebhookBody', () => {
  it('signs `${timestamp}.${body}` with the sha256= prefix', () => {
    const sig = signWebhookBody('s3cr3t', '1700000000', '{"a":1}');
    const expected =
      'sha256=' + crypto.createHmac('sha256', 's3cr3t').update('1700000000.{"a":1}').digest('hex');
    expect(sig).toBe(expected);
    // Bound to the timestamp: body-only signing differs.
    const bodyOnly = 'sha256=' + crypto.createHmac('sha256', 's3cr3t').update('{"a":1}').digest('hex');
    expect(sig).not.toBe(bodyOnly);
  });
});

describe('buildSignedHeaders', () => {
  it('emits a delivery-id-bound signature, timestamp, and id when a secret is present', () => {
    const { headers, timestamp, deliveryId } = buildSignedHeaders('sec', '{}', { now: () => 1700000000_000, deliveryId: 'delivery-1' });
    expect(timestamp).toBe('1700000000');
    expect(headers[TIMESTAMP_HEADER]).toBe('1700000000');
    expect(deliveryId).toBe('delivery-1');
    expect(headers[DELIVERY_ID_HEADER]).toBe('delivery-1');
    expect(headers[SIGNATURE_HEADER]).toBe(signWebhookDelivery('sec', '1700000000', 'delivery-1', '{}'));
    expect(headers['Content-Type']).toBe('application/json');
  });
  it('omits signature headers when no secret', () => {
    const { headers } = buildSignedHeaders(null, '{}');
    expect(headers[SIGNATURE_HEADER]).toBeUndefined();
    expect(headers[TIMESTAMP_HEADER]).toBeUndefined();
  });
});

describe('verifyWebhookSignature (receiver side)', () => {
  const secret = 'shared-secret';
  const body = '{"event":"book.added"}';

  it('round-trips: what buildSignedHeaders signs, verify accepts', () => {
    const now = () => 1700000000_000;
    const { headers } = buildSignedHeaders(secret, body, { now });
    expect(
      verifyWebhookSignature({
        secret,
        rawBody: body,
        signatureHeader: headers[SIGNATURE_HEADER],
        timestampHeader: headers[TIMESTAMP_HEADER],
        deliveryIdHeader: headers[DELIVERY_ID_HEADER],
        now,
      }),
    ).toBe(true);
  });

  it('rejects a tampered body', () => {
    const now = () => 1700000000_000;
    const { headers } = buildSignedHeaders(secret, body, { now });
    expect(
      verifyWebhookSignature({
        secret,
        rawBody: body + 'x',
        signatureHeader: headers[SIGNATURE_HEADER],
        timestampHeader: headers[TIMESTAMP_HEADER],
        deliveryIdHeader: headers[DELIVERY_ID_HEADER],
        now,
      }),
    ).toBe(false);
  });

  it('rejects a stale timestamp (replay) outside the tolerance', () => {
    const signedAt = () => 1700000000_000;
    const { headers } = buildSignedHeaders(secret, body, { now: signedAt });
    // Verify 10 minutes later with a 5-minute tolerance.
    expect(
      verifyWebhookSignature({
        secret,
        rawBody: body,
        signatureHeader: headers[SIGNATURE_HEADER],
        timestampHeader: headers[TIMESTAMP_HEADER],
        deliveryIdHeader: headers[DELIVERY_ID_HEADER],
        toleranceSec: 300,
        now: () => 1700000000_000 + 600_000,
      }),
    ).toBe(false);
  });

  it('rejects missing headers and a non-numeric timestamp', () => {
    expect(verifyWebhookSignature({ secret, rawBody: body, signatureHeader: null, timestampHeader: '1' })).toBe(false);
    expect(verifyWebhookSignature({ secret, rawBody: body, signatureHeader: 'sha256=x', timestampHeader: null })).toBe(false);
    expect(verifyWebhookSignature({ secret, rawBody: body, signatureHeader: 'sha256=x', timestampHeader: 'nope' })).toBe(false);
  });

  it('rejects a signature made with a different secret', () => {
    const now = () => 1700000000_000;
    const { headers } = buildSignedHeaders('other-secret', body, { now });
    expect(
      verifyWebhookSignature({
        secret,
        rawBody: body,
        signatureHeader: headers[SIGNATURE_HEADER],
        timestampHeader: headers[TIMESTAMP_HEADER],
        deliveryIdHeader: headers[DELIVERY_ID_HEADER],
        now,
      }),
    ).toBe(false);
  });

  it('rejects a replay inside the timestamp tolerance through an atomic replay store', async () => {
    const now = () => 1700000000_000;
    const { headers } = buildSignedHeaders(secret, body, { now, deliveryId: 'delivery-1' });
    const claimed = new Set<string>();
    const replayStore = { claim: async (id: string) => {
      if (claimed.has(id)) return false;
      claimed.add(id);
      return true;
    } };
    const params = {
      secret,
      rawBody: body,
      signatureHeader: headers[SIGNATURE_HEADER],
      timestampHeader: headers[TIMESTAMP_HEADER],
      deliveryIdHeader: headers[DELIVERY_ID_HEADER],
      replayStore,
      now,
    };
    await expect(verifyWebhookDelivery(params)).resolves.toBe(true);
    await expect(verifyWebhookDelivery(params)).resolves.toBe(false);
  });
});

describe('deliverWebhook', () => {
  it('POSTs signed, with redirect: manual, and reports status', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
      calls.push([url, init]);
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;

    const res = await deliverWebhook(
      { url: 'https://example.com/hook', secret: 'sec', id: 'w1' },
      '{"x":1}',
      { fetchImpl, now: () => 1700000000_000, assertSafeUrl: () => undefined },
    );

    expect(res).toMatchObject({ url: 'https://example.com/hook', id: 'w1', deliveryId: expect.any(String), ok: true, status: 200 });
    const [, init] = calls[0];
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('manual');
    const h = init.headers as Record<string, string>;
    expect(h[DELIVERY_ID_HEADER]).toBe(res.deliveryId);
    expect(h[SIGNATURE_HEADER]).toBe(signWebhookDelivery('sec', '1700000000', res.deliveryId!, '{"x":1}'));
    expect(h[TIMESTAMP_HEADER]).toBe('1700000000');
  });

  it('skips (does not fetch) when the SSRF guard rejects the URL', async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const res = await deliverWebhook(
      { url: 'http://169.254.169.254/', secret: 'sec' },
      '{}',
      { fetchImpl, assertSafeUrl: () => { throw new Error('blocked'); } },
    );
    expect(res.skipped).toBe(true);
    expect(res.ok).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('never throws on transport failure — returns the error', async () => {
    const fetchImpl = vi.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;
    const res = await deliverWebhook({ url: 'https://down.example', secret: 'sec' }, '{}', {
      fetchImpl,
      assertSafeUrl: () => undefined,
    });
    expect(res.ok).toBe(false);
    expect(res.skipped).toBeUndefined();
    expect(res.error?.message).toBe('ECONNREFUSED');
  });

  it('fails closed when a signing secret or URL guard is missing', async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const unsigned = await deliverWebhook({ url: 'https://example.com/hook' }, '{}', {
      fetchImpl,
      assertSafeUrl: () => undefined,
    });
    const unguarded = await deliverWebhook({ url: 'https://example.com/hook', secret: 'sec' }, '{}', {
      fetchImpl,
      // JavaScript callers can still omit the compile-time-required property.
      assertSafeUrl: undefined as unknown as (url: string) => unknown,
    });
    expect(unsigned.error?.message).toBe('Webhook signing secret is required');
    expect(unguarded.error?.message).toBe('Webhook URL guard is required');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('keeps unsigned or unguarded delivery behind an explicit unsafe API', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 202 })) as unknown as typeof fetch;
    const result = await deliverWebhookUnsafe({ url: 'https://example.com/hook' }, '{}', { fetchImpl });
    expect(result).toMatchObject({ ok: true, status: 202 });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('redacts credentials and query strings from results and guard errors', async () => {
    const result = await deliverWebhook(
      { url: 'https://user:secret@example.com/hook?token=leak', secret: 'sec' },
      '{}',
      { assertSafeUrl: () => { throw new Error('blocked https://user:secret@example.com/hook?token=leak'); } },
    );
    expect(result.url).toBe('https://example.com/hook');
    expect(result.error?.message).not.toContain('secret');
    expect(result.error?.message).not.toContain('token=leak');
  });
});

describe('deliverWebhooks', () => {
  it('delivers to every target in parallel and returns one result each', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 202 })) as unknown as typeof fetch;
    const results = await deliverWebhooks(
      [
        { url: 'https://a.example/h', secret: 's1' },
        { url: 'https://b.example/h', secret: 's2' },
      ],
      '{}',
      { fetchImpl, assertSafeUrl: () => undefined },
    );
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.ok && r.status === 202)).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('limits concurrent deliveries while retaining input order', async () => {
    let active = 0;
    let peak = 0;
    const fetchImpl = vi.fn(async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return new Response('{}', { status: 202 });
    }) as unknown as typeof fetch;
    const targets = Array.from({ length: 5 }, (_, index) => ({ url: `https://${index}.example/h`, secret: 'sec', id: `${index}` }));
    const results = await deliverWebhooks(targets, '{}', { fetchImpl, assertSafeUrl: () => undefined, concurrency: 2 });
    expect(peak).toBeLessThanOrEqual(2);
    expect(results.map((result) => result.id)).toEqual(['0', '1', '2', '3', '4']);
  });
});
