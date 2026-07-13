import crypto from 'crypto';

/**
 * @andrewpopov/webhook-kit — framework-agnostic outbound webhook delivery.
 *
 * Owns the drift-prone core that cairn and bewks had independently reimplemented:
 * HMAC signing over `${timestamp}.${body}`, the `sha256=` + `X-Webhook-Timestamp`
 * headers, a fire-time SSRF re-check, per-attempt timeout, `redirect: 'manual'`,
 * and error isolation. The body shape, the SSRF guard, and logging are injected,
 * so each consumer keeps its exact wire contract.
 */

export const SIGNATURE_HEADER = 'X-Webhook-Signature';
export const TIMESTAMP_HEADER = 'X-Webhook-Timestamp';
export const DELIVERY_ID_HEADER = 'X-Webhook-Delivery-Id';
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_TOLERANCE_SEC = 300;

/** Generate a webhook signing secret (256-bit, hex-encoded). */
export function generateWebhookSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Resolve a secret-update input under the "always signed" invariant:
 * `undefined` → no change; a non-empty string → use it as-is; `null`/`''` →
 * rotate to a fresh generated secret. A webhook never becomes unsigned, so an
 * explicit clear rotates rather than removes.
 */
export function resolveSecretRotation(input: string | null | undefined): string | undefined {
  if (input === undefined) return undefined;
  return input && input.length > 0 ? input : generateWebhookSecret();
}

/** True if a subscription list matches an event, honoring the `*` wildcard. */
export function matchesEvent(subscribedEvents: readonly string[], event: string): boolean {
  return subscribedEvents.includes(event) || subscribedEvents.includes('*');
}

/** Compute the `sha256=<hex>` signature over `` `${timestamp}.${body}` ``. */
export function signWebhookBody(secret: string, timestamp: string, body: string): string {
  const hex = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `sha256=${hex}`;
}

/** Compute a signature bound to a unique delivery id as well as timestamp and body. */
export function signWebhookDelivery(secret: string, timestamp: string, deliveryId: string, body: string): string {
  const hex = crypto.createHmac('sha256', secret).update(`${timestamp}.${deliveryId}.${body}`).digest('hex');
  return `sha256=${hex}`;
}

export interface BuildHeadersOptions {
  /** Clock source (unix ms), for tests. Defaults to `Date.now`. */
  now?: () => number;
  contentType?: string;
  /** Deterministic seam for tests or a caller-owned idempotency key. */
  deliveryId?: string;
}

/**
 * Build signed request headers for a delivery, returning the unix-seconds
 * timestamp used (so the caller can log/persist it). When `secret` is falsy only
 * `Content-Type` is set — keep every webhook secret-backed so delivery is signed.
 */
export function buildSignedHeaders(
  secret: string | null | undefined,
  body: string,
  options: BuildHeadersOptions = {},
): { headers: Record<string, string>; timestamp: string; deliveryId: string } {
  const timestamp = Math.floor((options.now ? options.now() : Date.now()) / 1000).toString();
  const deliveryId = options.deliveryId ?? crypto.randomUUID();
  const headers: Record<string, string> = { 'Content-Type': options.contentType ?? 'application/json' };
  if (secret) {
    headers[SIGNATURE_HEADER] = signWebhookDelivery(secret, timestamp, deliveryId, body);
    headers[TIMESTAMP_HEADER] = timestamp;
    headers[DELIVERY_ID_HEADER] = deliveryId;
  }
  return { headers, timestamp, deliveryId };
}

export interface VerifyParams {
  secret: string;
  rawBody: string;
  signatureHeader: string | null | undefined;
  timestampHeader: string | null | undefined;
  deliveryIdHeader?: string | null | undefined;
  /** Reject deliveries whose timestamp is further than this from now. Default 300s. */
  toleranceSec?: number;
  now?: () => number;
}

/**
 * Receiver-side verification. Returns true only when the signature matches
 * `` `${timestamp}.${rawBody}` `` (constant-time) AND the timestamp is within
 * `toleranceSec` of now — the freshness window that makes a captured delivery
 * unreplayable. Use this to verify inbound webhooks signed by this library.
 */
export function verifyWebhookSignature(params: VerifyParams): boolean {
  const { secret, rawBody, signatureHeader, timestampHeader } = params;
  if (!signatureHeader || !timestampHeader) return false;
  if (!/^\d+$/.test(timestampHeader)) return false;

  const tolerance = params.toleranceSec ?? DEFAULT_TOLERANCE_SEC;
  const nowSec = Math.floor((params.now ? params.now() : Date.now()) / 1000);
  if (Math.abs(nowSec - Number(timestampHeader)) > tolerance) return false;

  const expected = params.deliveryIdHeader
    ? signWebhookDelivery(secret, timestampHeader, params.deliveryIdHeader, rawBody)
    : signWebhookBody(secret, timestampHeader, rawBody);
  const given = Buffer.from(signatureHeader);
  const want = Buffer.from(expected);
  if (given.length !== want.length) return false;
  return crypto.timingSafeEqual(given, want);
}

/** Store must atomically reserve an id until expiry, returning false when it was already seen. */
export interface WebhookReplayStore {
  claim(deliveryId: string, expiresAt: Date): Promise<boolean> | boolean;
}

/**
 * Recommended receiver API: verifies a delivery-id-bound signature and then
 * atomically claims that id. A replay inside the timestamp tolerance is denied.
 */
export async function verifyWebhookDelivery(params: VerifyParams & {
  deliveryIdHeader: string | null | undefined;
  replayStore: WebhookReplayStore;
}): Promise<boolean> {
  const deliveryId = params.deliveryIdHeader;
  if (!deliveryId || !/^[A-Za-z0-9._-]{1,200}$/.test(deliveryId)) return false;
  if (!verifyWebhookSignature(params)) return false;
  const timestamp = Number(params.timestampHeader);
  const expiresAt = new Date((timestamp + (params.toleranceSec ?? DEFAULT_TOLERANCE_SEC)) * 1000);
  try {
    return await params.replayStore.claim(deliveryId, expiresAt);
  } catch {
    return false;
  }
}

export interface WebhookTarget {
  url: string;
  secret?: string | null;
  /** Opaque id echoed back in the DeliveryResult for the caller's logs. */
  id?: string;
}

export interface DeliverOptions {
  /**
   * Fire-time URL safety check (SSRF guard). If it throws/rejects, the target is
   * SKIPPED (reported with `skipped: true`), not delivered. Inject the app's own
   * guard — a DNS rebind after registration is why this must run per attempt.
   * Only whether it throws matters; any return value is awaited and ignored, so
   * guards that return the parsed URL (or nothing) both fit.
   */
  assertSafeUrl: (url: string) => unknown;
  timeoutMs?: number;
  /** Override fetch (tests / non-global environments). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  now?: () => number;
  contentType?: string;
  /** Maximum simultaneous requests for `deliverWebhooks`. Default 8. */
  concurrency?: number;
}

/** Explicit opt-out for migrations that cannot yet provide a signing secret or SSRF guard. */
export type UnsafeDeliverOptions = Omit<DeliverOptions, 'assertSafeUrl'> & {
  assertSafeUrl?: (url: string) => unknown;
};

export interface DeliveryResult {
  url: string;
  id?: string;
  deliveryId?: string;
  ok: boolean;
  status?: number;
  /** True when the SSRF guard rejected the URL and delivery was not attempted. */
  skipped?: boolean;
  error?: Error;
}

function asError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

function redactUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return '<invalid URL>';
  }
}

function redactError(error: unknown, rawUrl: string): Error {
  const message = asError(error).message.split(rawUrl).join(redactUrl(rawUrl));
  return new Error(message);
}

/**
 * Deliver one signed webhook. Never throws — a guard rejection, timeout, or
 * transport failure comes back in the result. `redirect: 'manual'` ensures a 3xx
 * cannot bounce the request past the SSRF guard to an unvetted host.
 */
export async function deliverWebhook(
  target: WebhookTarget,
  body: string,
  options: DeliverOptions,
): Promise<DeliveryResult> {
  return deliver(target, body, options, true);
}

/**
 * Permissive migration escape hatch. It may send without a signing secret or
 * SSRF guard, so never use it for a new untrusted webhook integration.
 */
export async function deliverWebhookUnsafe(
  target: WebhookTarget,
  body: string,
  options: UnsafeDeliverOptions = {},
): Promise<DeliveryResult> {
  return deliver(target, body, options, false);
}

async function deliver(
  target: WebhookTarget,
  body: string,
  options: UnsafeDeliverOptions,
  requireSafeDelivery: boolean,
): Promise<DeliveryResult> {
  const base: DeliveryResult = { url: redactUrl(target.url), id: target.id, ok: false };

  if (requireSafeDelivery && !target.secret) {
    return { ...base, skipped: true, error: new Error('Webhook signing secret is required') };
  }
  if (requireSafeDelivery && !options.assertSafeUrl) {
    return { ...base, skipped: true, error: new Error('Webhook URL guard is required') };
  }

  if (options.assertSafeUrl) {
    try {
      await options.assertSafeUrl(target.url);
    } catch (error) {
      return { ...base, skipped: true, error: redactError(error, target.url) };
    }
  }

  const doFetch = options.fetchImpl ?? globalThis.fetch;
  const { headers, deliveryId } = buildSignedHeaders(target.secret, body, {
    now: options.now,
    contentType: options.contentType,
  });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await doFetch(target.url, {
      method: 'POST',
      headers,
      body,
      redirect: 'manual',
      signal: controller.signal,
    });
    return { ...base, deliveryId, ok: res.ok, status: res.status };
  } catch (error) {
    return { ...base, error: redactError(error, target.url) };
  } finally {
    clearTimeout(timeout);
  }
}

/** Deliver to many targets with bounded concurrency. Never rejects; one result per target. */
export async function deliverWebhooks(
  targets: readonly WebhookTarget[],
  body: string,
  options: DeliverOptions,
): Promise<DeliveryResult[]> {
  const concurrency = options.concurrency ?? 8;
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new TypeError('concurrency must be a positive integer');
  }

  const results = new Array<DeliveryResult>(targets.length);
  let nextIndex = 0;
  async function worker(): Promise<void> {
    while (nextIndex < targets.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await deliverWebhook(targets[index], body, options);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
  return results;
}
