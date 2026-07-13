"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_TOLERANCE_SEC = exports.DEFAULT_TIMEOUT_MS = exports.DELIVERY_ID_HEADER = exports.TIMESTAMP_HEADER = exports.SIGNATURE_HEADER = void 0;
exports.generateWebhookSecret = generateWebhookSecret;
exports.resolveSecretRotation = resolveSecretRotation;
exports.matchesEvent = matchesEvent;
exports.signWebhookBody = signWebhookBody;
exports.signWebhookDelivery = signWebhookDelivery;
exports.buildSignedHeaders = buildSignedHeaders;
exports.verifyWebhookSignature = verifyWebhookSignature;
exports.verifyWebhookDelivery = verifyWebhookDelivery;
exports.deliverWebhook = deliverWebhook;
exports.deliverWebhookUnsafe = deliverWebhookUnsafe;
exports.deliverWebhooks = deliverWebhooks;
const crypto_1 = __importDefault(require("crypto"));
/**
 * @andrewpopov/webhook-kit — framework-agnostic outbound webhook delivery.
 *
 * Owns the drift-prone core that cairn and bewks had independently reimplemented:
 * HMAC signing over `${timestamp}.${deliveryId}.${body}`, `sha256=`, timestamp,
 * and delivery-ID headers, a fire-time SSRF re-check, per-attempt timeout,
 * `redirect: 'manual'`, and error isolation. The body shape, the SSRF guard,
 * replay storage, and logging are injected, so each consumer keeps its exact
 * wire contract.
 */
exports.SIGNATURE_HEADER = 'X-Webhook-Signature';
exports.TIMESTAMP_HEADER = 'X-Webhook-Timestamp';
exports.DELIVERY_ID_HEADER = 'X-Webhook-Delivery-Id';
exports.DEFAULT_TIMEOUT_MS = 10000;
exports.DEFAULT_TOLERANCE_SEC = 300;
/** Generate a webhook signing secret (256-bit, hex-encoded). */
function generateWebhookSecret() {
    return crypto_1.default.randomBytes(32).toString('hex');
}
/**
 * Resolve a secret-update input under the "always signed" invariant:
 * `undefined` → no change; a non-empty string → use it as-is; `null`/`''` →
 * rotate to a fresh generated secret. A webhook never becomes unsigned, so an
 * explicit clear rotates rather than removes.
 */
function resolveSecretRotation(input) {
    if (input === undefined)
        return undefined;
    return input && input.length > 0 ? input : generateWebhookSecret();
}
/** True if a subscription list matches an event, honoring the `*` wildcard. */
function matchesEvent(subscribedEvents, event) {
    return subscribedEvents.includes(event) || subscribedEvents.includes('*');
}
/** Compute the `sha256=<hex>` signature over `` `${timestamp}.${body}` ``. */
function signWebhookBody(secret, timestamp, body) {
    const hex = crypto_1.default.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
    return `sha256=${hex}`;
}
/** Compute a signature bound to a unique delivery id as well as timestamp and body. */
function signWebhookDelivery(secret, timestamp, deliveryId, body) {
    const hex = crypto_1.default.createHmac('sha256', secret).update(`${timestamp}.${deliveryId}.${body}`).digest('hex');
    return `sha256=${hex}`;
}
/**
 * Build signed request headers for a delivery, returning the unix-seconds
 * timestamp and delivery ID used (so the caller can log/persist them). When
 * `secret` is falsy only `Content-Type` is set — keep every webhook secret-backed
 * so delivery is signed.
 */
function buildSignedHeaders(secret, body, options = {}) {
    const timestamp = Math.floor((options.now ? options.now() : Date.now()) / 1000).toString();
    const deliveryId = options.deliveryId ?? crypto_1.default.randomUUID();
    const headers = { 'Content-Type': options.contentType ?? 'application/json' };
    if (secret) {
        headers[exports.SIGNATURE_HEADER] = signWebhookDelivery(secret, timestamp, deliveryId, body);
        headers[exports.TIMESTAMP_HEADER] = timestamp;
        headers[exports.DELIVERY_ID_HEADER] = deliveryId;
    }
    return { headers, timestamp, deliveryId };
}
/**
 * Receiver-side verification. Returns true only when the signature matches
 * the legacy two-part or current delivery-ID-bound signature (constant-time) AND
 * the timestamp is within `toleranceSec` of now. This function alone does not
 * claim the delivery ID and therefore cannot prevent a replay within that window;
 * use `verifyWebhookDelivery` for new receivers.
 */
function verifyWebhookSignature(params) {
    const { secret, rawBody, signatureHeader, timestampHeader } = params;
    if (!signatureHeader || !timestampHeader)
        return false;
    if (!/^\d+$/.test(timestampHeader))
        return false;
    const tolerance = params.toleranceSec ?? exports.DEFAULT_TOLERANCE_SEC;
    const nowSec = Math.floor((params.now ? params.now() : Date.now()) / 1000);
    if (Math.abs(nowSec - Number(timestampHeader)) > tolerance)
        return false;
    const expected = params.deliveryIdHeader
        ? signWebhookDelivery(secret, timestampHeader, params.deliveryIdHeader, rawBody)
        : signWebhookBody(secret, timestampHeader, rawBody);
    const given = Buffer.from(signatureHeader);
    const want = Buffer.from(expected);
    if (given.length !== want.length)
        return false;
    return crypto_1.default.timingSafeEqual(given, want);
}
/**
 * Recommended receiver API: verifies a delivery-id-bound signature and then
 * atomically claims that id. A replay inside the timestamp tolerance is denied.
 */
async function verifyWebhookDelivery(params) {
    const deliveryId = params.deliveryIdHeader;
    if (!deliveryId || !/^[A-Za-z0-9._-]{1,200}$/.test(deliveryId))
        return false;
    if (!verifyWebhookSignature(params))
        return false;
    const timestamp = Number(params.timestampHeader);
    const expiresAt = new Date((timestamp + (params.toleranceSec ?? exports.DEFAULT_TOLERANCE_SEC)) * 1000);
    try {
        return await params.replayStore.claim(deliveryId, expiresAt);
    }
    catch {
        return false;
    }
}
function asError(e) {
    return e instanceof Error ? e : new Error(String(e));
}
function redactUrl(rawUrl) {
    try {
        const url = new URL(rawUrl);
        url.username = '';
        url.password = '';
        url.search = '';
        url.hash = '';
        return url.toString();
    }
    catch {
        return '<invalid URL>';
    }
}
function redactError(error, rawUrl) {
    const message = asError(error).message.split(rawUrl).join(redactUrl(rawUrl));
    return new Error(message);
}
/**
 * Deliver one signed webhook. Never throws — a guard rejection, timeout, or
 * transport failure comes back in the result. `redirect: 'manual'` ensures a 3xx
 * cannot bounce the request past the SSRF guard to an unvetted host.
 */
async function deliverWebhook(target, body, options) {
    return deliver(target, body, options, true);
}
/**
 * Permissive migration escape hatch. It may send without a signing secret or
 * SSRF guard, so never use it for a new untrusted webhook integration.
 */
async function deliverWebhookUnsafe(target, body, options = {}) {
    return deliver(target, body, options, false);
}
async function deliver(target, body, options, requireSafeDelivery) {
    const base = { url: redactUrl(target.url), id: target.id, ok: false };
    if (requireSafeDelivery && !target.secret) {
        return { ...base, skipped: true, error: new Error('Webhook signing secret is required') };
    }
    if (requireSafeDelivery && !options.assertSafeUrl) {
        return { ...base, skipped: true, error: new Error('Webhook URL guard is required') };
    }
    if (options.assertSafeUrl) {
        try {
            await options.assertSafeUrl(target.url);
        }
        catch (error) {
            return { ...base, skipped: true, error: redactError(error, target.url) };
        }
    }
    const doFetch = options.fetchImpl ?? globalThis.fetch;
    const { headers, deliveryId } = buildSignedHeaders(target.secret, body, {
        now: options.now,
        contentType: options.contentType,
    });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? exports.DEFAULT_TIMEOUT_MS);
    try {
        const res = await doFetch(target.url, {
            method: 'POST',
            headers,
            body,
            redirect: 'manual',
            signal: controller.signal,
        });
        return { ...base, deliveryId, ok: res.ok, status: res.status };
    }
    catch (error) {
        return { ...base, error: redactError(error, target.url) };
    }
    finally {
        clearTimeout(timeout);
    }
}
/** Deliver to many targets with bounded concurrency. Never rejects; one result per target. */
async function deliverWebhooks(targets, body, options) {
    const concurrency = options.concurrency ?? 8;
    if (!Number.isInteger(concurrency) || concurrency < 1) {
        throw new TypeError('concurrency must be a positive integer');
    }
    const results = new Array(targets.length);
    let nextIndex = 0;
    async function worker() {
        while (nextIndex < targets.length) {
            const index = nextIndex;
            nextIndex += 1;
            results[index] = await deliverWebhook(targets[index], body, options);
        }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
    return results;
}
