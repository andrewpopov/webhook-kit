"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_TOLERANCE_SEC = exports.DEFAULT_TIMEOUT_MS = exports.TIMESTAMP_HEADER = exports.SIGNATURE_HEADER = void 0;
exports.generateWebhookSecret = generateWebhookSecret;
exports.resolveSecretRotation = resolveSecretRotation;
exports.matchesEvent = matchesEvent;
exports.signWebhookBody = signWebhookBody;
exports.buildSignedHeaders = buildSignedHeaders;
exports.verifyWebhookSignature = verifyWebhookSignature;
exports.deliverWebhook = deliverWebhook;
exports.deliverWebhookUnsafe = deliverWebhookUnsafe;
exports.deliverWebhooks = deliverWebhooks;
const crypto_1 = __importDefault(require("crypto"));
/**
 * @andrewpopov/webhook-kit — framework-agnostic outbound webhook delivery.
 *
 * Owns the drift-prone core that cairn and bewks had independently reimplemented:
 * HMAC signing over `${timestamp}.${body}`, the `sha256=` + `X-Webhook-Timestamp`
 * headers, a fire-time SSRF re-check, per-attempt timeout, `redirect: 'manual'`,
 * and error isolation. The body shape, the SSRF guard, and logging are injected,
 * so each consumer keeps its exact wire contract.
 */
exports.SIGNATURE_HEADER = 'X-Webhook-Signature';
exports.TIMESTAMP_HEADER = 'X-Webhook-Timestamp';
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
/**
 * Build signed request headers for a delivery, returning the unix-seconds
 * timestamp used (so the caller can log/persist it). When `secret` is falsy only
 * `Content-Type` is set — keep every webhook secret-backed so delivery is signed.
 */
function buildSignedHeaders(secret, body, options = {}) {
    const timestamp = Math.floor((options.now ? options.now() : Date.now()) / 1000).toString();
    const headers = { 'Content-Type': options.contentType ?? 'application/json' };
    if (secret) {
        headers[exports.SIGNATURE_HEADER] = signWebhookBody(secret, timestamp, body);
        headers[exports.TIMESTAMP_HEADER] = timestamp;
    }
    return { headers, timestamp };
}
/**
 * Receiver-side verification. Returns true only when the signature matches
 * `` `${timestamp}.${rawBody}` `` (constant-time) AND the timestamp is within
 * `toleranceSec` of now — the freshness window that makes a captured delivery
 * unreplayable. Use this to verify inbound webhooks signed by this library.
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
    const expected = signWebhookBody(secret, timestampHeader, rawBody);
    const given = Buffer.from(signatureHeader);
    const want = Buffer.from(expected);
    if (given.length !== want.length)
        return false;
    return crypto_1.default.timingSafeEqual(given, want);
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
    const { headers } = buildSignedHeaders(target.secret, body, {
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
        return { ...base, ok: res.ok, status: res.status };
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
