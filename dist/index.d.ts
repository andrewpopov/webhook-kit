/**
 * @andrewpopov/webhook-kit — framework-agnostic outbound webhook delivery.
 *
 * Owns the drift-prone core that cairn and bewks had independently reimplemented:
 * HMAC signing over `${timestamp}.${body}`, the `sha256=` + `X-Webhook-Timestamp`
 * headers, a fire-time SSRF re-check, per-attempt timeout, `redirect: 'manual'`,
 * and error isolation. The body shape, the SSRF guard, and logging are injected,
 * so each consumer keeps its exact wire contract.
 */
export declare const SIGNATURE_HEADER = "X-Webhook-Signature";
export declare const TIMESTAMP_HEADER = "X-Webhook-Timestamp";
export declare const DEFAULT_TIMEOUT_MS = 10000;
export declare const DEFAULT_TOLERANCE_SEC = 300;
/** Generate a webhook signing secret (256-bit, hex-encoded). */
export declare function generateWebhookSecret(): string;
/**
 * Resolve a secret-update input under the "always signed" invariant:
 * `undefined` → no change; a non-empty string → use it as-is; `null`/`''` →
 * rotate to a fresh generated secret. A webhook never becomes unsigned, so an
 * explicit clear rotates rather than removes.
 */
export declare function resolveSecretRotation(input: string | null | undefined): string | undefined;
/** True if a subscription list matches an event, honoring the `*` wildcard. */
export declare function matchesEvent(subscribedEvents: readonly string[], event: string): boolean;
/** Compute the `sha256=<hex>` signature over `` `${timestamp}.${body}` ``. */
export declare function signWebhookBody(secret: string, timestamp: string, body: string): string;
export interface BuildHeadersOptions {
    /** Clock source (unix ms), for tests. Defaults to `Date.now`. */
    now?: () => number;
    contentType?: string;
}
/**
 * Build signed request headers for a delivery, returning the unix-seconds
 * timestamp used (so the caller can log/persist it). When `secret` is falsy only
 * `Content-Type` is set — keep every webhook secret-backed so delivery is signed.
 */
export declare function buildSignedHeaders(secret: string | null | undefined, body: string, options?: BuildHeadersOptions): {
    headers: Record<string, string>;
    timestamp: string;
};
export interface VerifyParams {
    secret: string;
    rawBody: string;
    signatureHeader: string | null | undefined;
    timestampHeader: string | null | undefined;
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
export declare function verifyWebhookSignature(params: VerifyParams): boolean;
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
     */
    assertSafeUrl?: (url: string) => void | Promise<void>;
    timeoutMs?: number;
    /** Override fetch (tests / non-global environments). Defaults to global fetch. */
    fetchImpl?: typeof fetch;
    now?: () => number;
    contentType?: string;
}
export interface DeliveryResult {
    url: string;
    id?: string;
    ok: boolean;
    status?: number;
    /** True when the SSRF guard rejected the URL and delivery was not attempted. */
    skipped?: boolean;
    error?: Error;
}
/**
 * Deliver one signed webhook. Never throws — a guard rejection, timeout, or
 * transport failure comes back in the result. `redirect: 'manual'` ensures a 3xx
 * cannot bounce the request past the SSRF guard to an unvetted host.
 */
export declare function deliverWebhook(target: WebhookTarget, body: string, options?: DeliverOptions): Promise<DeliveryResult>;
/** Deliver to many targets in parallel. Never rejects; one result per target. */
export declare function deliverWebhooks(targets: readonly WebhookTarget[], body: string, options?: DeliverOptions): Promise<DeliveryResult[]>;
