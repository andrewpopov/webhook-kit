# Changelog

## 0.1.1

- `DeliverOptions.assertSafeUrl` now accepts a guard returning any value (`(url) => unknown`), not just `void`/`Promise<void>`. Only whether it throws matters, so guards that return the parsed URL fit without a wrapper. Surfaced adopting bewks, whose SSRF guard returns the parsed `URL`.

## 0.1.0

Initial release. Framework-agnostic outbound webhook delivery extracted from the
converged cairn + bewks dispatchers.

- `deliverWebhook` / `deliverWebhooks`: signed POST delivery with a fire-time
  SSRF re-check hook, per-attempt timeout, `redirect: 'manual'`, and error
  isolation (never throws).
- `buildSignedHeaders` / `signWebhookBody`: HMAC-SHA256 over `${timestamp}.${body}`
  with `sha256=` + `X-Webhook-Timestamp` headers (replay-resistant).
- `verifyWebhookSignature`: receiver-side constant-time verify with a freshness
  window.
- `matchesEvent` (`*` wildcard), `generateWebhookSecret`, `resolveSecretRotation`
  (always-signed invariant).
