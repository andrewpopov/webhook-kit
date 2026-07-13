# Changelog

## 1.0.1

- Bind all newly sent webhook signatures to a unique `X-Webhook-Delivery-Id`.
- Add `verifyWebhookDelivery`, which validates the delivery signature/freshness
  and invokes a consumer-provided atomic replay-store claim. A duplicate ID is
  rejected within the freshness window.
- Keep `signWebhookBody` / `verifyWebhookSignature` for legacy protocol
  compatibility, explicitly without replay protection.
- Upgrade the Vitest development toolchain to a version with no known advisories.

## 1.0.0

**Breaking security release.** `deliverWebhook` and `deliverWebhooks` now require
both a non-empty target secret and an `assertSafeUrl` callback. A missing control
produces a skipped result and sends nothing. The old permissive behavior remains
available only as explicitly named `deliverWebhookUnsafe` for migration.

- Bound fan-out delivery via `concurrency` (default `8`) instead of issuing an
  unbounded request burst.
- Redact URL credentials, query strings, and fragments from delivery results and
  propagated guard/transport errors.
- Correct receiver documentation: timestamp freshness alone does not stop a
  captured request from being replayed within its tolerance window.
- Add `npm run verify` for the local release gate.

## 0.1.2

Fix — expose `./package.json` in the `exports` map. Without it,
`require('@andrewpopov/webhook-kit/package.json')` threw
`ERR_PACKAGE_PATH_NOT_EXPORTED` — which broke the standards' own documented way of
verifying an INSTALLED version, the guard against the `github:` re-resolve trap.

No runtime change.

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
