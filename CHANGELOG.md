# Changelog

## 1.0.3

- Release tooling upgraded to release-kit v0.3.1, so a feature release is graded as a minor rather than a patch
  This package's release-kit was pinned at v0.2.0, whose `stableSemver` incremented the patch component regardless of fragment kind — measured directly, a `minor` and even a `major` bump both resolved to a patch, and `bumpLevelSupport` was absent. Any release adding public surface would therefore have been published as a patch, telling every consumer the upgrade added nothing. That was not hypothetical: during the PKG-114 cuts, alert-kit on v0.2.0 derived 0.5.1 for a release that added a whole new public module, caught only because the derived version was read before cutting.
  
  No runtime change — release-kit is a devDependency and nothing this package exports is affected.
- the aggregate verification gate now rejects stale committed build output
  The aggregate verification lane now blocks a push whose committed webhook
  implementation or types lag behind source.
- Document that an invalid concurrency throws rather than being silently swallowed
  `deliverWebhooks`'s doc comment claimed it never rejects, but a non-positive
  or non-integer `concurrency` (e.g. `0`) has always thrown a `TypeError`
  synchronously — the doc and the code disagreed. Rather than folding a caller's
  misconfigured `concurrency` into the per-target result array, where an
  automated caller could mistake a config bug for an ordinary delivery failure,
  the doc comment now says plainly that an invalid `concurrency` throws. Only
  the documentation changed; `deliverWebhooks` itself is unchanged, and a new
  test pins the throwing behavior against regressions.
- Fix a sub-second replay window at the tolerance boundary
  `verifyWebhookSignature` floors `now` to whole seconds and accepts equality at
  the tolerance boundary, so the entire final second of the freshness window is
  accepted, not just its first millisecond. `verifyWebhookDelivery` computed its
  replay claim's `expiresAt` at the *start* of that same second instead of its
  end, so for up to just under one second an already-delivered request could
  still pass the freshness check while its replay claim had already lapsed,
  letting a captured delivery ID be claimed and replayed. Both bounds are now
  derived from one `freshnessCutoffMs` helper so they cannot drift apart again;
  the accepted freshness window itself is unchanged (verified equivalent by
  inspection — this closes the replay gap without narrowing what a legitimate,
  on-time delivery is accepted).

## 1.0.2

- Manage releases with release-kit (fragment-based CHANGELOG + version bump)
  Releases are now driven by release-kit: describe each change as a fragment under `.changes/unreleased/` and run `npm run release:cut` to compile them into a new CHANGELOG section, bump the version, and archive the fragments.

## 1.0.1

The first tagged `1.x` release. `1.0.0` was never published as a separate
version — the package went from `0.1.2` straight to `1.0.1`, so the changes
once listed under `1.0.0` shipped here and are consolidated into this entry.

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
- Bind all newly sent webhook signatures to a unique `X-Webhook-Delivery-Id`.
- Add `verifyWebhookDelivery`, which validates the delivery signature/freshness
  and invokes a consumer-provided atomic replay-store claim. A duplicate ID is
  rejected within the freshness window.
- Keep `signWebhookBody` / `verifyWebhookSignature` for legacy protocol
  compatibility, explicitly without replay protection.
- Upgrade the Vitest development toolchain to a version with no known advisories.
- Add public contribution, support, and private vulnerability-reporting policies.

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
