# @andrewpopov/webhook-kit

Framework-agnostic **outbound webhook delivery** for Node services. Owns the
security-sensitive core that repos kept re-implementing and drifting on:

- HMAC-SHA256 signing over `` `${timestamp}.${body}` `` (replay-resistant) with
  `X-Webhook-Signature: sha256=<hex>` + `X-Webhook-Timestamp` headers.
- A **fire-time SSRF re-check** hook — the app injects its own URL guard, run per
  attempt so a DNS rebind after registration can't reach an internal host.
- Per-attempt timeout and `redirect: 'manual'` (a 3xx can't bounce past the guard).
- Error isolation: delivery never throws; failures come back in the result.
- A matching **receiver-side verifier** so subscribers (and your tests) can
  verify what this library signs, with a freshness window.

Zero runtime dependencies — Node `crypto` and the global `fetch` (Node ≥ 20).

## Install

```
npm install github:andrewpopov/webhook-kit#v0.1.0
```

## Sending

```ts
import { deliverWebhooks, matchesEvent } from '@andrewpopov/webhook-kit';

async function fire(event: string, payload: Record<string, unknown>) {
  const targets = (await listActiveWebhooks())
    .filter((w) => matchesEvent(JSON.parse(w.events), event))
    .map((w) => ({ url: w.url, secret: w.secret, id: w.id }));

  // Each consumer keeps its own body shape — the library signs whatever you pass.
  const body = JSON.stringify({ event, timestamp: new Date().toISOString(), ...payload });

  const results = await deliverWebhooks(targets, body, {
    assertSafeUrl: (url) => assertPublicHttpUrl(url), // your SSRF guard; throw to skip
    timeoutMs: 10_000,
  });

  for (const r of results) {
    if (r.skipped) log.warn('webhook skipped (unsafe url)', { id: r.id });
    else if (!r.ok) log.warn('webhook delivery failed', { id: r.id, status: r.status, err: r.error?.message });
  }
}
```

The body shape and the SSRF guard are injected, so a consumer's exact wire
contract and logging are preserved — only the signing/transport core is shared.

## Receiving (subscriber side)

```ts
import { verifyWebhookSignature } from '@andrewpopov/webhook-kit';

app.post('/hook', (req, res) => {
  const ok = verifyWebhookSignature({
    secret: MY_SECRET,
    rawBody: req.rawBody,                       // the exact bytes received
    signatureHeader: req.header('X-Webhook-Signature'),
    timestampHeader: req.header('X-Webhook-Timestamp'),
    toleranceSec: 300,                          // reject deliveries older than 5 min
  });
  if (!ok) return res.status(401).end();
  // ... handle the verified event
});
```

## API

| Export | Purpose |
|---|---|
| `deliverWebhook(target, body, opts)` | Deliver one signed webhook; never throws. |
| `deliverWebhooks(targets, body, opts)` | Deliver many in parallel; one `DeliveryResult` each. |
| `buildSignedHeaders(secret, body, opts)` | Signed headers + the timestamp used. |
| `signWebhookBody(secret, timestamp, body)` | The `sha256=<hex>` signature string. |
| `verifyWebhookSignature(params)` | Receiver-side verify: constant-time + freshness window. |
| `matchesEvent(subscribed, event)` | Event match honoring the `*` wildcard. |
| `generateWebhookSecret()` | 256-bit hex signing secret. |
| `resolveSecretRotation(input)` | Always-signed secret update (clear → rotate, never remove). |

`DeliverOptions`: `assertSafeUrl`, `timeoutMs` (default 10000), `fetchImpl`, `now`, `contentType`.

## Signature scheme

```
X-Webhook-Timestamp: <unix-seconds>
X-Webhook-Signature: sha256=HMAC_SHA256(secret, `${X-Webhook-Timestamp}.${rawBody}`)
```

A receiver reconstructs `` `${X-Webhook-Timestamp}.${rawBody}` ``, compares the HMAC
constant-time, and rejects deliveries outside its freshness window. Because the
timestamp is bound into the signature, a captured delivery cannot be replayed.

## Standards

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).
