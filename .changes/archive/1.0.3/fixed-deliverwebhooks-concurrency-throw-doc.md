---
kind: fixed
summary: Document that an invalid concurrency throws rather than being silently swallowed
---

`deliverWebhooks`'s doc comment claimed it never rejects, but a non-positive
or non-integer `concurrency` (e.g. `0`) has always thrown a `TypeError`
synchronously — the doc and the code disagreed. Rather than folding a caller's
misconfigured `concurrency` into the per-target result array, where an
automated caller could mistake a config bug for an ordinary delivery failure,
the doc comment now says plainly that an invalid `concurrency` throws. Only
the documentation changed; `deliverWebhooks` itself is unchanged, and a new
test pins the throwing behavior against regressions.
