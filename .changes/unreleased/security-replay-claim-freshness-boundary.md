---
kind: security
summary: Fix a sub-second replay window at the tolerance boundary
---

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
