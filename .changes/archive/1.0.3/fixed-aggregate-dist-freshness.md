---
kind: fixed
summary: the aggregate verification gate now rejects stale committed build output
---

The aggregate verification lane now blocks a push whose committed webhook
implementation or types lag behind source.
