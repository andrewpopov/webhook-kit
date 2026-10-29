---
kind: changed
summary: Installing from git no longer runs a full dependency install: the `prepare` script is gone (run `npm run hooks` once after cloning) and `build` is now `compile`
---

The committed `dist/` is what consumers load, so no install-time step is needed. Run `npm run hooks` once after cloning to enable the pre-push gate.
