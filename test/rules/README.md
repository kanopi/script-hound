# Rule fixtures

Synthetic samples for `lib/heuristics.mjs`, checked by `test/run-test.mjs` without a browser.

- `positive/`: skimmer-style code, modeled on publicly documented Magecart patterns. Each one **must** trigger `skimmer-field-harvest`.
- `negative/`: legitimate card-handling code (first-party checkout posting to its own API, direct payment-processor calls, a BIN check). None of them may trigger a **high** rule.

The test also builds a large "theme bundle" containing every ingredient far apart (must not match), then appends a compact skimmer (must match).

These samples are inert: the destinations are `.example` domains.
