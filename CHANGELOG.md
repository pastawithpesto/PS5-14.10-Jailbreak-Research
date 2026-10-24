# Changelog

## 2026-10-24 — 14.10 evidence reconciliation

- Corrected the Canvas UAF capability statement: same-type Canvas2D reclaim
  yields a typed state-field alias, not arbitrary read/write.
- Retracted the 768-byte ArrayBuffer-reclaim and V650/V655 validated-map claims
  for the tested Guide build.
- Retracted the save-count/state-stack OOB disclosure model; both wrappers use
  the reclaimed object's single live Vector header.
- Reclassified the stream short-result crash as a bounds/null termination, not
  an observable stale 8-byte read.
- Added the V661–V702 closure results to `docs/PROBE_INDEX.md`, including RAB,
  PNG, font metrics, MSE, transfer, typed-array representation and API-surface
  results.
- Current blocker: a Guide-reachable native-byte disclosure through an integer
  view/String, or a separate raw pointer/Vector-header write.
