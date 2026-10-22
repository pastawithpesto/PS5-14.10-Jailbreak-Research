# Changelog

## Stage-2 view-cell extraction probes (2026-10-19)

- **p164-dataview-extract.js + p165-f64vector.js (PREPARED — NOT RUN)** — the issue #5 roadmap's first two extraction probes, targeting view cells in the proven p156 groom instead of JSString cells. p157 showed backing stores are not overwritten; these flip the bet to the cell region p156 proves the sweep rewrites (`.length=81400` on two consoles).
  - p164: DataViews — if `m_vector` receives a metadata-entry value (LLInt code pointer candidate), `getUint32` reads fetch raw bytes from that address (module-relative leak); if `byteLength` is hit, reads stay near the store.
  - p165: Float64Arrays — raw-bit extraction of `f64[0]`/`f64[1]` via a clean bitcast buffer; a corrupted larger `m_length` turns indexed reads into OOB reads past the 16-byte backing store.
  - Per-view classification beacons (PRE-OK / VECTOR-HIT / LEN-HIT / DEAD) + canary `.length` baseline for cross-console comparison; +~30 small objects vs p156, within the second-console ceiling.
  - Offline validation: Node stub run (alloc beacons, pre-checks, ready flow), f2hex bitcast (0.5 → 3fe0000000000000), classification truth table.
- RESEARCH_MAP Stage 2 now lists the MetadataTable extraction track alongside the CSSFontFace track; PROBE_INDEX documents both probes with an interpretation guide.
